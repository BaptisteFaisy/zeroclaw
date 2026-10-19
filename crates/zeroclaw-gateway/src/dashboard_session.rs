//! Opt-in dashboard sign-in sessions (`[gateway.dashboard_sign_in]`).
//!
//! A browser that completed an OIDC sign-in holds only an opaque session
//! cookie. The access token it was issued stays here, in memory, and every
//! request carrying the cookie is checked again against the same inbound
//! authority RPC uses: credential expiry, the introspection revalidation
//! deadline, and the grants the principal holds under the policy in force
//! now. The gateway decides nothing of its own; it only narrows.
//!
//! The layer never rejects a request itself. It classifies the caller and
//! leaves the decision to the route: public routes ignore the
//! classification, so an expired cookie never keeps the dashboard shell or
//! the sign-in screen from loading, while every authenticated route reads it
//! through [`current_caller`] or the request's [`DashboardCaller`] extension.
//!
//! With sign-in off, which is the default, the layer is a no-op that never
//! reads a cookie: a forged one is no credential at all.
//!
//! The store is process-shared rather than held in `AppState`. The gateway
//! is rebuilt on every daemon generation, and a sign-in has to survive a
//! reload; a session verified by an earlier generation's authority is
//! verified again, with the token it holds, against the current one before
//! it is used.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use zeroclaw_api::grants::ResolvedGrants;
use zeroclaw_api::principal::{ActorKind, Principal};
use zeroclaw_runtime::rpc::auth::{ConnectionAuth, RpcInboundAuth};

use crate::AppState;
use crate::principal_gate::GatewayInboundAuth;

/// Session cookie on an HTTPS dashboard served at the root path. The
/// `__Host-` prefix makes the browser refuse it unless it is `Secure`,
/// host-only and `Path=/`, so a sibling host cannot plant one.
pub(crate) const HOST_SESSION_COOKIE: &str = "__Host-zc_session";

/// Session cookie everywhere `__Host-` cannot apply: under a path prefix,
/// or over plain HTTP on a loopback host.
pub(crate) const SESSION_COOKIE: &str = "zc_session";

/// Short-lived cookie binding a dashboard sign-in to the browser that
/// started it, so a callback someone else started cannot finish here.
pub(crate) const BINDING_COOKIE: &str = "zc_signin";

/// Header a cookie-authenticated request that changes state must carry,
/// holding the session's CSRF token.
pub(crate) const CSRF_HEADER: &str = "x-zeroclaw-csrf";

/// Sessions held at once across every principal. At the cap a new sign-in
/// is refused rather than evicting somebody else's session, so one account
/// cycling sign-ins cannot sign everyone else out.
pub(crate) const MAX_SESSIONS: usize = 256;

/// Sessions one principal may hold at once (a browser per device, a few
/// profiles). A further sign-in by the same principal replaces its oldest.
pub(crate) const MAX_SESSIONS_PER_PRINCIPAL: usize = 8;

/// Longest display name kept from the verified claims.
const MAX_DISPLAY_NAME_CHARS: usize = 128;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The store's key for a cookie value: the store never holds a value a
/// browser could present.
pub(crate) fn session_key(cookie_value: &str) -> [u8; 32] {
    Sha256::digest(cookie_value.as_bytes()).into()
}

/// One signed-in browser.
struct Session {
    alias: String,
    /// The access token the sign-in was issued. Memory only; never logged
    /// and never sent anywhere but the inbound authority that verifies it.
    bearer: String,
    auth: ConnectionAuth,
    /// The authority `auth` was verified by. A reload builds a new one, and
    /// a session verified by another is verified again before it is used.
    /// Holding the `Weak` keeps the old allocation, so the comparison
    /// cannot be fooled by an address reused for the new authority.
    authority: Weak<RpcInboundAuth>,
    csrf: String,
    display_name: String,
    created: u64,
    hard_expiry: u64,
    /// Cancelled on sign-out, expiry or revocation, so long-lived sockets
    /// the session opened can close.
    ended: CancellationToken,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("alias", &self.alias)
            .field("bearer", &"<redacted>")
            .field("principal", &self.auth.principal.id)
            .field("csrf", &"<redacted>")
            .field("created", &self.created)
            .field("hard_expiry", &self.hard_expiry)
            .finish()
    }
}

impl Session {
    fn expires_at(&self) -> u64 {
        self.auth
            .principal
            .expires_at
            .map_or(self.hard_expiry, |exp| exp.min(self.hard_expiry))
    }
}

/// A sign-in the store could not take.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StoreFull;

/// A verified sign-in on its way into the store.
struct NewSession {
    alias: String,
    bearer: String,
    auth: ConnectionAuth,
    authority: Weak<RpcInboundAuth>,
    display_name: String,
    lifetime_secs: u64,
}

/// Every live dashboard session in this process.
#[derive(Default)]
pub struct DashboardSessions {
    sessions: parking_lot::Mutex<HashMap<[u8; 32], Session>>,
}

impl std::fmt::Debug for DashboardSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DashboardSessions")
            .field("sessions", &self.sessions.lock().len())
            .finish()
    }
}

impl DashboardSessions {
    /// The process's one store, shared by every gateway generation.
    pub fn process_shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<DashboardSessions>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| Arc::new(Self::default())))
    }

    fn sweep(sessions: &mut HashMap<[u8; 32], Session>, now: u64) {
        sessions.retain(|_, session| {
            let live = session.expires_at() > now;
            if !live {
                session.ended.cancel();
            }
            live
        });
    }

    /// Whether a new sign-in could land now. Checked before the code
    /// exchange so a refusal costs no round trip to the identity provider;
    /// [`Self::insert`] checks again.
    pub(crate) fn has_room(&self) -> bool {
        let mut sessions = self.sessions.lock();
        Self::sweep(&mut sessions, now_unix());
        sessions.len() < MAX_SESSIONS
    }

    /// Store a verified sign-in and return the cookie value that names it.
    ///
    /// A principal at its own cap gives up its oldest session. Nobody else's
    /// session is ever evicted: at the global cap the sign-in is refused.
    fn insert(&self, new: NewSession, now: u64) -> Result<(String, Arc<SessionAuth>), StoreFull> {
        let NewSession {
            alias,
            bearer,
            auth,
            authority,
            display_name,
            lifetime_secs,
        } = new;
        let mut sessions = self.sessions.lock();
        Self::sweep(&mut sessions, now);
        let principal = auth.principal.id.clone();
        let mut own: Vec<([u8; 32], u64)> = sessions
            .iter()
            .filter(|(_, session)| session.auth.principal.id == principal)
            .map(|(key, session)| (*key, session.created))
            .collect();
        if own.len() >= MAX_SESSIONS_PER_PRINCIPAL {
            own.sort_by_key(|(_, created)| *created);
            let excess = own.len() + 1 - MAX_SESSIONS_PER_PRINCIPAL;
            for (key, _) in own.into_iter().take(excess) {
                if let Some(evicted) = sessions.remove(&key) {
                    evicted.ended.cancel();
                }
            }
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(StoreFull);
        }
        let cookie = random_token();
        let key = session_key(&cookie);
        let session = Session {
            alias,
            bearer,
            auth,
            authority,
            csrf: random_token(),
            display_name,
            created: now,
            hard_expiry: now.saturating_add(lifetime_secs),
            ended: CancellationToken::new(),
        };
        let view = Arc::new(SessionAuth::from_session(key, &session, None));
        sessions.insert(key, session);
        Ok((cookie, view))
    }

    /// End the session a cookie names. Returns whether one existed.
    pub(crate) fn remove(&self, cookie_value: &str) -> bool {
        self.remove_key(&session_key(cookie_value))
    }

    fn remove_key(&self, key: &[u8; 32]) -> bool {
        match self.sessions.lock().remove(key) {
            Some(session) => {
                session.ended.cancel();
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.lock().len()
    }
}

/// What the routes see of a valid session: who it is and what it may do
/// now, never the token behind it.
#[derive(Clone)]
pub struct SessionAuth {
    key: [u8; 32],
    pub alias: String,
    /// The verified binding, for routes that re-authorize at their effect
    /// (the config routes do so under the config write lock).
    pub connection: ConnectionAuth,
    /// The grants the principal holds under the policy in force when this
    /// request was admitted.
    pub grants: ResolvedGrants,
    pub display_name: String,
    pub csrf: String,
    /// When the session ends unless renewed by signing in again (UNIX
    /// seconds): the earlier of the token's expiry and the session cap.
    pub expires_at: u64,
    /// Cancelled when the session ends.
    pub ended: CancellationToken,
}

impl std::fmt::Debug for SessionAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionAuth")
            .field("alias", &self.alias)
            .field("principal", &self.connection.principal.id)
            .field("admin", &self.grants.admin)
            .field("csrf", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SessionAuth {
    fn from_session(key: [u8; 32], session: &Session, grants: Option<ResolvedGrants>) -> Self {
        Self {
            key,
            alias: session.alias.clone(),
            connection: session.auth.clone(),
            grants: grants.unwrap_or_else(|| session.auth.grants.clone()),
            display_name: session.display_name.clone(),
            csrf: session.csrf.clone(),
            expires_at: session.expires_at(),
            ended: session.ended.clone(),
        }
    }

    pub fn principal(&self) -> &Principal {
        &self.connection.principal
    }

    /// Operator-equivalent: the grant set the shared operator itself holds.
    pub fn is_admin(&self) -> bool {
        self.grants.admin
    }
}

/// Why a request that carried a session cookie is not signed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRejection {
    /// The session ended: token expiry, the session cap, a refused
    /// revalidation, or a policy that no longer grants the principal
    /// anything. Signing in again may succeed.
    Expired,
    /// No such session (signed out, lost on restart, or never issued), or
    /// its provider is no longer offered.
    Invalid,
    /// A request that changes state without the session's CSRF token.
    Csrf,
    /// A request, or a WebSocket upgrade, from another origin.
    Origin,
}

impl SessionRejection {
    fn reason(self) -> &'static str {
        match self {
            Self::Expired => "session_expired",
            Self::Invalid => "session_invalid",
            Self::Csrf => "csrf",
            Self::Origin => "origin",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::Expired | Self::Invalid => StatusCode::UNAUTHORIZED,
            Self::Csrf | Self::Origin => StatusCode::FORBIDDEN,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Expired => "Your dashboard sign-in has expired. Sign in again.",
            Self::Invalid => "This dashboard sign-in is no longer valid. Sign in again.",
            Self::Csrf => "Signed-in requests that change state must send the X-ZeroClaw-CSRF header",
            Self::Origin => "Signed-in requests must come from the dashboard's own origin",
        }
    }

    /// Whether the browser should drop the cookie: only once the session
    /// itself is gone, never for a request that merely arrived wrongly.
    fn clears_cookie(self) -> bool {
        matches!(self, Self::Expired | Self::Invalid)
    }

    pub(crate) fn body(self) -> (StatusCode, Json<serde_json::Value>) {
        (
            self.status(),
            Json(serde_json::json!({ "error": self.message(), "reason": self.reason() })),
        )
    }
}

/// How the request that carried a session cookie is classified. Absent
/// (no extension, no task-local) when sign-in is off, the request carried
/// no cookie, or it carried an `Authorization` header, which always wins.
#[derive(Clone, Debug)]
pub enum DashboardCaller {
    Session(Arc<SessionAuth>),
    Rejected(SessionRejection),
}

tokio::task_local! {
    /// The classification of the request being served, for checks that
    /// see only the request headers (`require_auth`). Set by [`layer`]
    /// alone, around the rest of the request.
    static DASHBOARD_CALLER: DashboardCaller;
}

/// The current request's classification, when it carried a session cookie
/// and sign-in is on.
pub(crate) fn current_caller() -> Option<DashboardCaller> {
    DASHBOARD_CALLER.try_with(Clone::clone).ok()
}

/// The 403 for a signed-in account that is not an administrator, on a
/// route only operators may use.
pub(crate) fn operator_required() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "This page needs an administrator account",
            "reason": "operator_required",
        })),
    )
}

impl DashboardCaller {
    /// Admission to an operator route: an administrator session passes, any
    /// other session gets 403 with a stable reason, and a rejected cookie
    /// answers with its own reason instead of the pairing prompt.
    pub(crate) fn admit_operator(&self) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        match self {
            Self::Session(session) if session.is_admin() => Ok(()),
            Self::Session(_) => Err(operator_required()),
            Self::Rejected(rejection) => Err(rejection.body()),
        }
    }
}

/// The dashboard's sign-in state for one gateway run: the process-shared
/// sessions and this generation's inbound authority.
pub struct DashboardAuth {
    pub(crate) sessions: Arc<DashboardSessions>,
    pub(crate) inbound: Arc<GatewayInboundAuth>,
}

/// Why a sign-in that the identity provider completed did not become a
/// session. Each maps to a fixed page; details go to the log only.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignInRefusal {
    /// The core's provider refused the access token, or the policy grants
    /// the identity nothing.
    Denied,
    /// A service principal: services never hold browser sessions.
    Service,
    /// The store is at its global cap.
    Full,
}

impl DashboardAuth {
    pub fn new(sessions: Arc<DashboardSessions>, inbound: Arc<GatewayInboundAuth>) -> Self {
        Self { sessions, inbound }
    }

    /// Verify the access token a dashboard sign-in was issued and store the
    /// session. The token is verified by the configured provider exactly as
    /// RPC verifies a bearer; the resolved principal must be a human.
    pub(crate) async fn sign_in(
        &self,
        alias: &str,
        access_token: String,
        lifetime_secs: u64,
    ) -> Result<(String, Arc<SessionAuth>), SignInRefusal> {
        let provider = format!("oidc.{alias}");
        let auth = self
            .inbound
            .authenticate_scoped(&access_token, &provider)
            .await
            .map_err(|_| SignInRefusal::Denied)?;
        if auth.principal.actor == ActorKind::Service {
            return Err(SignInRefusal::Service);
        }
        let display_name = display_name(&auth);
        self.sessions
            .insert(
                NewSession {
                    alias: alias.to_string(),
                    bearer: access_token,
                    auth,
                    authority: self.inbound.authority_ref(),
                    display_name,
                    lifetime_secs,
                },
                now_unix(),
            )
            .map_err(|StoreFull| SignInRefusal::Full)
    }

    /// The session a cookie names, checked as RPC checks a bound connection
    /// before each operation. A session that fails is ended.
    /// Check again, from a long-lived socket, the session a request admitted
    /// earlier; the same checks as for a request.
    pub(crate) async fn recheck(&self, state: &AppState, session: &SessionAuth) -> DashboardCaller {
        let offered = offered_aliases(state);
        self.admit_key(|alias| offered.iter().any(|o| o == alias), session.key)
            .await
    }

    async fn admit(&self, config_alias_offered: impl Fn(&str) -> bool, cookie: &str) -> DashboardCaller {
        self.admit_key(config_alias_offered, session_key(cookie))
            .await
    }

    async fn admit_key(
        &self,
        config_alias_offered: impl Fn(&str) -> bool,
        key: [u8; 32],
    ) -> DashboardCaller {
        let now = now_unix();
        let snapshot = {
            let sessions = self.sessions.sessions.lock();
            sessions.get(&key).map(|session| {
                (
                    session.alias.clone(),
                    session.bearer.clone(),
                    session.auth.clone(),
                    session.authority.clone(),
                    session.expires_at(),
                )
            })
        };
        let Some((alias, bearer, auth, authority, expires_at)) = snapshot else {
            return DashboardCaller::Rejected(SessionRejection::Invalid);
        };
        if expires_at <= now {
            self.sessions.remove_key(&key);
            return DashboardCaller::Rejected(SessionRejection::Expired);
        }
        if !config_alias_offered(&alias) {
            self.sessions.remove_key(&key);
            return DashboardCaller::Rejected(SessionRejection::Invalid);
        }
        let due = auth
            .principal
            .revalidate_by
            .is_some_and(|deadline| deadline <= now);
        let auth = if due || !self.inbound.is_authority(&authority) {
            match self.reverify(&key, &alias, &bearer, &auth).await {
                Some(fresh) => fresh,
                None => return DashboardCaller::Rejected(SessionRejection::Expired),
            }
        } else {
            auth
        };
        let grants = match self.inbound.current_grants(&auth) {
            Ok(grants) => grants,
            // The accepted policy can move between a resolution and its
            // check; that is no reason to sign somebody out. Verify once
            // more with the token held, then fail closed.
            Err(_) => match self.reverify(&key, &alias, &bearer, &auth).await {
                Some(fresh) => match self.inbound.current_grants(&fresh) {
                    Ok(grants) => grants,
                    Err(_) => {
                        self.sessions.remove_key(&key);
                        return DashboardCaller::Rejected(SessionRejection::Expired);
                    }
                },
                None => return DashboardCaller::Rejected(SessionRejection::Expired),
            },
        };
        let sessions = self.sessions.sessions.lock();
        match sessions.get(&key) {
            Some(session) => DashboardCaller::Session(Arc::new(SessionAuth::from_session(
                key,
                session,
                Some(grants),
            ))),
            // Signed out while this request was being checked.
            None => DashboardCaller::Rejected(SessionRejection::Invalid),
        }
    }

    /// Verify the held token again against the current authority and keep
    /// the result. A refusal, or a token that now names another principal,
    /// ends the session.
    async fn reverify(
        &self,
        key: &[u8; 32],
        alias: &str,
        bearer: &str,
        previous: &ConnectionAuth,
    ) -> Option<ConnectionAuth> {
        let provider = format!("oidc.{alias}");
        let fresh = match self.inbound.authenticate_scoped(bearer, &provider).await {
            Ok(fresh)
                if fresh.principal.id == previous.principal.id
                    && fresh.principal.actor != ActorKind::Service =>
            {
                fresh
            }
            _ => {
                self.sessions.remove_key(key);
                return None;
            }
        };
        let mut sessions = self.sessions.sessions.lock();
        let session = sessions.get_mut(key)?;
        session.auth = fresh.clone();
        session.authority = self.inbound.authority_ref();
        Some(fresh)
    }

    /// End the session behind `session` (sign-out).
    pub(crate) fn end(&self, session: &SessionAuth) -> bool {
        self.sessions.remove_key(&session.key)
    }
}

/// A display name for the header, from the verified access-token claims.
/// Cosmetic only: it never authorizes anything.
fn display_name(auth: &ConnectionAuth) -> String {
    ["name", "preferred_username", "email"]
        .iter()
        .filter_map(|claim| auth.identity.claims.get(*claim)?.as_str())
        .map(str::trim)
        .find(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(|value| value.chars().take(MAX_DISPLAY_NAME_CHARS).collect())
        .unwrap_or_else(|| auth.principal.display_id.clone())
}

/// Read one cookie's value from the request.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The session cookie the request carries, if any.
pub(crate) fn session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, HOST_SESSION_COOKIE).or_else(|| cookie_value(headers, SESSION_COOKIE))
}

/// The scheme, host and path a dashboard cookie is scoped to.
pub(crate) struct CookieScope<'a> {
    pub https: bool,
    pub path_prefix: &'a str,
}

impl CookieScope<'_> {
    fn session_name(&self) -> &'static str {
        if self.https && self.path_prefix.is_empty() {
            HOST_SESSION_COOKIE
        } else {
            SESSION_COOKIE
        }
    }

    fn secure(&self) -> &'static str {
        if self.https { "; Secure" } else { "" }
    }

    /// `Set-Cookie` for a new session. No `Max-Age`: the browser keeps it
    /// for the browsing session, and the server-side expiry is the
    /// authority.
    pub(crate) fn session_cookie(&self, value: &str) -> HeaderValue {
        let header = format!(
            "{}={value}; Path={}/; HttpOnly; SameSite=Strict{}",
            self.session_name(),
            self.path_prefix,
            self.secure()
        );
        HeaderValue::from_str(&header).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    /// `Set-Cookie` values that drop the session cookie under both names.
    pub(crate) fn clear_session_cookies(&self) -> Vec<HeaderValue> {
        let mut cleared = vec![format!(
            "{SESSION_COOKIE}=; Path={}/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            self.path_prefix,
            self.secure()
        )];
        if self.https {
            cleared.push(format!(
                "{HOST_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure"
            ));
        }
        cleared
            .into_iter()
            .filter_map(|value| HeaderValue::from_str(&value).ok())
            .collect()
    }

    /// `Set-Cookie` for the sign-in binding. `Lax`, because the callback is
    /// a cross-site top-level navigation from the identity provider and a
    /// `Strict` cookie would not be sent with it; scoped to the callback
    /// path and the flow's lifetime.
    pub(crate) fn binding_cookie(&self, value: &str, max_age_secs: u64) -> HeaderValue {
        let header = format!(
            "{BINDING_COOKIE}={value}; Path={}/oidc/callback; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}{}",
            self.path_prefix,
            self.secure()
        );
        HeaderValue::from_str(&header).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    pub(crate) fn clear_binding_cookie(&self) -> HeaderValue {
        let header = format!(
            "{BINDING_COOKIE}=; Path={}/oidc/callback; HttpOnly; SameSite=Lax; Max-Age=0{}",
            self.path_prefix,
            self.secure()
        );
        HeaderValue::from_str(&header).unwrap_or_else(|_| HeaderValue::from_static(""))
    }
}

/// `scheme://host` exactly as a browser would put it in `Origin`: lower
/// case, default port omitted.
pub(crate) fn origin_of(https: bool, host: &str) -> String {
    let scheme = if https { "https" } else { "http" };
    let host = host.trim().to_ascii_lowercase();
    let default_port = if https { ":443" } else { ":80" };
    let host = host.strip_suffix(default_port).unwrap_or(&host);
    format!("{scheme}://{host}")
}

fn is_unsafe(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Where a cookie-carrying request came from, checked before any session
/// state is touched, so a cross-site request costs nothing.
///
/// Cookies ride along on WebSocket handshakes, and `SameSite` does not tell
/// two ports of one host apart, so `Origin` is the check that matters: it
/// must name this dashboard whenever present, and must be present on
/// requests that change state and on upgrades. `Sec-Fetch-Site`, where
/// sent, must say the request came from this origin (or, for a plain
/// navigation, from the user).
fn check_origin(method: &Method, headers: &HeaderMap, own_origin: &str) -> Result<(), SessionRejection> {
    let strict = is_unsafe(method) || is_websocket_upgrade(headers);
    match headers.get(header::ORIGIN).map(|v| v.to_str()) {
        Some(Ok(origin)) if origin.eq_ignore_ascii_case(own_origin) => {}
        Some(_) => return Err(SessionRejection::Origin),
        None if strict => return Err(SessionRejection::Origin),
        None => {}
    }
    match headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        None | Some("same-origin") => Ok(()),
        Some("none") if !strict => Ok(()),
        Some(_) => Err(SessionRejection::Origin),
    }
}

fn check_csrf(method: &Method, headers: &HeaderMap, session: &SessionAuth) -> Result<(), SessionRejection> {
    if !is_unsafe(method) {
        return Ok(());
    }
    match headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) {
        Some(presented) if zeroclaw_config::pairing::constant_time_eq(presented, &session.csrf) => {
            Ok(())
        }
        _ => Err(SessionRejection::Csrf),
    }
}

/// The providers the dashboard offers now that are still configured.
fn offered_aliases(state: &AppState) -> Vec<String> {
    let config = state.config.read();
    config
        .gateway
        .dashboard_sign_in
        .oidc
        .iter()
        .filter(|alias| config.oidc.contains_key(*alias))
        .cloned()
        .collect()
}

/// How often a long-lived socket checks its session again, so a policy
/// change or a removed provider reaches a socket that sends nothing.
const SOCKET_RECHECK: std::time::Duration = std::time::Duration::from_secs(60);

/// WebSocket close code for a session that ended (signed out, expired, or
/// no longer valid): the client must not reconnect on its own.
pub(crate) const WS_CLOSE_SESSION_ENDED: u16 = 4401;

/// WebSocket close code for a session that is still valid but no longer
/// admits this socket (the account lost the access the socket needs).
pub(crate) const WS_CLOSE_ACCESS_LOST: u16 = 4403;

/// A long-lived socket's view of the dashboard session that opened it.
pub(crate) struct SessionWatch {
    auth: Arc<DashboardAuth>,
    session: Arc<SessionAuth>,
    require_admin: bool,
    recheck: tokio::time::Interval,
}

impl SessionWatch {
    pub(crate) fn new(auth: Arc<DashboardAuth>, session: Arc<SessionAuth>, require_admin: bool) -> Self {
        let start = tokio::time::Instant::now() + SOCKET_RECHECK;
        let mut recheck = tokio::time::interval_at(start, SOCKET_RECHECK);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            auth,
            session,
            require_admin,
            recheck,
        }
    }

    pub(crate) fn principal_id(&self) -> &str {
        self.session.principal().id.as_str()
    }

    /// Resolves with the close code once the session stops admitting the
    /// socket. Cancel-safe: every await is a timer, a cancellation token, or
    /// a recheck whose effects are complete before it returns.
    async fn lost(&mut self, state: &AppState) -> u16 {
        loop {
            let remaining = self.session.expires_at.saturating_sub(now_unix());
            tokio::select! {
                () = self.session.ended.cancelled() => return WS_CLOSE_SESSION_ENDED,
                () = tokio::time::sleep(std::time::Duration::from_secs(remaining)) => {
                    return WS_CLOSE_SESSION_ENDED;
                }
                _ = self.recheck.tick() => {
                    match self.auth.recheck(state, &self.session).await {
                        DashboardCaller::Session(session)
                            if !self.require_admin || session.is_admin() =>
                        {
                            self.session = session;
                        }
                        DashboardCaller::Session(_) => return WS_CLOSE_ACCESS_LOST,
                        DashboardCaller::Rejected(_) => return WS_CLOSE_SESSION_ENDED,
                    }
                }
            }
        }
    }
}

/// [`SessionWatch::lost`] for a socket that may have no session: one opened
/// with a pairing token, or with pairing off, is never closed by this.
pub(crate) async fn session_lost(watch: &mut Option<SessionWatch>, state: &AppState) -> u16 {
    match watch {
        Some(watch) => watch.lost(state).await,
        None => std::future::pending().await,
    }
}

/// Admission for an operator route that checks pairing itself instead of
/// through `require_auth`, called when the request presented no token.
pub(crate) enum OperatorSession {
    /// No dashboard session is in play: the route's own check decides.
    Absent,
    /// An administrator session. For a long-lived stream, the watch that
    /// ends it with the session.
    Admitted(Option<SessionWatch>),
    /// A session that may not use the route, with its answer.
    Denied(Response),
}

pub(crate) fn operator_session(dashboard: Option<&Arc<DashboardAuth>>) -> OperatorSession {
    let Some(caller) = current_caller() else {
        return OperatorSession::Absent;
    };
    if let Err(denied) = caller.admit_operator() {
        return OperatorSession::Denied(denied.into_response());
    }
    match (caller, dashboard) {
        (DashboardCaller::Session(session), Some(auth)) => OperatorSession::Admitted(Some(
            SessionWatch::new(Arc::clone(auth), session, true),
        )),
        _ => OperatorSession::Admitted(None),
    }
}

/// Router-wide state for [`layer`].
#[derive(Clone)]
pub struct DashboardLayer {
    pub state: AppState,
    pub auth: Arc<DashboardAuth>,
}

/// Classify every request that carries a session cookie; see the module
/// docs. Installed on the whole router, so it covers every route,
/// WebSocket upgrades and the fallback included.
pub async fn layer(State(layer): State<DashboardLayer>, mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(Arc::clone(&layer.auth));
    let enabled = layer.state.config.read().gateway.dashboard_sign_in.enabled();
    if !enabled || request.headers().contains_key(header::AUTHORIZATION) {
        return next.run(request).await;
    }
    let Some(cookie) = session_cookie(request.headers()) else {
        return next.run(request).await;
    };
    let https = crate::api_oidc::request_is_https(&layer.state, request.headers());
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let own_origin = origin_of(https, &host);
    let caller = match check_origin(request.method(), request.headers(), &own_origin) {
        Err(rejection) => DashboardCaller::Rejected(rejection),
        Ok(()) => {
            let offered = offered_aliases(&layer.state);
            let caller = layer
                .auth
                .admit(|alias| offered.iter().any(|offered| offered == alias), &cookie)
                .await;
            match caller {
                DashboardCaller::Session(session) => {
                    match check_csrf(request.method(), request.headers(), &session) {
                        Ok(()) => DashboardCaller::Session(session),
                        Err(rejection) => DashboardCaller::Rejected(rejection),
                    }
                }
                rejected => rejected,
            }
        }
    };
    let clears = matches!(caller, DashboardCaller::Rejected(r) if r.clears_cookie());
    if let DashboardCaller::Session(session) = &caller {
        request.extensions_mut().insert(Arc::clone(session));
    }
    request.extensions_mut().insert(caller.clone());
    let mut response = DASHBOARD_CALLER.scope(caller, next.run(request)).await;
    if clears {
        let scope = CookieScope {
            https,
            path_prefix: &layer.state.path_prefix,
        };
        for value in scope.clear_session_cookies() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

/// A rejected session's answer as a full response, for routes that answer
/// with [`Response`] rather than the `require_auth` tuple.
pub(crate) fn rejection_response(rejection: SessionRejection) -> Response {
    rejection.body().into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use http_body_util::BodyExt as _;
    use std::collections::HashMap as Map;
    use std::net::SocketAddr;
    use tower::ServiceExt as _;
    use wiremock::matchers::{method as http_method, path as http_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zeroclaw_api::grants::{Resource, Verb};
    use zeroclaw_config::pairing::{PairingCodePolicy, PairingGuard};
    use zeroclaw_config::schema::{Config, OidcConfig, OidcValidation, PermissionProfileConfig};

    const HOST: &str = "localhost:42617";
    const OWN_ORIGIN: &str = "http://localhost:42617";

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 39999))
    }

    fn remote() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], 40000))
    }

    fn unix_now() -> u64 {
        now_unix()
    }

    /// An identity provider with discovery, an authorization endpoint the
    /// test never visits, and an introspection endpoint that vouches for any
    /// token as `sub` with `groups`, issued to `client_id`.
    async fn idp(groups: &[&str], client_id: &str) -> MockServer {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(http_method("GET"))
            .and(http_path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "introspection_endpoint": format!("{issuer}/introspect"),
                "code_challenge_methods_supported": ["S256"],
            })))
            .mount(&server)
            .await;
        Mock::given(http_method("POST"))
            .and(http_path("/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "token_type": "Bearer",
                "client_id": client_id,
                "iss": issuer,
                "sub": "alice",
                "aud": "zeroclaw",
                "exp": unix_now() + 600,
                "groups": groups,
                "preferred_username": "alice@example.com",
            })))
            .mount(&server)
            .await;
        server
    }

    fn sign_in_config(issuer: &str) -> Config {
        let mut config = Config::default();
        config.gateway.require_pairing = true;
        config.gateway.paired_tokens = vec!["zc_paired".into()];
        config.gateway.dashboard_sign_in.oidc = vec!["corp".into()];
        config.oidc.insert(
            "corp".into(),
            OidcConfig {
                issuer: issuer.to_string(),
                audience: "zeroclaw".into(),
                client_id: "gw".into(),
                client_secret: Some("s3cret".into()),
                validation: OidcValidation::Introspection,
                claim_path: "groups".into(),
                profile_map: Map::from([
                    ("admins".to_string(), "admin".to_string()),
                    ("ops".to_string(), "config-reader".to_string()),
                ]),
                interactive_clients: vec!["gw".into()],
                service_clients: vec!["svc".into()],
                ..OidcConfig::default()
            },
        );
        config.permission_profiles.insert(
            "admin".into(),
            PermissionProfileConfig {
                admin: true,
                ..PermissionProfileConfig::default()
            },
        );
        config.permission_profiles.insert(
            "config-reader".into(),
            PermissionProfileConfig {
                grants: Map::from([(Resource::Config, vec![Verb::Read])]),
                ..PermissionProfileConfig::default()
            },
        );
        config
    }

    /// Stands in for any operator route: answers exactly as `require_auth`
    /// decides.
    async fn operator_probe(State(state): State<AppState>, headers: HeaderMap) -> Response {
        match crate::api::require_auth(&state, &headers) {
            Ok(()) => StatusCode::OK.into_response(),
            Err(denied) => denied.into_response(),
        }
    }

    struct Fixture {
        router: Router,
        auth: Arc<DashboardAuth>,
        state: AppState,
    }

    /// The sign-in routes, the config route group and an operator route,
    /// under the session layer, wired as `run_gateway` wires them, with a
    /// store of the test's own.
    fn fixture(config: Config) -> Fixture {
        let pairing = Arc::new(PairingGuard::new(
            config.gateway.require_pairing,
            &config.gateway.paired_tokens,
            PairingCodePolicy::default(),
        ));
        let inbound = Arc::new(
            GatewayInboundAuth::from_config(&config, Arc::clone(&pairing))
                .expect("inbound auth builds"),
        );
        fixture_with(config, pairing, inbound, Arc::new(DashboardSessions::default()))
    }

    fn fixture_with(
        config: Config,
        pairing: Arc<PairingGuard>,
        inbound: Arc<GatewayInboundAuth>,
        sessions: Arc<DashboardSessions>,
    ) -> Fixture {
        let state = AppState {
            pairing,
            ..crate::api::tests::test_state(config)
        };
        let auth = Arc::new(DashboardAuth::new(sessions, Arc::clone(&inbound)));
        let router = Router::new()
            .merge(crate::config_admin_router(&inbound))
            .merge(crate::api_oidc::routes())
            .route("/api/operator-probe", get(operator_probe))
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(
                DashboardLayer {
                    state: state.clone(),
                    auth: Arc::clone(&auth),
                },
                layer,
            ));
        Fixture {
            router,
            auth,
            state,
        }
    }

    fn request(
        method: &str,
        path: &str,
        peer: SocketAddr,
        headers: &[(&str, &str)],
    ) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("host", HOST);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    async fn send(router: &Router, request: HttpRequest<Body>) -> Response {
        router.clone().oneshot(request).await.unwrap()
    }

    async fn json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn set_cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn cookie_from(response: &Response, name: &str) -> Option<String> {
        set_cookies(response).into_iter().find_map(|cookie| {
            let value = cookie.strip_prefix(&format!("{name}="))?;
            let value = value.split(';').next().unwrap_or_default();
            (!value.is_empty()).then(|| value.to_string())
        })
    }

    fn query_param(url: &str, name: &str) -> String {
        url.split_once('?')
            .unwrap()
            .1
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap()
            .to_string()
    }

    fn id_token(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.c2ln")
    }

    /// A started sign-in: the binding cookie and the flow's `state` and
    /// `nonce`, read back from the redirect to the identity provider.
    struct Started {
        binding: String,
        state: String,
        nonce: String,
    }

    async fn start(fixture: &Fixture, path: &str) -> Started {
        let response = send(&fixture.router, request("GET", path, loopback(), &[])).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let binding = cookie_from(&response, BINDING_COOKIE).expect("binding cookie set");
        let binding_cookie = set_cookies(&response)
            .into_iter()
            .find(|c| c.starts_with(BINDING_COOKIE))
            .unwrap();
        assert!(binding_cookie.contains("HttpOnly"), "{binding_cookie}");
        assert!(binding_cookie.contains("SameSite=Lax"), "{binding_cookie}");
        assert!(binding_cookie.contains("Path=/oidc/callback"), "{binding_cookie}");
        Started {
            binding,
            state: query_param(&location, "state"),
            nonce: query_param(&location, "nonce"),
        }
    }

    async fn mount_token(server: &MockServer, nonce: &str, with_id_token: bool) {
        let issuer = server.uri();
        let mut body = serde_json::json!({
            "access_token": "at-alice",
            "token_type": "Bearer",
            "expires_in": 600,
        });
        if with_id_token {
            body["id_token"] = serde_json::json!(id_token(serde_json::json!({
                "iss": issuer,
                "aud": "gw",
                "sub": "alice",
                "exp": unix_now() + 600,
                "nonce": nonce,
            })));
        }
        Mock::given(http_method("POST"))
            .and(http_path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    fn callback(started: &Started, binding: Option<&str>) -> HttpRequest<Body> {
        let cookie = binding.map(|b| format!("{BINDING_COOKIE}={b}"));
        let mut headers = vec![];
        if let Some(cookie) = cookie.as_deref() {
            headers.push(("cookie", cookie));
        }
        request(
            "GET",
            &format!("/oidc/callback?state={}&code=c1", started.state),
            loopback(),
            &headers,
        )
    }

    struct SignedIn {
        cookie: String,
        csrf: String,
        session: serde_json::Value,
    }

    impl SignedIn {
        fn cookie_header(&self) -> String {
            format!("{SESSION_COOKIE}={}", self.cookie)
        }
    }

    async fn sign_in(fixture: &Fixture, server: &MockServer) -> SignedIn {
        let started = start(fixture, "/auth/sign-in/corp?return=/chat").await;
        mount_token(server, &started.nonce, true).await;
        let response = send(&fixture.router, callback(&started, Some(&started.binding))).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/chat");
        let session_cookie = set_cookies(&response)
            .into_iter()
            .find(|c| c.starts_with(SESSION_COOKIE))
            .expect("session cookie set");
        assert!(session_cookie.contains("HttpOnly"), "{session_cookie}");
        assert!(session_cookie.contains("SameSite=Strict"), "{session_cookie}");
        assert!(session_cookie.contains("Path=/;"), "{session_cookie}");
        assert!(!session_cookie.contains("Secure"), "plain HTTP on loopback");
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with(BINDING_COOKIE) && c.contains("Max-Age=0")),
            "the binding cookie is cleared"
        );
        let cookie = cookie_from(&response, SESSION_COOKIE).unwrap();
        let cookie_header = format!("{SESSION_COOKIE}={cookie}");
        let response = send(
            &fixture.router,
            request(
                "GET",
                "/api/auth/session",
                loopback(),
                &[("cookie", &cookie_header), ("sec-fetch-site", "same-origin")],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = json(response).await;
        SignedIn {
            cookie,
            csrf: session["csrf_token"].as_str().unwrap().to_string(),
            session,
        }
    }

    async fn probe(fixture: &Fixture, headers: &[(&str, &str)]) -> (StatusCode, serde_json::Value) {
        let response = send(
            &fixture.router,
            request("GET", "/api/operator-probe", loopback(), headers),
        )
        .await;
        let status = response.status();
        (status, json(response).await)
    }

    // ── Off by default ───────────────────────────────────────────────

    #[tokio::test]
    async fn with_sign_in_off_a_session_cookie_is_no_credential_at_all() {
        let server = idp(&["admins"], "gw").await;
        let mut config = sign_in_config(&server.uri());
        config.gateway.dashboard_sign_in.oidc.clear();
        let fixture = fixture(config);

        let (status, body) = probe(&fixture, &[("cookie", "zc_session=forged")]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.get("reason").is_none(), "the pairing denial, unchanged: {body}");

        let response = send(
            &fixture.router,
            request("GET", "/api/auth/methods", loopback(), &[]),
        )
        .await;
        assert_eq!(json(response).await["oidc"], serde_json::json!([]));

        let response = send(
            &fixture.router,
            request("GET", "/auth/sign-in/corp", loopback(), &[]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(set_cookies(&response).is_empty());
    }

    // ── The flow ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn an_administrator_signs_in_reaches_operator_routes_and_signs_out() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));

        let methods = json(
            send(
                &fixture.router,
                request("GET", "/api/auth/methods", loopback(), &[]),
            )
            .await,
        )
        .await;
        assert_eq!(
            methods["oidc"],
            serde_json::json!([{"alias": "corp", "provider": "oidc.corp"}])
        );

        let signed_in = sign_in(&fixture, &server).await;
        assert_eq!(signed_in.session["kind"], "oidc");
        assert_eq!(signed_in.session["provider"], "oidc.corp");
        assert_eq!(signed_in.session["admin"], true);
        assert_eq!(signed_in.session["display_name"], "alice@example.com");
        assert!(signed_in.session["expires_at"].as_u64().unwrap() > unix_now());

        let cookie = signed_in.cookie_header();
        let (status, _) = probe(&fixture, &[("cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK, "an administrator is operator-equivalent");

        // Sign-out changes state: the CSRF token and the own origin are required.
        let response = send(
            &fixture.router,
            request(
                "POST",
                "/auth/sign-out",
                loopback(),
                &[("cookie", &cookie), ("origin", OWN_ORIGIN)],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(response).await["reason"], "csrf");

        let response = send(
            &fixture.router,
            request(
                "POST",
                "/auth/sign-out",
                loopback(),
                &[
                    ("cookie", &cookie),
                    ("origin", OWN_ORIGIN),
                    (CSRF_HEADER, &signed_in.csrf),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with(SESSION_COOKIE) && c.contains("Max-Age=0"))
        );

        let (status, body) = probe(&fixture, &[("cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["reason"], "session_invalid");
    }

    #[tokio::test]
    async fn a_scoped_account_gets_config_but_not_operator_routes() {
        let server = idp(&["ops"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let signed_in = sign_in(&fixture, &server).await;
        assert_eq!(signed_in.session["admin"], false);
        assert_eq!(signed_in.session["features"]["chat"], false);

        let cookie = signed_in.cookie_header();
        let (status, body) = probe(&fixture, &[("cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["reason"], "operator_required");

        // The config route group takes the session as the principal.
        let response = send(
            &fixture.router,
            request(
                "GET",
                "/api/quickstart/state",
                loopback(),
                &[("cookie", &cookie), ("sec-fetch-site", "same-origin")],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(
            &fixture.router,
            request(
                "POST",
                "/api/quickstart/fields",
                loopback(),
                &[
                    ("cookie", &cookie),
                    ("origin", OWN_ORIGIN),
                    (CSRF_HEADER, &signed_in.csrf),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "Config:Read only");
    }

    #[tokio::test]
    async fn a_sign_in_without_an_id_token_is_refused() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let started = start(&fixture, "/auth/sign-in/corp").await;
        mount_token(&server, &started.nonce, false).await;
        let response = send(&fixture.router, callback(&started, Some(&started.binding))).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(cookie_from(&response, SESSION_COOKIE).is_none());
        assert_eq!(fixture.auth.sessions.len(), 0);
    }

    #[tokio::test]
    async fn a_callback_from_another_browser_cannot_finish_the_sign_in() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let started = start(&fixture, "/auth/sign-in/corp").await;
        mount_token(&server, &started.nonce, true).await;

        for binding in [None, Some("someone-elses-binding")] {
            let response = send(&fixture.router, callback(&started, binding)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{binding:?}");
            assert!(cookie_from(&response, SESSION_COOKIE).is_none());
        }
        // The first refusal consumed the flow: the right cookie is too late.
        let response = send(&fixture.router, callback(&started, Some(&started.binding))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(fixture.auth.sessions.len(), 0);
        // No code ever reached the identity provider.
        let exchanges = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/token")
            .count();
        assert_eq!(exchanges, 0);
    }

    #[tokio::test]
    async fn service_and_unmapped_identities_get_no_session() {
        for (groups, client) in [(&["admins"][..], "svc"), (&["nobody"][..], "gw")] {
            let server = idp(groups, client).await;
            let fixture = fixture(sign_in_config(&server.uri()));
            let started = start(&fixture, "/auth/sign-in/corp").await;
            mount_token(&server, &started.nonce, true).await;
            let response =
                send(&fixture.router, callback(&started, Some(&started.binding))).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{client} {groups:?}");
            assert!(cookie_from(&response, SESSION_COOKIE).is_none());
            assert_eq!(fixture.auth.sessions.len(), 0);
        }
    }

    #[tokio::test]
    async fn sign_in_needs_https_off_the_loopback_host() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let response = send(
            &fixture.router,
            request("GET", "/auth/sign-in/corp", remote(), &[]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(set_cookies(&response).is_empty());
    }

    #[tokio::test]
    async fn an_off_site_return_path_lands_on_the_dashboard_root() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        for target in ["//evil.example", "https://evil.example", "/\\evil.example"] {
            let started = start(
                &fixture,
                &format!("/auth/sign-in/corp?return={}", target.replace('\\', "%5C")),
            )
            .await;
            // A fresh token answer for this flow's nonce.
            server.reset().await;
            mount_discovery_and_introspection(&server, &["admins"], "gw").await;
            mount_token(&server, &started.nonce, true).await;
            let response =
                send(&fixture.router, callback(&started, Some(&started.binding))).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{target}");
            assert_eq!(response.headers()[header::LOCATION], "/", "{target}");
        }
    }

    async fn mount_discovery_and_introspection(server: &MockServer, groups: &[&str], client: &str) {
        let issuer = server.uri();
        Mock::given(http_method("GET"))
            .and(http_path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "introspection_endpoint": format!("{issuer}/introspect"),
                "code_challenge_methods_supported": ["S256"],
            })))
            .mount(server)
            .await;
        Mock::given(http_method("POST"))
            .and(http_path("/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "token_type": "Bearer",
                "client_id": client,
                "iss": issuer,
                "sub": "alice",
                "aud": "zeroclaw",
                "exp": unix_now() + 600,
                "groups": groups,
            })))
            .mount(server)
            .await;
    }

    // ── Where a cookie-carrying request came from ────────────────────

    #[tokio::test]
    async fn cross_origin_and_cross_site_use_of_the_cookie_is_refused() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let signed_in = sign_in(&fixture, &server).await;
        let cookie = signed_in.cookie_header();

        // A page on another port of the same host is same-site, so the
        // browser sends the cookie; its Origin gives it away.
        let other = "http://localhost:3000";
        let (status, body) = probe(&fixture, &[("cookie", &cookie), ("origin", other)]).await;
        assert_eq!((status, body["reason"].clone()), (StatusCode::FORBIDDEN, "origin".into()));

        let (status, body) =
            probe(&fixture, &[("cookie", &cookie), ("sec-fetch-site", "same-site")]).await;
        assert_eq!((status, body["reason"].clone()), (StatusCode::FORBIDDEN, "origin".into()));

        // WebSocket upgrades must name the dashboard's origin.
        let (status, body) =
            probe(&fixture, &[("cookie", &cookie), ("upgrade", "websocket")]).await;
        assert_eq!((status, body["reason"].clone()), (StatusCode::FORBIDDEN, "origin".into()));
        let (status, _) = probe(
            &fixture,
            &[("cookie", &cookie), ("upgrade", "websocket"), ("origin", OWN_ORIGIN)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // A state-changing request with a foreign origin fails even with the token.
        let response = send(
            &fixture.router,
            request(
                "POST",
                "/auth/sign-out",
                loopback(),
                &[("cookie", &cookie), ("origin", other), (CSRF_HEADER, &signed_in.csrf)],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(response).await["reason"], "origin");
        assert_eq!(fixture.auth.sessions.len(), 1, "a refused request ends nothing");
    }

    #[tokio::test]
    async fn an_explicit_bearer_beats_the_cookie() {
        let server = idp(&["ops"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let signed_in = sign_in(&fixture, &server).await;
        let cookie = signed_in.cookie_header();
        let (status, _) = probe(
            &fixture,
            &[("cookie", &cookie), ("authorization", "Bearer zc_paired")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the paired bearer decides, not the scoped cookie");
        let (status, _) = probe(
            &fixture,
            &[("cookie", &cookie), ("authorization", "Bearer wrong")],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── The store ────────────────────────────────────────────────────

    async fn verified_auth(fixture: &Fixture) -> ConnectionAuth {
        fixture
            .auth
            .inbound
            .authenticate_scoped("at-alice", "oidc.corp")
            .await
            .expect("the mock provider vouches for the token")
    }

    fn new_session(auth: ConnectionAuth, inbound: &GatewayInboundAuth, lifetime: u64) -> NewSession {
        NewSession {
            alias: "corp".into(),
            bearer: "at-alice".into(),
            auth,
            authority: inbound.authority_ref(),
            display_name: "alice".into(),
            lifetime_secs: lifetime,
        }
    }

    #[tokio::test]
    async fn a_full_store_refuses_new_sign_ins_instead_of_evicting_others() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let auth = verified_auth(&fixture).await;
        let mut cookies = Vec::new();
        for i in 0..MAX_SESSIONS {
            let mut other = auth.clone();
            other.principal.id = zeroclaw_api::principal::PrincipalId(format!("principal-{i}"));
            let (cookie, _) = fixture
                .auth
                .sessions
                .insert(new_session(other, &fixture.auth.inbound, 3600), unix_now())
                .expect("room for every distinct principal up to the cap");
            cookies.push(cookie);
        }
        assert!(!fixture.auth.sessions.has_room());
        let refused = fixture
            .auth
            .sessions
            .insert(new_session(auth.clone(), &fixture.auth.inbound, 3600), unix_now());
        assert_eq!(refused.err(), Some(StoreFull));

        // The starter refuses before any round trip to the provider.
        let response = send(
            &fixture.router,
            request("GET", "/auth/sign-in/corp", loopback(), &[]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(fixture.auth.sessions.len(), MAX_SESSIONS);
        assert!(
            cookies
                .iter()
                .all(|cookie| fixture.auth.sessions.sessions.lock().contains_key(&session_key(cookie))),
            "every existing session survives"
        );
    }

    #[tokio::test]
    async fn one_principal_past_its_cap_gives_up_only_its_own_oldest_session() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let auth = verified_auth(&fixture).await;
        let mut bystander = auth.clone();
        bystander.principal.id = zeroclaw_api::principal::PrincipalId("bystander".into());
        let (bystander_cookie, _) = fixture
            .auth
            .sessions
            .insert(new_session(bystander, &fixture.auth.inbound, 3600), unix_now())
            .unwrap();
        let mut own = Vec::new();
        for i in 0..=MAX_SESSIONS_PER_PRINCIPAL {
            let (cookie, view) = fixture
                .auth
                .sessions
                .insert(
                    new_session(auth.clone(), &fixture.auth.inbound, 3600),
                    unix_now() + i as u64,
                )
                .unwrap();
            own.push((cookie, view));
        }
        let held = |cookie: &str| {
            fixture
                .auth
                .sessions
                .sessions
                .lock()
                .contains_key(&session_key(cookie))
        };
        assert!(!held(&own[0].0), "the oldest of this principal's sessions went");
        assert!(own[0].1.ended.is_cancelled(), "and its sockets were told");
        assert!(own[1..].iter().all(|(cookie, _)| held(cookie)));
        assert!(held(&bystander_cookie), "nobody else's session is touched");
    }

    #[tokio::test]
    async fn an_expired_session_ends_and_says_so() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let auth = verified_auth(&fixture).await;
        let (cookie, view) = fixture
            .auth
            .sessions
            .insert(new_session(auth, &fixture.auth.inbound, 0), unix_now())
            .unwrap();
        let cookie_header = format!("{SESSION_COOKIE}={cookie}");
        let response = send(
            &fixture.router,
            request("GET", "/api/operator-probe", loopback(), &[("cookie", &cookie_header)]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with(SESSION_COOKIE) && c.contains("Max-Age=0")),
            "the browser is told to drop the cookie"
        );
        assert_eq!(json(response).await["reason"], "session_expired");
        assert!(view.ended.is_cancelled());
        assert_eq!(fixture.auth.sessions.len(), 0);
    }

    #[tokio::test]
    async fn a_provider_no_longer_offered_ends_its_sessions() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let signed_in = sign_in(&fixture, &server).await;
        let caller = fixture.auth.admit(|_| false, &signed_in.cookie).await;
        assert!(matches!(
            caller,
            DashboardCaller::Rejected(SessionRejection::Invalid)
        ));
        assert_eq!(fixture.auth.sessions.len(), 0);
    }

    #[tokio::test]
    async fn a_policy_that_no_longer_maps_the_account_ends_the_session() {
        let server = idp(&["admins"], "gw").await;
        let config = sign_in_config(&server.uri());
        let pairing = Arc::new(PairingGuard::new(
            true,
            &config.gateway.paired_tokens,
            PairingCodePolicy::default(),
        ));
        let rpc = Arc::new(RpcInboundAuth::from_config(&config, Arc::clone(&pairing)).unwrap());
        let inbound = Arc::new(GatewayInboundAuth::from_shared(Arc::clone(&rpc)));
        let fixture = fixture_with(
            config.clone(),
            pairing,
            inbound,
            Arc::new(DashboardSessions::default()),
        );
        let signed_in = sign_in(&fixture, &server).await;
        let (status, _) = probe(&fixture, &[("cookie", &signed_in.cookie_header())]).await;
        assert_eq!(status, StatusCode::OK);

        // The operator drops the group mapping; the next request sees it.
        let mut revoked = config;
        revoked.oidc.get_mut("corp").unwrap().profile_map.remove("admins");
        rpc.publish_accepted(&revoked, rpc.accepted_revision() + 1)
            .unwrap();
        let (status, body) = probe(&fixture, &[("cookie", &signed_in.cookie_header())]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["reason"], "session_expired");
    }

    #[tokio::test]
    async fn a_session_from_an_earlier_generation_is_verified_again_before_use() {
        let server = idp(&["admins"], "gw").await;
        let config = sign_in_config(&server.uri());
        let sessions = Arc::new(DashboardSessions::default());
        let generation = |config: &Config| {
            let pairing = Arc::new(PairingGuard::new(
                true,
                &config.gateway.paired_tokens,
                PairingCodePolicy::default(),
            ));
            let inbound = Arc::new(
                GatewayInboundAuth::from_config(config, Arc::clone(&pairing)).unwrap(),
            );
            fixture_with(config.clone(), pairing, inbound, Arc::clone(&sessions))
        };
        let first = generation(&config);
        let signed_in = sign_in(&first, &server).await;

        // A reload: a new gateway generation with a new authority, the same store.
        let second = generation(&config);
        let introspections = |requests: &[wiremock::Request]| {
            requests.iter().filter(|r| r.url.path() == "/introspect").count()
        };
        let before = introspections(&server.received_requests().await.unwrap());
        let (status, _) = probe(&second, &[("cookie", &signed_in.cookie_header())]).await;
        assert_eq!(status, StatusCode::OK, "the sign-in survives the reload");
        let after = introspections(&server.received_requests().await.unwrap());
        assert_eq!(after, before + 1, "verified once against the new authority");
        let (status, _) = probe(&second, &[("cookie", &signed_in.cookie_header())]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            introspections(&server.received_requests().await.unwrap()),
            after,
            "and not again while the new authority stands"
        );
        drop(first);
    }

    // ── Long-lived sockets ───────────────────────────────────────────

    #[tokio::test]
    async fn a_socket_watch_fires_when_its_session_is_signed_out() {
        let server = idp(&["admins"], "gw").await;
        let fixture = fixture(sign_in_config(&server.uri()));
        let signed_in = sign_in(&fixture, &server).await;
        let DashboardCaller::Session(session) = fixture
            .auth
            .admit(|alias| alias == "corp", &signed_in.cookie)
            .await
        else {
            panic!("signed in");
        };
        let mut watch = Some(SessionWatch::new(
            Arc::clone(&fixture.auth),
            Arc::clone(&session),
            true,
        ));
        assert!(fixture.auth.end(&session));
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session_lost(&mut watch, &fixture.state),
        )
        .await
        .expect("the watch fires at once");
        assert_eq!(code, WS_CLOSE_SESSION_ENDED);

        let mut none: Option<SessionWatch> = None;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                session_lost(&mut none, &fixture.state)
            )
            .await
            .is_err(),
            "a socket without a session is never closed by it"
        );
    }

    #[test]
    fn origins_compare_as_browsers_send_them() {
        assert_eq!(origin_of(false, "LocalHost:42617"), "http://localhost:42617");
        assert_eq!(origin_of(true, "zc.example.com:443"), "https://zc.example.com");
        assert_eq!(origin_of(false, "zc.example.com:80"), "http://zc.example.com");
        assert_eq!(origin_of(true, "zc.example.com:8443"), "https://zc.example.com:8443");
    }

    #[test]
    fn cookies_carry_the_attributes_their_scope_needs() {
        let https_root = CookieScope { https: true, path_prefix: "" };
        let value = https_root.session_cookie("v").to_str().unwrap().to_string();
        assert_eq!(value, "__Host-zc_session=v; Path=/; HttpOnly; SameSite=Strict; Secure");
        let prefixed = CookieScope { https: true, path_prefix: "/zc" };
        let value = prefixed.session_cookie("v").to_str().unwrap().to_string();
        assert_eq!(value, "zc_session=v; Path=/zc/; HttpOnly; SameSite=Strict; Secure");
        let binding = prefixed.binding_cookie("b", 600).to_str().unwrap().to_string();
        assert_eq!(
            binding,
            "zc_signin=b; Path=/zc/oidc/callback; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
        );
        assert_eq!(https_root.clear_session_cookies().len(), 2);
    }
}
