//! Retirement of orphaned remote sessions.
//!
//! A remote client's sessions stay live after it disconnects, so that it can
//! reconnect with its identity and carry on. A client that never comes back,
//! or comes back under a new identity (which cannot reach them), would
//! otherwise hold its places in the daemon's live-session map until a
//! restart. Once the owning identity has had no live connection for
//! `wss.orphaned_session_timeout_secs`, each of its sessions that has been idle
//! as long, has no turn running and has no approval pending is closed, as
//! `session/close` would close it. The transcript stays where it is; only the
//! live session goes.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::context::RpcContext;
use super::session::OwnedSession;

/// Close every orphaned remote session that is due at `now` and return the
/// ids closed. Also forgets the departures of identities that no longer own a
/// live session.
pub async fn retire_orphaned_sessions(ctx: &RpcContext, now: Instant) -> Vec<String> {
    let timeout_secs = ctx.config.read().wss.orphaned_session_timeout_secs;
    let checked_at = Instant::now();
    let owned = ctx.sessions.owned_sessions().await;
    let mut retired = Vec::new();
    if timeout_secs > 0 {
        let timeout = Duration::from_secs(timeout_secs);
        for candidate in &owned {
            if is_due(ctx, candidate, timeout, now) && retire(ctx, candidate, timeout, now).await {
                retired.push(candidate.id.clone());
            }
        }
    }
    if !retired.is_empty() {
        crate::util::release_freed_heap();
    }

    // Sessions are created only by a connected identity, so an identity that
    // departed before the snapshot has all its sessions in it. One that owns
    // none of them any more needs no departure record.
    let owners: HashSet<&str> = owned
        .iter()
        .filter(|session| !retired.contains(&session.id))
        .map(|session| session.owner_tui_id.as_str())
        .collect();
    ctx.tui_registry.retain_departures(|tui_id, departure| {
        departure.at >= checked_at || owners.contains(tui_id)
    });
    retired
}

/// Whether `session` is an orphaned remote session that is due at `now`.
fn is_due(ctx: &RpcContext, session: &OwnedSession, timeout: Duration, now: Instant) -> bool {
    ctx.tui_registry
        .departure(&session.owner_tui_id)
        .is_some_and(|departure| {
            departure.remote && now.saturating_duration_since(departure.at) >= timeout
        })
        && now.saturating_duration_since(session.last_active) >= timeout
        && !ctx.sessions.has_inflight_turn(&session.id)
        && !ctx.approval_pending.has_pending_for_session(&session.id)
}

/// Close one orphaned session, the way `session/close` closes a session.
async fn retire(
    ctx: &RpcContext,
    candidate: &OwnedSession,
    timeout: Duration,
    now: Instant,
) -> bool {
    // Serialize with prompts and client closes on the same session.
    let Ok(_permit) = ctx.sessions.session_queue.acquire(&candidate.id).await else {
        return false;
    };
    // The same incarnation, still idle and still orphaned, under the permit.
    let still_due = ctx
        .sessions
        .owned_session(&candidate.id)
        .await
        .is_some_and(|current| {
            current.generation == candidate.generation
                && current.owner_tui_id == candidate.owner_tui_id
                && is_due(ctx, &current, timeout, now)
        });
    if !still_due {
        return false;
    }
    if let Some(agent) = ctx.sessions.get_agent(&candidate.id).await {
        agent
            .lock()
            .await
            .channel_handles()
            .unregister_channel("rpc");
    }
    if !ctx
        .sessions
        .remove_generation(&candidate.id, candidate.generation)
        .await
    {
        return false;
    }
    if let Some(ref hooks) = ctx.hooks {
        hooks.fire_session_end(&candidate.id, "rpc").await;
    }
    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_category(::zeroclaw_log::EventCategory::Agent)
            .with_outcome(::zeroclaw_log::EventOutcome::Success)
            .with_attrs(::serde_json::json!({
                "session_id": candidate.id,
                "owner_tui_id": candidate.owner_tui_id,
                "timeout_secs": timeout.as_secs(),
            })),
        "Closed an orphaned remote session; its transcript is kept"
    );
    true
}

/// How long to wait between checks: the timeout itself when it is short,
/// otherwise a minute. With retirement off, a minute, so that turning it on
/// takes effect without a restart.
fn check_interval(timeout_secs: u64) -> Duration {
    if timeout_secs == 0 {
        return Duration::from_secs(60);
    }
    Duration::from_secs(timeout_secs.clamp(1, 60))
}

/// Run [`retire_orphaned_sessions`] until `cancel` fires or `ctx` is dropped.
/// The task holds `ctx` only while it checks, so it never keeps a finished
/// daemon generation alive.
pub fn spawn_orphan_retirement(
    ctx: &Arc<RpcContext>,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::downgrade(ctx);
    zeroclaw_spawn::spawn!(async move {
        loop {
            let Some(timeout_secs) = ctx
                .upgrade()
                .map(|ctx| ctx.config.read().wss.orphaned_session_timeout_secs)
            else {
                return;
            };
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(check_interval(timeout_secs)) => {}
            }
            let Some(ctx) = ctx.upgrade() else {
                return;
            };
            retire_orphaned_sessions(&ctx, Instant::now()).await;
        }
    })
}
