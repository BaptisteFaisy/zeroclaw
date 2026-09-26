## Security-focused review — consolidated OIDC / principal-isolation slice (#8289)

Reviewed the full diff against `master` with a focus on the auth surface: OIDC enrollment, principal isolation, RPC dispatch authorization, memory-plane separation, and the architecture gates. Verdict up front: **no blocking findings.** This is careful, fail-closed, spec-grounded work. Notes below are non-blocking; a couple are questions for the author to confirm rather than defects.

### What I checked and why it holds

**OIDC enrollment client (`security/auth_provider/enrollment.rs`)**
- Issuer binding is correct: the discovery document must assert exactly the configured issuer before any advertised endpoint is used, with a trailing-slash hint that does not loosen the equality check.
- Every credential-bearing endpoint is re-validated through the shared `validate_discovered_endpoint` (https, or exact-loopback http, never userinfo). Redirects are refused, not followed.
- PKCE is S256-only with no downgrade path; the plain-PKCE default advertisement is explicitly refused.
- `id_token` validation implements OIDC Core 3.1.3.7 faithfully — issuer, `aud`/`azp` (with `azp` required on multi-audience), NumericDate `exp` with saturating float→int and leeway, and nonce echo.
- The A→B provider-swap defense in `pkce_exchange` (refuse if issuer/client repointed while the flow was pending) is exactly right and prevents leaking B's secret to A's endpoint.
- The RFC 8252 loopback listener is one-shot, state-gated, issuer-checked (RFC 9207), bounds its reads, does not reflect any request input, and has stall protection against local port-probe noise.

**Principal / memory isolation (`memory_traits.rs`, `principal_plane.rs`, `sqlite.rs`)**
- Trait defaults for every `*_for_principal` op `bail!` — a backend without principal scoping fails closed rather than silently un-scoping. Correct posture.
- `PrincipalPlaneMemory` routes all ordinary ops to the scoped forms; ops with no private-plane meaning refuse rather than fall through.
- The SQLite predicate binds owner + agent + namespace + tenant as parameters (`scope_predicate`), with a physical-key prefix as defense-in-depth and `principal_id IS NULL` gating every legacy/shared statement. No injection surface; no cross-principal leakage path found.

**RPC dispatch authorization (`rpc/dispatch.rs`)**
- The `scoped_principal_id` (admin bypasses) vs `owner_principal_id` (durable identity, admin does not bypass) split is subtle and correct: promotion/demotion never re-labels or hides a principal's sessions/memory.
- `memory_plane` refuses `"shared"` to scoped principals and audits admin shared access.
- `recheck_authority_after_admission` / `recheck_config_write_authority` close the TOCTOU window by re-resolving authority against live policy under the write lock.
- Forwarded shell environment is retained only for local + admin, dropped (audited) otherwise — a scoped/remote principal cannot shape the daemon's subprocess env around its allowlist.

**Architecture gates (`tests/architecture/auth_boundary.rs`)**
- Turns two placement invariants (config handlers must live under the authenticated router; every session-id-taking RPC method must call `authorize_session_owner`) into build failures. This catches a whole class of future regressions and is the right way to enforce placement-based auth.

**Nevis removal (`config/schema.rs`, `security/mod.rs`)**
- Dead auth modules removed; `[security.nevis]` kept as an inert `Option<Value>` so old configs still load. Config-compat win, not a security regression.

### Non-blocking notes / questions

1. `enrollment.rs` `client_credentials` and device flows request `scope=openid`. For pure service principals (`client_credentials`) some IdPs reject `openid` without a user context. Non-blocking, but worth confirming the target IdPs tolerate it, or make scope configurable per alias.
2. `@Audacity88`'s environment-lifecycle follow-up from #10265: `retained_tui_env` appears to fully address it (env dropped for anything but local+admin, on-disconnect cleanup present). Can you confirm this matches the specific lifecycle concern you raised, or point at the residual case if not?
3. `read_request_target` in the loopback listener breaks on the first `\r\n` or 8192 bytes — fine for a GET callback. Minor: the `buf.windows(2).any(...)` rescans the whole buffer each read; negligible at these sizes, noting only for completeness.

### Stack path

Per the 2026-09-23 contributor call this is the consolidated single slice carrying the #8289 stack (the slice-by-slice alternative in the earlier thread is superseded). I'm refreshing this PR onto current `master` (it was CONFLICTING — three files: `agent/agent.rs`, `rpc/dispatch.rs`, `authentication.md`) and will keep it green; downstream slice PRs get closed once this lands.
