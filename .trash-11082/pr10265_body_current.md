> **Stacked on #10263** (→ #10259 → #10255 → #10248) — review scope is the seven commits from `feat(infra): stamp session stores with their owning principal` onward: the five original slice commits plus the two review-response commits (`fix(infra): fail closed on an unrecordable session owner; repair the ACP owner index`, `fix(security): bind session ownership to the exact stored record and incarnation`). Depends on #10263.

## Summary

- **Base branch:** `master`
- **What changed and why:** The session half of the RFC 7141 storage boundary (the milestone's stage-4 requirement this tracker owns; the broader multi-user rollout stays with its own tracker):
  - **Storage**: `session_metadata` and `acp_sessions` gain a nullable `principal_id` (idempotent migrations + indexes; the ACP index is (re)created whenever the column exists, so an interrupted migration repairs itself on the next open), threaded through every metadata read. `set_session_principal` stamps the chat backend and its trait default now fails closed (`Unsupported`) instead of succeeding silently; ACP `create_session` takes the owner at creation. `delete_session_owned` on both stores is an atomic ownership predicate — the check and the destruction of the owner row are one SQL statement, and backends without the column fail closed by deleting nothing.
  - **Approval binding**: `ApprovalPendingMap` keys `request_id → (originating session_id, responder)`, so `session/approve` authorizes against the session the approval was *raised for*, never client-supplied routing.
  - **Canonical record**: one resolver locates the live incarnation, every chat key (`rpc_`, `gw_`, raw) and the ACP row for an id, refuses an id whose records disagree about their owner (a prefixed-id or ACP/chat collision is an error, never a read of someone else's data), and returns one record with one durable location. `messages`, `state` and `delete` act on exactly that record; store failures are errors, never absence.
  - **Incarnation binding**: the ownership check returns the record with the live generation, and every operation that then waits re-validates owner and generation at its admission boundary (prompt after its permit, close/delete/kill after signal-then-acquire, configure under the provider-update lock); removal is generation-bound. Resume is owner-predicated inside the store's `resume_existing`, under the store lock, so a foreign incarnation installed after an earlier read is never adopted.
  - **Identity vs bypass**: sessions are stamped with the authenticated principal's durable identity (`owner_principal_id`, admin or not; `None` only for the unauthenticated shared operator), while the ownership check uses the authorization scope (`scoped_principal_id`; `None` bypasses). Rehydration restores the durable owner, never the restorer's scope, so an administrator restoring another principal's reaped session does not re-label it.
  - **Enforcement**: `session/new` stamps the creator everywhere a session lands (live store, chat row, ACP row); for a scoped creator a failed or unsupported stamp fails the creation and unwinds the live entry. Every session-targeting method (prompt, configure, git_branch, close, cancel, kill, messages, state, delete, resume-by-id) resolves the canonical record: scoped principals get one uniform "not found or not owned" denial (no existence oracle; legacy NULL rows invisible), unscoped connections pass with a cross-principal audit event when touching an owned session. Delete destroys the resolved durable row through the owner-predicated store primitive and reports success only when something was removed. Listings filter to the caller's own sessions. Fresh session ids are reserved atomically, so `session/new` can never replace a live session the caller does not own.
  - **Memory interim (fail closed)**: scoped principals must scope memory reads to an owned `session_id`, and `memory/store` / `memory/delete` are refused for scoped principals outright, because the current backend keys rows by (agent, key) with no owner predicate — never silently un-scoped. Unscoped connections are unaffected.
- **Scope boundary:** No principal-owned memory storage (the second half of the storage boundary — #10268; the interim posture above is deny, not ignore). No gateway/channel session surfaces (#6250 and channel identity are separate boundaries). No per-sender RBAC or broader multi-user scope hardening (that tracker's own rollout).
- **Blast radius:** session persistence (`zeroclaw-infra` both stores — additive nullable columns; the `SessionBackend::set_session_principal` default now errors), the ACP orchestrator's `create_session` call (passes `None`, unchanged behavior), the RPC session/memory handlers, the live session store's resume/removal primitives, the approval map shape.
- **Linked issue(s):** Depends on #10263. Related #8289 (stage 4 storage boundary), Related #8290 (owns the broader rollout this unblocks), Related #7141. Supersedes #8672 in part (the session-store `principal_id` migration, ownership helpers, and approval binding; the dispatcher checks are upgraded from check-then-mutate to storage-predicated deletes bound to one resolved record).
- **Labels (live):** `enhancement`, `docs`, `core`, `agent`, `channel`, `config`, `daemon`, `gateway`, `runtime`, `security`, `tool`, `distinguished contributor`, `channel:core`, `tool:delegate`, `observability:log`, `domain:security`, `tool:mcp`, `status:accepted`, `stacked`, `quickstart`, `zerocode`, `risk:high`, `size:XL`, `channel:acp`, `cli`, `topic:identity-access`.

## Testing (required)

### How you can test (when useful)

- **Reviewer testing requested?** Yes — the isolation is directly observable with two local users.
- **Interface(s) exercised:** `tui` (zerocode), `cli`.
- **Setup / preconditions:** a daemon from this branch; `[users]` entries for two Unix accounts with a profile granting sessions; `security.trust_daemon_uid` left on.
- **Steps to run:**
  1. As user A (mapped uid), create a session and send a prompt.
  2. As user B, run `session/list` (A's session absent), then `session/messages`/`session/delete` against A's session id — both refused with `-32012` "not found or not owned".
  3. As the daemon's own user (unscoped), list sessions — both visible; note the cross-principal audit event when touching A's session.
  4. Restart the daemon and repeat step 2 — the on-disk stamp keeps enforcing.
- **Expected on this branch (after):** as above.
- **Prior behavior on `master` (before):** every authenticated connection sees and can delete every session; there is no owner anywhere.

### How I tested

- **CI checks relied on and why they cover this change:** the hosted Quality Gate on the current head (`5157f9d4b7`): fmt, clippy `-D warnings`, and the parallel workspace tests cover the changed surface; migrations, predicates, and dispatcher behavior are pinned by in-crate tests at the real storage boundary and through `process_line`.
- **Known CI coverage gap, if any:** no multi-uid OS-level integration test (roster uids are simulated through the transport credential seam); the reviewer steps above cover it live.
- **Commands run and tail output (local, at `5157f9d4b7`):**

```
$ cargo fmt --all -- --check
(clean)

$ cargo clippy --workspace --all-targets -- -D warnings -A clippy::nonminimal_bool
(clean; the allow covers two auth_provider/oidc.rs lines from #10255 that local
clippy 0.1.96 flags and CI's 1.98 does not — CI was green on that code)

$ cargo test -p zeroclaw-infra acp_session_store
test result: ok. 33 passed (incl. principal_index_is_repaired_when_the_column_exists_without_it)

$ cargo test -p zeroclaw-infra session
test result: ok. 136 passed (owned-delete predicates, idempotent migrations, tri-state owner reads)

$ cargo test -p zeroclaw-runtime rpc::
test result: ok. 445 passed (incl. admitted_operations_refuse_an_incarnation_replaced_during_the_wait,
configure_refuses_an_incarnation_replaced_under_the_lock,
resume_rebinds_only_to_an_incarnation_the_caller_owns,
colliding_session_records_with_different_owners_are_refused_not_read,
administrator_restoration_keeps_the_durable_owner,
delete_destroys_exactly_the_authorized_durable_record,
scoped_creation_fails_closed_when_the_owner_cannot_be_recorded,
scoped_memory_writes_are_refused_while_storage_cannot_isolate_them,
ownership_denials_hold_through_request_dispatch,
scoped_principals_sessions_are_isolated,
approvals_authorize_against_the_bound_session_owner)
```

- **Beyond CI, what did you manually verify?** Pinned by tests: storage stamps land on both stores with the durable principal id; the wrong owner's predicated delete removes nothing; NULL-owner rows are never owned-deletable and stay invisible to scoped principals; read/resume denials are uniform; listings filter; an approval bound to A's session cannot be resolved by B and remains pending; an incarnation replaced during a queue wait or lock wait is refused and survives; colliding records are refused for everyone; an administrator's restoration keeps the durable owner; a scoped creator's unrecordable stamp fails the creation; the memory gate refuses scoped writes and passes owned-session reads. NOT verified: gateway-created (`gw_`-prefixed) session rows under scoped principals — the gateway does not resolve principals yet (#6250), so such rows are NULL-owned legacy by construction. NOT verified: the `zeroclaw-channels` test suite locally at this head (a full disk interrupted that build; the hosted run covers it).
- **If any command was intentionally skipped, why:** the local `zeroclaw-channels` suite, for the reason above; CI runs it.

## Security & Privacy Impact (required)

- New permissions, capabilities, or file system access scope? No — strictly narrowing for scoped principals; unscoped behavior unchanged except the new audit event and the not-found answer for deleting an id that exists nowhere.
- New external network calls? No
- Secrets / tokens / credentials handling changed? No — principal ids are non-secret canonical identifiers.
- PII, real identities, or personal data in diff, tests, fixtures, or docs? No
- Prompt injection or untrusted model-visible text introduced/changed? No
- If any `Yes`, describe the risk and mitigation: N/A

## Compatibility (required)

- Backward compatible? Config, data and wire: yes — columns are additive and nullable, legacy rows keep NULL owners and today's visibility for unscoped connections, and single-operator installs see zero behavior change. Rust source: **no** — `AcpSessionStore::create_session` takes an owner argument, `SessionMetadata` gains `principal_id`, `SessionStore::resume_existing` takes the caller's scope, and the `SessionBackend::set_session_principal` default now returns an error, so out-of-tree implementors and callers of these APIs must adapt. The `zeroclaw-*` crates are not published for external consumption at this version.
- Config / env / CLI surface changed? No
- Rust/MSRV/toolchain floor changed? No
- If backward compatibility is `No` or either surface/floor question is `Yes`: exact upgrade steps for existing users: none for operators; in-tree callers are updated in this PR.

## Rollback (required for medium/high-risk PRs)

- **Fast rollback command/path:** `git revert` of the seven commits. The added columns may remain; older code ignores them. **For a deployment that already has more than one scoped principal, reverting returns to code that ignores the ownership columns, so every principal's sessions become visible to every authenticated connection again.** Before reverting such a deployment, either remove the `[users]` roster (which returns every connection to the shared-operator path the older code assumes) or stop the daemon for the affected accounts until the fix is back; do not revert while scoped principals keep connecting.
- **Feature flags or config toggles:** None — isolation activates only for scoped principals, which only exist once `[users]` is configured.
- **Observable failure symptoms:** a scoped user unable to see their own session (check the stamp: `principal_id` on the row vs the durable roster id), unexpected `-32012` "not found or not owned" denials, an INTERNAL_ERROR naming session records that "disagree about their owner" (a prefixed-id or ACP/chat collision that needs an operator to reconcile), or the cross-principal audit event firing for a session the actor should own.

## Supersede Attribution (required only when `Supersedes #` is used)

- Superseded PRs + authors:
  - #8672 by @singlerider
- Scope materially carried forward: the session-store `principal_id` column design (nullable additive column + idempotent migration + index + tri-state owner reads on both stores), `set_session_principal`, the ACP `create_session` owner parameter, the approval→session binding (`request_id → (session_id, responder)` with `session_for`), and the dispatcher ownership-check structure. Upgraded per RFC 7141 Rev 8 review findings: scoped destructive operations now use single-statement owner-predicated deletes instead of check-then-mutate, fresh session ids are reserved atomically against live-session replacement, ownership is bound to one resolved record and one live incarnation, and scoped memory access is explicitly fail-closed instead of post-filtered.
- `Co-authored-by` trailers added in commit messages for incorporated contributors? Yes — on three of the seven commits, the ones carrying #8672 material.
- If `No`, why: N/A

## Non-goals

- Principal-owned memory storage (#10268: ownership composed into the memory backends' atomic predicates; today's posture is deny-for-scoped, not enforce).
- Gateway session surfaces and channel identity (#6250 and later boundaries).
- Per-sender RBAC and scope hardening beyond this storage boundary (the multi-user tracker's own rollout).

