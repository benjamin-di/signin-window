# signin-window roadmap

Keep the package public, provider-neutral and useful with an application's
existing authentication. Prioritize reliable completion and recovery in real
consumers. [Permissions and ownership](PERMISSIONS.md) defines the boundary;
the library is not an account directory, agent authorization service or provider
credential broker.

## Available in 0.4.7

- Human windows and authenticated relay hooks, with private owner/requester/
  target context and exact-origin mutations/viewer access.
- Reload/reconnect presentation, explicit cancellation and bounded application
  lifespans that clean up expired attempts without page polling. Saving may
  finish after the viewer closes; an unavailable process is not resumable.
- Optional standard OIDC browser identity, public-client PKCE, fresh-authentication
  evidence and short-lived opaque server-side sessions. Core human APIs remain
  independent of this extra and of optional automation.
- Kept backends that publish privately and return completion metadata; existing
  remote one-time result transfer remains a separate contract.
- Warm-first session helpers, durable attempt accounting, ordered profile
  leases, origin-bound credential delivery and explicitly configured optional
  credential/planner adapters. Applications retain their state formats, provider
  identity, entitlement, holds, publication and maintenance policy.
- noVNC paste/input and native browser-policy checks using synthetic fixtures.

These are library capabilities, not a claim that any consuming deployment has
been upgraded or accepted. Consumer versions, accounts, runtime paths, grants
and deployment receipts belong to their own repositories.

## Remaining work, in order

1. **Finish consumer adoption.** Each consumer must qualify its installed package
   and actual browser/native adapter, not only a source import. Document its
   account-use versus management policy, credential custodian, group/API grant
   boundaries and supported disconnect/recovery behavior. Coordinate frontend,
   reader and credential-writer upgrades; preserve current state and revocations.
   Prove that reviewed first initialization is distinct from missing adopted
   controls or a replaced state directory. Hosted startup and maintenance must
   fail closed on lost authority; retain working standalone contracts.
2. **Accept recovery at the application boundary.** Exercise reload, cancellation,
   wrong account, viewer closure while saving, publication failure, stale epoch,
   reader/writer isolation and restart. A native profile must be closed and
   independently verified before publication. Application-owned journals must
   preserve accepted generations, accounting and later disconnects. Qualify
   complete-state restore on disposable copies and select a compatible runtime
   rollback; an older credential-readable image may ignore disconnects. When
   current authority is unavailable, remain stopped pending explicit recovery.
   Extract more library code only if multiple consumers prove the same small
   contract; these requirements do not add a generic control database or ledger.
3. **Qualify deployed behavior and publish accurate guidance.** Verify real
   ingress/session isolation and the relevant native provider flow. Separate
   pre-exposure source/runtime qualification from real browser acceptance after
   the configured callback origin is reachable. Complete one consumer's normal
   path before expanding, without alternate callbacks or authorization bypasses.
   Keep human MFA/passkey steps distinct from synthetic acceptance. Publish
   mirrors through their normal reviewed export/release process; documentation
   publication alone needs no compatible consumer runtime upgrade. Never include
   account or deployment facts in reusable docs or fixtures.
4. **Revisit acknowledged remote transfer only for a demonstrated need.** If a
   consumer needs recovery after lost acknowledgement, first specify idempotency,
   expiry, original-consumer binding and compatibility with the one-time result
   endpoint. Kept backends do not require a new transfer protocol. Do not report
   the current authenticated relay as an acknowledged transactional transfer.

Completion requires consumer acceptance, not a new framework or a larger API.
Use existing source gates, synthetic browser harnesses and release tooling;
do not add an observability service or workflow engine for this roadmap.

## Password managers and passkeys

A person's own native browser can use its normal supported password manager and
passkeys. A remote browser does not gain access to the person's local extension
or authenticator. Cross-device passkey proximity requirements are not solved by
displaying a distant server's QR code. Document supported alternatives honestly
and keep password/code paste out of logs and persistent storage.

Existing optional 1Password maintenance adapters remain explicitly configured,
read-only and origin-bound. A failed lookup must not fall back to another
identity. Password/TOTP delivery is not evidence of passkey support. Consider
user-approved autofill only after a real consumer qualifies the supported
integration's approval, denial, timeout and independent verification; it is not
a prerequisite for current adoption.

## Deferred

Custom WebAuthn bridges, passkey export, production virtual authenticators,
unlocked personal-vault extensions, new browser backends, a universal
authentication/status framework and additional login/CAPTCHA automation remain
outside this work. Reconsider them only for a demonstrated consumer problem.
