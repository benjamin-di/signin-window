# Permissions and ownership

`signin-window` provides human sign-in windows, a relay and optional browser
identity mechanics. It does not grant an agent access to an account, manage a
directory or replace an application's authorization policy.

| Decision | Owner |
| --- | --- |
| Who signed in to the host application? | The application's existing browser session or optional standard OIDC integration |
| May this person view, start, cancel or inspect this attempt? | Application policy supplied through `Relay(authorize=...)` and private `AttemptContext` |
| Which provider account may this person use or manage? | Application-owned account and manager bindings |
| Is this the expected, usable provider session? | The application's independent provider identity and entitlement checks |
| May an agent invoke a tool, and on whose behalf? | The service's API/gateway authorization and backend account permissions |
| May a credential be published or refreshed now? | The application's durable controls, generation checks and native credential custodian |

For example, a service can allow two people to use a shared shopping account
while allowing only its owner to reconnect it. Group membership alone does not
establish account ownership. Provider login, API access and approval for a
purchase remain distinct decisions.

A retained provider ID, email or native authentication record identifies the
provider account according to the application's contract. Binding it to the
human manager is a separate decision at first adoption. An integration without
a stable provider identity must describe its explicit account-selection and
confirmation limits rather than claim an identity proof it cannot perform.

## Browser entry and relay

The core package accepts an existing authentication/session system. The
optional `signin-window[oidc]` extra implements standard issuer/client
configuration, PKCE, callback verification and short-lived server-side browser
sessions; Pocket ID is one possible provider. It introduces no provider
administrator key, fleet directory or required gateway.

An OIDC browser client is separate from a client or workload permitted to call
MCP or another API. `BrowserAuth` discards identity-provider tokens after
verification. Its opaque browser cookie is not an API credential or a vendor
session. A persistent service should have its own API identity and explicit
resource grants rather than borrowing a person's browser session.

The host creates private owner/requester/target context from verified identity
and existing bindings. It authorizes every page, mutation, state, static asset
and viewer stream through the relay hook. Authenticated mutations and viewer
WebSockets require the exact configured Origin. A GET preview does not start
a browser. Host policy must reject an unrecognized owner and a superseded
attempt; caller-supplied headers, account IDs or email addresses are not proof.

The generic capability-link mode remains available to existing integrations.
An account-management application should explicitly protect its host routes
and relay. Once a relay authorization hook is configured, failed authentication
or missing context never falls back to capability access. Cookie names and URL
paths do not isolate different applications; use separate browser origins when
their trust boundaries differ.

## Sessions, credentials and revocation

| Operation | Contract |
| --- | --- |
| Local browser logout | Ends that host browser session; does not revoke API grants or log out the vendor |
| Identity/group/grant change | Enforcement and token lifetime belong to the identity provider, API gateway and host; optional OIDC browser sessions are bounded to 15 minutes |
| Cancel an attempt | Ends the current sign-in according to its lifecycle; does not erase a previously accepted account session |
| Accept a sign-in | Requires application verification of provider identity, entitlement, expected revision and publication outcome |
| Disconnect an account | Application-owned durable barrier; must also stop native readers, credential writers and maintenance after restart |
| Vendor logout or token revocation | Separate operation at the provider; local removal or pause must not claim global provider revocation |

Keep identity-provider tokens, backend API keys, vendor credentials and optional
automation credentials separate. The human-only window and relay modules do
not import automation or acquire secret-store access. Optional automation needs
an explicitly supplied credential/planner capability and application policy;
it never creates API permissions or proves provider entitlement by itself.

Credentials entered into a remote browser are handled on its host. That browser,
its profile and the trusted host/operator are inside the credential boundary.
Keeping credentials out of MCP/model output does not hide them from that host.

## Publication and recovery

The host owns durable connection state. Check its disconnect/epoch barrier in
the actual reader and every credential writer, including refresh and maintenance.
Drain or fence older work before publishing a replacement. Preserve the previous
verified artifact when sign-in is cancelled, fails or reaches the wrong account.
Do not reset attempt budgets, unrelated holds or revocations during installation
or recovery.

An account-management host must distinguish explicit first initialization from
loss of an adopted account's controls or bindings. Missing adopted state or a
replacement control directory must stop account use and publication, rather
than silently create an active account. Disposable browser-session loss does
not reset durable account authority. Initialization evidence and state-layout
checks stay with the application; the library does not infer account ownership
or supply a universal control store.

Runtime rollback retains current controls. Qualify recovery of the complete
application state on disposable copies; an older full-state backup cannot prove
current revocations. If authority cannot be verified, keep access stopped until
explicit recovery. An incompatible older runtime is not a safe fallback merely
because it can read the vendor profile.

A kept backend publishes its own private session and reports completion metadata.
The legacy remote result endpoint retains its one-time transfer contract;
browser authentication does not make it transactional. A reloaded viewer may
reattach to a live attempt, but process restart does not preserve a browser.
The application reconciles its accepted artifact and reports interruption or
uncertainty honestly. Native profile journals and provider snapshot formats stay
with the application rather than becoming a universal library credential store.

See the [public APIs](README.md#authenticated-sign-in-attempts),
[OIDC integration](README.md#optional-browser-identity) and
[remaining work](ROADMAP.md).
