"""Compose with an existing host session; no identity provider or directory dependency."""

from signin_window.page import PageText
from signin_window.relay import AttemptContext, Relay


def authenticated_relay(backend, public_url, *, session_actor, permitted):
    """The host supplies async verified-session and account-policy functions.

    session_actor(connection) returns a stable opaque actor reference or None.
    permitted(actor, target, operation) checks the host's current authorization.
    Both must bound their I/O and work for HTTP and WebSocket connections.
    Login redirects belong in the host's middleware, before these routes.
    """

    async def authorize(connection, link, operation):
        actor = await session_actor(connection)
        return (
            isinstance(actor, str)
            and actor == link.context.owner
            and await permitted(actor, link.context.target, operation)
        )

    return Relay(backend, public_url, authorize=authorize, text=PageText(reconnect=True, return_url="/connections/"))


def request_sign_in(relay, *, verified_owner, verified_requester, account, revision):
    """Called by the authenticated application, using its account binding and revision.

    Request bodies must never choose these authority-bearing references. The
    application's publication callback verifies the revision before committing.
    """
    return relay.create(
        account,
        label="Your account",
        context=AttemptContext(owner=verified_owner, requester=verified_requester, target=revision),
    )
