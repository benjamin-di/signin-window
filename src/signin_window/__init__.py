"""Sign-in windows a person drives themselves, through noVNC: the login service (``service``), the MCP server's
client for it (``client``), sign-in links (``relay``, ``page``), child-process windows (``child``) and keeping a
window on the site (``hosts``)."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("signin-window")
except PackageNotFoundError:  # a source tree that is not installed
    __version__ = "0+unknown"
