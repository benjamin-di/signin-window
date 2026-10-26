"""Local stand-in for Amazon. Contains no accounts, credentials or external requests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from amazonorders.constants import Constants


class SyntheticConstants(Constants):
    def __init__(self, config):
        super().__init__(config)
        self.BASE_URL = config.synthetic_origin
        self.SIGN_IN_URL = self.BASE_URL + "/signin"
        self.SIGN_IN_QUERY_PARAMS = {}
        self.ORDER_HISTORY_URL = self.BASE_URL + "/orders"
        self.COOKIES_SET_WHEN_AUTHENTICATED = ["sid"]
        self.REQUEST_COOKIES = {}
        self.BASE_HEADERS = {}


class Provider:
    def __init__(self):
        self.reject = False
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                owner.requests.append(self.path.split("?")[0])
                if self.path.startswith("/signin"):
                    body = (
                        b'<html><form method="post" action="/complete">'
                        b"<button autofocus>Complete synthetic sign-in</button></form></html>"
                    )
                    self.send_response(200)
                elif owner.reject:
                    body = b"Verification unavailable"
                    self.send_response(503)
                elif "sid=synthetic-accepted" not in self.headers.get("Cookie", ""):
                    self.send_response(302)
                    self.send_header("Location", "/signin")
                    self.end_headers()
                    return
                else:
                    self.send_response(200)
                    body = b"<html><h1>Synthetic orders</h1></html>"
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                self.send_response(303)
                self.send_header("Set-Cookie", "sid=synthetic-accepted; Path=/; HttpOnly; SameSite=Lax")
                self.send_header("Location", "/orders")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def configure(self, config):
        # Public class configuration survives deepcopy and other site's config creation.
        config.update_config("synthetic_origin", self.origin, save=False)
        config.update_config("constants_class", "synthetic.SyntheticConstants", save=False)
