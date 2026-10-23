# syntax=docker/dockerfile:1.7
# The login service of examples/minimal: a virtual display (Xvfb), a remote-desktop server on loopback (x11vnc),
# noVNC's viewer files and Playwright's Chromium. Build from the repository root:
#   docker build -f examples/minimal/Dockerfile -t signin-example-login .
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/home/login \
    NOVNC_DIR=/opt/novnc

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl dumb-init fonts-noto-cjk x11vnc xvfb \
 && rm -rf /var/lib/apt/lists/*

# noVNC's own viewer (static files only; the WebSocket bridge is the service's, behind each window's view token).
# The paste add-on needs noVNC 1.5 or later (vnc.html with app/ui.js).
ARG NOVNC_VERSION=1.6.0
ARG NOVNC_SHA256=5066103959ef4e9b10f37e5a148627360dd8414e4cf8a7db92bdbd022e728aaa
RUN curl --fail --silent --show-error --location \
      "https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.tar.gz" -o /tmp/novnc.tar.gz \
 && printf '%s  /tmp/novnc.tar.gz\n' "${NOVNC_SHA256}" | sha256sum --check --status \
 && mkdir -p /opt/novnc \
 && tar -xzf /tmp/novnc.tar.gz -C /opt/novnc --strip-components=1 \
      "noVNC-${NOVNC_VERSION}/app" "noVNC-${NOVNC_VERSION}/core" "noVNC-${NOVNC_VERSION}/vendor" \
      "noVNC-${NOVNC_VERSION}/vnc.html" \
 && rm /tmp/novnc.tar.gz

# The managed Chromium policy (signin_window.browser.POLICY): no offers to save passwords, no local files, downloads
# or Chromium's own pages in a sign-in window.
RUN pip install --no-cache-dir signin-window uvicorn playwright \
 && playwright install --with-deps chromium \
 && python -m signin_window.browser install-policy \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --home-dir /home/login --shell /usr/sbin/nologin login \
 && install -d -o 1000 -g 1000 -m 0700 /home/login

COPY examples/minimal/login_service.py /app/login_service.py
USER 1000
EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
CMD ["python", "/app/login_service.py"]
