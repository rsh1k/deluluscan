# Deluluscan security dashboard — static single-file report served by nginx.
#
# The dashboard is ONE self-contained HTML file (deluluscan/assets/dashboard_bundle.html
# with the scan payload injected). This image just serves it; all access control is
# done at the ALB via Google OIDC (see k8s/ingress.yaml) — there is no app here.
#
# Build context expects a generated `dashboard.html` alongside this Dockerfile:
#   python3 -m deluluscan.dashboard deluluscan-out/results.json deploy/dashboard/dashboard.html
# Generate it WITHOUT --password: SSO is the boundary once this is behind the ALB.
FROM nginx:1.27-alpine

# non-root hardening
RUN addgroup -S web && adduser -S -G web web

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY dashboard.html /usr/share/nginx/html/index.html

# nginx worker can run unprivileged on :3000 (matches the ALB target port)
RUN chown -R web:web /usr/share/nginx/html /var/cache/nginx /var/run \
    && sed -i 's/user  nginx;//' /etc/nginx/nginx.conf
USER web
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=2s CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
