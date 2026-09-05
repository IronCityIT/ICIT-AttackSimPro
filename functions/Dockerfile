# Reproducible local container for the storeScanResults ingest endpoint.
#
# This runs the EXACT production handler (handler.js) against an in-memory
# Firestore double via local-server.js — no GCP credentials, no external
# dependencies, no network egress. It is for local development, smoke testing,
# and demos. Production ingest runs as a Cloud Function (see index.js +
# ../.github/workflows/deploy-functions.yml), NOT from this image.
FROM node:20-alpine

WORKDIR /app

# Only the runtime-relevant sources. local-server.js + handler.js + testkit have
# zero third-party dependencies, so there is nothing to npm install for the
# local server. (firebase-admin/functions are only needed by index.js in prod.)
COPY handler.js local-server.js ./
COPY testkit ./testkit

ENV PORT=8088
EXPOSE 8088

# Liveness probe hits the handler's own /healthz route.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:8088/healthz || exit 1

USER node
CMD ["node", "local-server.js"]
