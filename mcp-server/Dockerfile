# UBI Node.js baseline for OpenShift
FROM registry.access.redhat.com/ubi9/nodejs-20

WORKDIR /opt/app-root/src

# Ensure we can write in the workdir during build even when the image defaults to a non-root user (UID 1001)
USER 0
RUN mkdir -p /opt/app-root/src && chown -R 1001:0 /opt/app-root/src

# Server deps
COPY --chown=1001:0 package*.json ./
USER 1001
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# UI build
USER 0
COPY --chown=1001:0 ui ./ui
RUN chown -R 1001:0 /opt/app-root/src/ui
USER 1001
RUN npm --prefix ui install && npm --prefix ui run build

# Install built UI into ./public for the Node server to serve
USER 0
RUN rm -rf /opt/app-root/src/public && cp -r /opt/app-root/src/ui/dist /opt/app-root/src/public && chown -R 1001:0 /opt/app-root/src/public
USER 1001

# Server sources
COPY --chown=1001:0 server.mjs ./server.mjs
COPY --chown=1001:0 auth.mjs ./auth.mjs
COPY --chown=1001:0 redaction.js ./redaction.js
COPY --chown=1001:0 data ./data

ENV PORT=8081
EXPOSE 8081

CMD ["npm","start"]
