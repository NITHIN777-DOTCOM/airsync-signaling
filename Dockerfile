# syntax=docker/dockerfile:1

# Slim runtime; the server has exactly one runtime dependency (ws), so there is no
# build step and nothing to compile.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# --omit=dev keeps the test-only tooling out of the image.
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Run unprivileged. The node image already ships a `node` user.
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src

USER node

# Railway injects PORT at runtime and routes external traffic to it; this default is
# only a fallback for local `docker run` with no PORT set.
ENV PORT=8080
EXPOSE 8080

# dumb-init isn't needed: node is PID 1 here and src/index.js installs its own
# SIGTERM handler so Railway's graceful redeploy actually closes sockets cleanly.
CMD ["node", "src/index.js"]
