# Agent Bridge relay. Build from the repository root:
#   docker compose --profile relay up -d --build relay
#
# Node runs the TypeScript sources directly (type stripping), so there is no
# build step. Migrations run on start.

FROM node:26-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/relay/package.json packages/relay/
RUN npm ci --omit=dev --no-fund --no-audit

COPY packages/protocol/src packages/protocol/src
COPY packages/relay/src packages/relay/src
COPY packages/relay/migrations packages/relay/migrations

USER node
EXPOSE 8080
CMD ["node", "packages/relay/src/server.ts"]
