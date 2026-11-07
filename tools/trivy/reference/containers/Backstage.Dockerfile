# This dockerfile builds an image for the backend package.
# It should be executed with the root of the repo as docker context.
#
# Before building this image, be sure to have run the following commands in the repo root:
#
# yarn install --immutable
# yarn tsc
# yarn build:backend
#
# Host build steps (yarn install, yarn build:backend) must use the same
# Node version as the FROM image below. Mismatched versions break native modules.
#
# Once the commands have been run, you can build the image using `yarn build-image`
#
# Alternatively, there is also a multi-stage Dockerfile documented here:
# https://backstage.io/docs/deployment/docker#multi-stage-build

FROM node:24-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66 AS dependencies

# Install sqlite3 dependencies. You can skip this if you don't use sqlite3 in the image,
# in which case you should also move better-sqlite3 to "devDependencies" in package.json.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends python3 make g++ libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

# Node's bundled Yarn shim must use this app's locked Yarn release.
ENV COREPACK_HOME=/opt/corepack
RUN corepack enable && corepack prepare yarn@4.4.1 --activate && \
    mkdir -p /home/node/.cache/yarn && \
    chown -R node:node /opt/corepack /home/node/.cache

# From here on we use the least-privileged `node` user to run the backend.
USER node

# This should create the app dir as `node`.
# If it is instead created as `root` then the `tar` command below will fail: `can't create directory 'packages/': Permission denied`.
# If this occurs, then ensure BuildKit is enabled (`DOCKER_BUILDKIT=1`) so the app dir is correctly created as `node`.
WORKDIR /app

# Copy files needed by Yarn
COPY --chown=node:node .yarn ./.yarn
COPY --chown=node:node .yarnrc.yml ./
COPY --chown=node:node backstage.json ./

# This switches many Node.js dependencies to production mode.
ENV NODE_ENV=production
ENV YARN_ENABLE_IMMUTABLE_INSTALLS=true

# Copy repo skeleton first, to avoid unnecessary docker cache invalidation.
# The skeleton contains the package.json of each package in the monorepo,
# and along with yarn.lock and the root package.json, that's enough to run yarn install.
COPY --chown=node:node yarn.lock package.json packages/backend/dist/skeleton.tar.gz ./
RUN tar xzf skeleton.tar.gz && rm skeleton.tar.gz

RUN --mount=type=cache,target=/home/node/.cache/yarn,sharing=locked,uid=1000,gid=1000 \
    yarn workspaces focus --all --production && yarn cache clean

# Backstage's bundle archive replaces root package metadata and directory modes.
# Extract as root in the disposable build stage, then copy as node into runtime.
USER root
COPY packages/backend/dist/bundle.tar.gz app-config.yaml app-config.production.yaml app-config.azure-managed.yaml app-config.vm.yaml ./
COPY --chown=node:node packages/backend/start-vm.sh ./start-vm.sh
RUN tar xzf bundle.tar.gz && rm bundle.tar.gz

# Native modules are built on the same Linux/Node base as the runtime. Build
# tools and package-manager caches stay in the disposable dependency stage.
FROM node:24-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66 AS runtime
# The backend starts through Node directly. Keep package managers and native
# build tooling in the dependency stage, not in the deployed runtime image.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
        /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/pnpm /usr/local/bin/pnpx
ENV NODE_ENV=production
WORKDIR /app
COPY --from=dependencies --chown=node:node /app/ ./
USER node

EXPOSE 7007
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD node -e "fetch('http://127.0.0.1:7007/.backstage/health/v1/liveness').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "packages/backend", "--config", "app-config.yaml", "--config", "app-config.production.yaml"]
