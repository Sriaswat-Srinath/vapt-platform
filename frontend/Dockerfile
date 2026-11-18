# Build the dashboard, then serve the static bundle from nginx. No node runtime
# is present in the served image and the container holds no credentials.
# node:20.18.1-bookworm-slim. glibc, not musl: rollup's native parser hits a
# stack limit on musl and fails to parse react-query.
FROM node@sha256:b2c8e0eb8a6aeeae33b2711f8f516003e27ee45804e270468d937b3214f2f0cc AS build
WORKDIR /app
COPY package.json package-lock.json ./
# ci, not install: the lockfile is committed, so the dependency set is fixed.
RUN npm ci --no-audit --no-fund
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npx tsc --noEmit && npx vite build

# nginx:1.27-alpine
FROM nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/dashboard.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
