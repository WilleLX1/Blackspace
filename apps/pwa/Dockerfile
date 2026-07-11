# syntax=docker/dockerfile:1.7
FROM node:22.12-bookworm-slim AS builder
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN npm install --global pnpm@10.2.1
WORKDIR /source
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/pwa/package.json apps/pwa/package.json
RUN pnpm install --frozen-lockfile --filter @blackspace/pwa...
COPY apps/pwa apps/pwa
RUN pnpm --filter @blackspace/pwa build

FROM nginxinc/nginx-unprivileged:1.28-alpine
COPY apps/pwa/nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /source/apps/pwa/dist /usr/share/nginx/html
EXPOSE 8080
