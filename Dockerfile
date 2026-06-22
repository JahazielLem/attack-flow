# syntax=docker/dockerfile:1

ARG NODE_VERSION=20
ARG NGINX_VERSION=1.27-alpine
ARG APP_VERSION=v3.2.1-sparta

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS builder

COPY src/attack_flow_builder /attack_flow_builder
WORKDIR /attack_flow_builder
RUN npm ci
RUN npm run build

FROM nginx:${NGINX_VERSION}
ARG APP_VERSION
LABEL org.opencontainers.image.title="Attack Flow SPARTA Builder" \
      org.opencontainers.image.description="Attack Flow Builder fork with SPARTA support and custom SPARTA/RF workflow features." \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/JahazielLem/attack-flow" \
      org.opencontainers.image.url="https://jahaziellem.github.io/attack-flow/"
COPY --from=builder /attack_flow_builder/dist /usr/share/nginx/html
