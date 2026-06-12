# syntax=docker/dockerfile:1

FROM koalaman/shellcheck-alpine:v0.11.0@sha256:9955be09ea7f0dbf7ae942ac1f2094355bb30d96fffba0ec09f5432207544002

ARG REVISION=""
ARG CREATED=""
ARG VERSION=""

LABEL org.opencontainers.image.title="shellscan" \
      org.opencontainers.image.description="Coroboros shellscan — context-aware shellcheck for shell + CI YAML (GitLab CI, GitHub Actions)" \
      org.opencontainers.image.source="https://gitlab.com/coroboros/security/infrastructure/shellscan" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Coroboros <ob@coroboros.com>" \
      org.opencontainers.image.vendor="Coroboros" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

ARG APP_NAME="shellscan"
ARG APP_BIN="/bin/${APP_NAME}"
ARG APP_DIR="/${APP_NAME}"

ENV LANG="C.UTF-8"

WORKDIR ${APP_DIR}

COPY src/shellscan.sh "${APP_BIN}"

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk upgrade --no-cache && \
    chmod +x "${APP_BIN}" && \
    addgroup -g 10001 "${APP_NAME}" && \
    adduser -u 10000 -D -G "${APP_NAME}" -H -S -s /bin/bash "${APP_NAME}" && \
    chown -R 10000:10001 "${APP_DIR}" && \
    apk add --no-cache bash ca-certificates fd jq yq

USER 10000:10001

ENTRYPOINT [ "shellscan" ]
