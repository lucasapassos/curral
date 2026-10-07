# syntax=docker/dockerfile:1

# Builder and runtime share the Debian release so glibc/libstdc++ match.
ARG GO_VERSION=1.27
ARG DEBIAN=trixie
ARG DISTROLESS=debian13

FROM golang:${GO_VERSION}-${DEBIAN} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/curral ./cmd/curral

# Extensions are installed at build time with the binary's own DuckDB, so the
# container boots offline and always gets the same extension builds.
ARG EXTENSIONS="httpfs avro iceberg"
RUN /out/curral install-extensions --extension-dir /out/extensions ${EXTENSIONS} \
 && mkdir -p /out/var/lib/curral/tmp /out/var/log/curral

FROM gcr.io/distroless/cc-${DISTROLESS}:nonroot
COPY --from=build /out/curral /usr/local/bin/curral
COPY --from=build --chown=nonroot:nonroot /out/extensions /opt/curral/extensions
COPY --from=build --chown=nonroot:nonroot /out/var/lib/curral /var/lib/curral
COPY --from=build --chown=nonroot:nonroot /out/var/log/curral /var/log/curral
WORKDIR /var/lib/curral
ENV CURRAL_LISTEN=:8080 \
    CURRAL_EXTENSION_DIR=/opt/curral/extensions \
    CURRAL_TEMP_DIR=/var/lib/curral/tmp \
    CURRAL_LOG_FORMAT=json
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s CMD ["/usr/local/bin/curral", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/curral"]
CMD ["serve"]
