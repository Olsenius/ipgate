# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ipgate ./cmd/ipgate \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ipgate /usr/local/bin/ipgate
# Pre-create /data owned by nonroot so a fresh named volume is writable.
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot
EXPOSE 8080
VOLUME ["/data"]
# HEALTHCHECK needs a shell in the image; use the subcommand from compose instead:
#   healthcheck: { test: ["CMD", "/usr/local/bin/ipgate", "healthcheck"] }
ENTRYPOINT ["/usr/local/bin/ipgate"]
