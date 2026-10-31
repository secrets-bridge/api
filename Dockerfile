# syntax=docker/dockerfile:1.7
#
# Multi-stage build for secrets-bridge api. The runtime image is
# distroless/static so the final container has no shell, no package
# manager, and runs as a non-root UID by default.

FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src

# Cache module downloads across layers.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.buildVersion=${BUILD_VERSION}" \
      -o /out/api \
      ./cmd/api

FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/api /usr/local/bin/api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/api"]
