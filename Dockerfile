# syntax=docker/dockerfile:1.7
#
# Multi-stage build for secrets-bridge api. The runtime image is
# distroless/static so the final container has no shell, no package
# manager, and runs as a non-root UID by default.

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
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

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/api /usr/local/bin/api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/api"]
