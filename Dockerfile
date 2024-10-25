FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.23.2 as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG GIT_TAG
ARG GIT_COMMIT

ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /go/src/github.com/kutovoys/xray-checker

# Cache the download before continuing
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY .  .

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -a -installsuffix cgo -o /usr/bin/xray-checker .

FROM --platform=${BUILDPLATFORM:-linux/amd64} teddysun/xray:1.8.23

LABEL org.opencontainers.image.source=https://github.com/kutovoys/xray-checker

WORKDIR /app
COPY --from=builder /usr/bin/xray-checker /app/xray-checker
COPY ./templates /app/templates
# USER nonroot:nonroot

CMD ["/app/xray-checker"]