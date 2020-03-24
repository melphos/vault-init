FROM golang:1.13-alpine AS builder

ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64

ARG VAULT_VERSION=1.3.2

WORKDIR /go/src/app
COPY . .

RUN apk add --no-cache unzip
RUN go get  
RUN go build \
    -a \
    -ldflags "-s -w -extldflags 'static'" \
    -installsuffix cgo \
    -tags netgo \
    -o /bin/vault-init \
    .
RUN ls -l /bin
RUN wget https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip && \
    unzip -d /bin vault_${VAULT_VERSION}_linux_amd64.zip

FROM ubuntu

ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /bin/vault-init /
COPY --from=builder /bin/vault /usr/local/bin/vault
COPY src/bootstrap-sidecar.sh /usr/local/bin/bootstrap

RUN chmod 0664 /etc/ssl/certs/ca-certificates.crt && \ 
    chmod +x /usr/local/bin/bootstrap && \
    chown 1000:1000 /usr/local/bin/bootstrap

CMD ["/vault-init"]
