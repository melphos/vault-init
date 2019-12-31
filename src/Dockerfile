FROM golang:1.13 AS builder

ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64

WORKDIR /go/src/app
COPY . .

#RUN go get  
RUN go build \
    -a \
    -ldflags "-s -w -extldflags 'static'" \
    -installsuffix cgo \
    -o /bin/vault-init \
    .
FROM ubuntu
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /bin/vault-init /
RUN chmod 0664 /etc/ssl/certs/ca-certificates.crt
CMD ["/vault-init"]
