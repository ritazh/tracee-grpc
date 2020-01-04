# Build the binary
FROM golang:1.13.3 as builder

# Copy in the go src
WORKDIR /go/src/github.com/ritazh/tracee-grpc
COPY target/    target/
COPY server/    server/
COPY tracee/    tracee/
COPY go.mod .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o output/server server/server.go

# package the binary
FROM gcr.io/distroless/static:nonroot 
WORKDIR /
COPY --from=builder /go/src/github.com/ritazh/tracee-grpc/output/server .
USER nonroot:nonroot

ENTRYPOINT ["/server"]