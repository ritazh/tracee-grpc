//go:generate protoc -I ../tracee --go_out=plugins=grpc:../tracee ../tracee/tracee.proto

// Package main implements a simple gRPC server that implements
// the tracee service whose definition can be found in tracee/tracee.proto.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"

	pb "github.com/ritazh/tracee-grpc/tracee"
)

var (
	tls      = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile = flag.String("cert_file", "", "The TLS cert file")
	keyFile  = flag.String("key_file", "", "The TLS key file")
	port     = flag.Int("port", 10000, "The server port")
)

type traceeServer struct {
	pb.UnimplementedTraceeServer
}

// RecordTrace accepts a stream of traces of newly created containers or processes
//
// It gets a stream of traces, and responds with a result.
func (s *traceeServer) RecordTrace(stream pb.Tracee_RecordTraceServer) error {
	for {
		traces, err := stream.Recv()
		if traces != nil || err == io.EOF {
			message := "ack"
			s := traces.GetEvent()
			if i, err := strconv.Atoi(s); err == nil {
				if i > 0 {
					message = s
				}
			}
			return stream.SendAndClose(&pb.Result{
				Message: message,
			})
		}
		if err != nil {
			return err
		}
	}
}

func newServer() *traceeServer {
	s := &traceeServer{}
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = testdata.Path("server1.pem")
		}
		if *keyFile == "" {
			*keyFile = testdata.Path("server1.key")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterTraceeServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
