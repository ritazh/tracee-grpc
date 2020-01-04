//go:generate protoc -I ../tracee --go_out=plugins=grpc:../tracee ../tracee/tracee.proto

// Package main implements a simple gRPC server that implements
// the tracee service whose definition can be found in tracee/tracee.proto.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"strconv"

	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"


	opa "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/ritazh/tracee-grpc/target"
	pb "github.com/ritazh/tracee-grpc/tracee"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8schema "k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	tls      = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile = flag.String("cert_file", "", "The TLS cert file")
	keyFile  = flag.String("key_file", "", "The TLS key file")
	port     = flag.Int("port", 10000, "The server port")
)

var (
	// basic deny template
	denyTemplateRego = `package Foo
	violation[{"msg": "DENIED when event is 0", "details": {}}] {
		input.review.Event == 0
	}`
	// traceEvent deny template
	traceEventTemplateRego = `package Foo
	violation[{"msg": "DENIED when event triggering /bin/ls", "details": {}}] {
		input.review.Object.arguments.p0 == "/bin/ls"
	}
	violation[{"msg": "DENIED when event triggering /bin/sh", "details": {}}] {
		input.review.Object.arguments.p0 == "/bin/sh"
	}`
	// test trace event
	traceEventLS = `{"status": [0], "uid": 0, "uts_name": "353f7a78ead1", "process_name": "sh", "pid": 8, "mnt_ns": 4026532549, "raw": "", "api": "execve", "return_value": 0, "arguments": {"p0": "/bin/ls", "p1": "[]"}, "time": 13658.341002, "tid": 8, "ppid": 1, "type": ["apicall"], "pid_ns": 4026532552}`
	traceEventSH = `{"status": [0], "uid": 0, "uts_name": "353f7a78ead1", "process_name": "runc:[2:INIT]", "pid": 1, "mnt_ns": 4026532549, "raw": "", "api": "execve", "return_value": 0, "arguments": {"p0": "/bin/sh", "p1": "[]"}, "time": 13637.534257, "tid": 1, "ppid": 107132, "type": ["apicall"], "pid_ns": 4026532552}`
)

type traceeServer struct {
	pb.UnimplementedTraceeServer
	client *opa.Client
	ctx context.Context
}

// RecordTrace accepts a stream of traces of newly created containers or processes
//
// It gets a stream of traces, and responds with a result.
func (s *traceeServer) RecordTrace(stream pb.Tracee_RecordTraceServer) error {
	for {
		traces, err := stream.Recv()
		if traces != nil || err == io.EOF {
			message := "ack"
			event := traces.GetEvent()
			if i, err := strconv.Atoi(event); err == nil {
				msg, err := s.reviewEvent(i)
				if err == nil && msg != nil {
					message = *msg
				} else {
					log.Println("failed to review event: ", err)
					return err
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

func (s *traceeServer) reviewEvent (event int) (*string, error) {
	var msgs []string
	result := "allow"
	type targetData struct {
		Name          string
		Event         int
		Object        interface{}
	}
	testTraceEvent := traceEventLS
	if event == 0 {
		testTraceEvent = traceEventSH
	}
	var eventObject interface{}
	err := json.Unmarshal([]byte(testTraceEvent), &eventObject)
	if err != nil {
		return nil, err
	}
	log.Println(eventObject)
	resp, err := s.client.Review(s.ctx, targetData{Name: "testInput", Object: eventObject}, opa.Tracing(true))
	
	if err != nil {
		return nil, err
	}
	res := resp.Results()
	//log.Println(resp.TraceDump())
	//log.Println(res)
	// dump, err := s.client.Dump(s.ctx)
	// if err != nil {
	// 	log.Println("dump error: ", err)
	// } else {
	// 	log.Println(dump)
	// }
	if len(res) > 0 {
		for _, r := range res {
			msgs = append(msgs, fmt.Sprintf("[denied by %s] %s", r.Constraint.GetName(), r.Msg))
			//log.Println("r: ", r)
		}
		result = strings.Join(msgs, "\n")
	}
	return &result, nil
}

func newConstraintTemplate(name, rego string, libs ...string) *templates.ConstraintTemplate {
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: strings.ToLower(name)},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{
				Spec: templates.CRDSpec{
					Names: templates.Names{
						Kind: name,
					},
					Validation: &templates.Validation{
						OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
							Properties: map[string]apiextensions.JSONSchemaProps{
								"expected": {Type: "string"},
							},
						},
					},
				},
			},
			Targets: []templates.Target{
				{Target: "syscall.k8s.gatekeeper.sh", Rego: rego, Libs: libs},
			},
		},
	}
}

func newConstraint(kind, name string, params map[string]string, enforcementAction *string) *unstructured.Unstructured {
	c := &unstructured.Unstructured{}
	c.SetGroupVersionKind(k8schema.GroupVersionKind{
		Group:   "constraints.gatekeeper.sh",
		Version: "v1beta1",
		Kind:    kind,
	})
	c.SetName(name)
	if err := unstructured.SetNestedStringMap(c.Object, params, "spec", "parameters"); err != nil {
		log.Fatalf("failed to create constraint: %v", err)
	}
	return c
}

func newServer() *traceeServer {
	s := &traceeServer{}
	return s
}

func main() {
	log.Println("staring server...")
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
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
	s := newServer()

	// initialize OPA
	driver := local.New(local.Tracing(false))
	backend, err := opa.NewBackend(opa.Driver(driver))
	if err != nil {
		log.Println("unable to set up OPA backend ", err)
		os.Exit(1)
	}
	s.client, err = backend.NewClient(opa.Targets(&target.SyscallValidationTarget{}))
	if err != nil {
		log.Println("unable to set up OPA client ", err)
	}
	s.ctx = context.Background()


	// initialize templates and constraints

	//_, err = s.client.AddTemplate(s.ctx, newConstraintTemplate("Foo", denyTemplateRego))
	_, err = s.client.AddTemplate(s.ctx, newConstraintTemplate("Foo", traceEventTemplateRego))
	if err != nil {
		log.Fatalf("Failed to add template %v", err)
	}
	cstr := newConstraint("Foo", "bar", nil, nil)
	if _, err := s.client.AddConstraint(s.ctx, cstr); err != nil {
		log.Fatalf("Failed to add constraint %v", err)
	}

	// initialize grpc server
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterTraceeServer(grpcServer, s)
	grpcServer.Serve(lis)
}
