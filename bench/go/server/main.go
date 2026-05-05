// Go gRPC server implementing helloworld.Greeter, same semantics
// as the Ada server. Used as the head-to-head baseline.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "perf-test/helloworldpb"
)

type server struct {
	pb.UnimplementedGreeterServer
}

// Unary: matches Ada SayHello.
func (s *server) SayHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	return &pb.HelloReply{Message: "Hello, " + req.GetName() + "!"}, nil
}

// Server-streaming: 5 replies "Hello, $name! [n/5]". Mirrors Ada.
func (s *server) LotsOfReplies(req *pb.HelloRequest, stream pb.Greeter_LotsOfRepliesServer) error {
	const total = 5
	for i := 1; i <= total; i++ {
		if err := stream.Send(&pb.HelloReply{
			Message: fmt.Sprintf("Hello, %s! [%d/%d]", req.GetName(), i, total),
		}); err != nil {
			return err
		}
	}
	return nil
}

// Client-streaming: collect names, return one combined "Hello to all: ...".
func (s *server) LotsOfGreetings(stream pb.Greeter_LotsOfGreetingsServer) error {
	names := ""
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.HelloReply{
				Message: "Hello to all: " + names + "!",
			})
		}
		if err != nil {
			return err
		}
		if names != "" {
			names += ", "
		}
		names += req.GetName()
	}
}

// Bidi: each ping → one pong "Hi, $name!".
func (s *server) BidiHello(stream pb.Greeter_BidiHelloServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&pb.HelloReply{
			Message: "Hi, " + req.GetName() + "!",
		}); err != nil {
			return err
		}
	}
}

func main() {
	port := flag.Int("port", 50052, "listen port")
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterGreeterServer(s, &server{})
	log.Printf("go-grpc server listening on :%d", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
