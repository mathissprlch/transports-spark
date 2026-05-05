// Go gRPC bench client. Cycles through five workloads against a
// configurable target for a fixed duration; emits per-workload stats
// (count, p50/p95/p99 latency) as JSON for the harness to aggregate.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "perf-test/helloworldpb"
)

type workloadStats struct {
	Name      string  `json:"name"`
	Count     int64   `json:"count"`
	Errors    int64   `json:"errors"`
	P50_us    int64   `json:"p50_us"`
	P95_us    int64   `json:"p95_us"`
	P99_us    int64   `json:"p99_us"`
	Mean_us   int64   `json:"mean_us"`
	Wall_s    float64 `json:"wall_s"`
	Ops_per_s float64 `json:"ops_per_s"`
}

type latencies struct {
	samples []int64 // microseconds
}

func (l *latencies) record(us int64) {
	l.samples = append(l.samples, us)
}

func (l *latencies) summarize(name string, errs int64, wall time.Duration) workloadStats {
	if len(l.samples) == 0 {
		return workloadStats{Name: name, Errors: errs, Wall_s: wall.Seconds()}
	}
	cp := make([]int64, len(l.samples))
	copy(cp, l.samples)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	pct := func(p float64) int64 {
		idx := int(float64(len(cp)-1) * p / 100.0)
		return cp[idx]
	}
	var sum int64
	for _, v := range cp {
		sum += v
	}
	return workloadStats{
		Name:      name,
		Count:     int64(len(cp)),
		Errors:    errs,
		P50_us:    pct(50),
		P95_us:    pct(95),
		P99_us:    pct(99),
		Mean_us:   sum / int64(len(cp)),
		Wall_s:    wall.Seconds(),
		Ops_per_s: float64(len(cp)) / wall.Seconds(),
	}
}

func runUnary(stub pb.GreeterClient, dur time.Duration, nameLen int) workloadStats {
	name := strings.Repeat("a", nameLen)
	lat := &latencies{}
	deadline := time.Now().Add(dur)
	var errs int64
	t0 := time.Now()
	for time.Now().Before(deadline) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := stub.SayHello(ctx, &pb.HelloRequest{Name: name})
		cancel()
		elapsed := time.Since(start).Microseconds()
		if err != nil {
			atomic.AddInt64(&errs, 1)
			continue
		}
		lat.record(elapsed)
	}
	return lat.summarize(fmt.Sprintf("unary_%dB", nameLen), errs, time.Since(t0))
}

func runServerStream(stub pb.GreeterClient, dur time.Duration) workloadStats {
	name := "bench"
	lat := &latencies{}
	deadline := time.Now().Add(dur)
	var errs int64
	t0 := time.Now()
	for time.Now().Before(deadline) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := stub.LotsOfReplies(ctx, &pb.HelloRequest{Name: name})
		_ = cancel
		if err != nil {
			atomic.AddInt64(&errs, 1)
			continue
		}
		count := 0
		for {
			_, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				atomic.AddInt64(&errs, 1)
				break
			}
			count++
		}
		elapsed := time.Since(start).Microseconds()
		if count == 5 {
			lat.record(elapsed)
		}
	}
	return lat.summarize("server_stream_5", errs, time.Since(t0))
}

func runClientStream(stub pb.GreeterClient, dur time.Duration, n int) workloadStats {
	lat := &latencies{}
	deadline := time.Now().Add(dur)
	var errs int64
	t0 := time.Now()
	for time.Now().Before(deadline) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := stub.LotsOfGreetings(ctx)
		_ = cancel
		if err != nil {
			atomic.AddInt64(&errs, 1)
			continue
		}
		var sendErr error
		for i := 0; i < n; i++ {
			if err := stream.Send(&pb.HelloRequest{Name: fmt.Sprintf("c%d", i)}); err != nil {
				sendErr = err
				break
			}
		}
		if sendErr != nil {
			atomic.AddInt64(&errs, 1)
			stream.CloseSend()
			continue
		}
		_, err = stream.CloseAndRecv()
		elapsed := time.Since(start).Microseconds()
		if err != nil {
			atomic.AddInt64(&errs, 1)
			continue
		}
		lat.record(elapsed)
	}
	return lat.summarize(fmt.Sprintf("client_stream_%d", n), errs, time.Since(t0))
}

func runBidi(stub pb.GreeterClient, dur time.Duration, n int) workloadStats {
	lat := &latencies{}
	deadline := time.Now().Add(dur)
	var errs int64
	t0 := time.Now()
	for time.Now().Before(deadline) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := stub.BidiHello(ctx)
		_ = cancel
		if err != nil {
			atomic.AddInt64(&errs, 1)
			continue
		}
		ok := true
		for i := 0; i < n; i++ {
			if err := stream.Send(&pb.HelloRequest{Name: fmt.Sprintf("p%d", i)}); err != nil {
				ok = false
				break
			}
			if _, err := stream.Recv(); err != nil {
				ok = false
				break
			}
		}
		stream.CloseSend()
		// Drain any trailing messages.
		for {
			_, err := stream.Recv()
			if err != nil {
				break
			}
		}
		elapsed := time.Since(start).Microseconds()
		if ok {
			lat.record(elapsed)
		} else {
			atomic.AddInt64(&errs, 1)
		}
	}
	return lat.summarize(fmt.Sprintf("bidi_%d", n), errs, time.Since(t0))
}

type result struct {
	Client      string          `json:"client"`
	Server      string          `json:"server"`
	Workloads   []workloadStats `json:"workloads"`
	Total_count int64           `json:"total_count"`
	Total_wall  float64         `json:"total_wall_s"`
}

func main() {
	target := flag.String("target", "localhost:50051", "server address")
	durStr := flag.String("dur", "60s", "duration per workload")
	tag := flag.String("tag", "", "label for this run (e.g. ada-server, go-server)")
	out := flag.String("out", "", "output JSON path; if empty, print to stdout")
	wlFilter := flag.String("workloads", "", "comma-separated workload subset (default: all)")
	flag.Parse()

	dur, err := time.ParseDuration(*durStr)
	if err != nil {
		log_die("bad duration: %v", err)
	}

	rand.Seed(time.Now().UnixNano())

	conn, err := grpc.Dial(*target,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log_die("dial: %v", err)
	}
	defer conn.Close()
	stub := pb.NewGreeterClient(conn)

	fmt.Fprintf(os.Stderr, "go-client → %s [tag=%s] dur/workload=%s wl=%q\n",
		*target, *tag, dur, *wlFilter)
	t0 := time.Now()
	res := result{Client: "go", Server: *tag}

	want := func(name string) bool {
		if *wlFilter == "" {
			return true
		}
		for _, w := range strings.Split(*wlFilter, ",") {
			if strings.TrimSpace(w) == name {
				return true
			}
		}
		return false
	}

	// Edge-case sweep: tiny payloads, large payloads, streaming patterns.
	if want("unary_4B") {
		res.Workloads = append(res.Workloads, runUnary(stub, dur, 4))
	}
	if want("unary_1024B") {
		res.Workloads = append(res.Workloads, runUnary(stub, dur, 1024))
	}
	if want("unary_8192B") {
		res.Workloads = append(res.Workloads, runUnary(stub, dur, 8192))
	}
	if want("server_stream_5") {
		res.Workloads = append(res.Workloads, runServerStream(stub, dur))
	}
	if want("client_stream_8") {
		res.Workloads = append(res.Workloads, runClientStream(stub, dur, 8))
	}
	if want("bidi_5") {
		res.Workloads = append(res.Workloads, runBidi(stub, dur, 5))
	}

	for _, w := range res.Workloads {
		res.Total_count += w.Count
	}
	res.Total_wall = time.Since(t0).Seconds()

	js, _ := json.MarshalIndent(res, "", "  ")
	if *out == "" {
		fmt.Println(string(js))
	} else {
		os.WriteFile(*out, js, 0644)
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	}
}

func log_die(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "fatal: "+f+"\n", a...)
	os.Exit(1)
}
