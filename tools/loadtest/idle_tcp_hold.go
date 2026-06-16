package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19000", "target TCP address")
	connections := flag.Int("connections", 10000, "connections to hold")
	ramp := flag.Int("ramp", 200, "new connections per second")
	readLoop := flag.Bool("read", false, "read until each connection closes")
	flag.Parse()

	if *connections <= 0 {
		log.Fatal("connections must be positive")
	}
	if *ramp <= 0 {
		log.Fatal("ramp must be positive")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var opened atomic.Int64
	var failed atomic.Int64
	var closed atomic.Int64
	var wg sync.WaitGroup
	conns := make([]net.Conn, 0, *connections)
	ticker := time.NewTicker(time.Second / time.Duration(*ramp))
	defer ticker.Stop()

	startedAt := time.Now()
	for i := 0; i < *connections; i++ {
		select {
		case <-ctx.Done():
			i = *connections
			continue
		case <-ticker.C:
		}

		conn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
		if err != nil {
			failed.Add(1)
			if failed.Load()%100 == 1 {
				log.Printf("dial failed: %v", err)
			}
			continue
		}
		opened.Add(1)
		conns = append(conns, conn)
		if *readLoop {
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer closed.Add(1)
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
		if opened.Load()%1000 == 0 {
			log.Printf("opened=%d failed=%d elapsed=%s", opened.Load(), failed.Load(), time.Since(startedAt).Round(time.Second))
		}
	}

	fmt.Printf("holding opened=%d failed=%d addr=%s\n", opened.Load(), failed.Load(), *addr)
	<-ctx.Done()
	for _, conn := range conns {
		_ = conn.Close()
	}
	wg.Wait()
	fmt.Printf("closed readLoops=%d\n", closed.Load())
}
