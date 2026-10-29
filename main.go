// Command pushhook runs a configured command when a verified GitHub or GitLab
// push webhook is received.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	confPath := flag.String("config", "pushhook.conf", "path to the configuration file")
	flag.Parse()

	// The journal adds its own timestamp to every line.
	if os.Getenv("JOURNAL_STREAM") != "" {
		log.SetFlags(0)
	}

	f, err := os.Open(*confPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := ParseConfig(f)
	f.Close()
	if err != nil {
		log.Fatalf("%s: %v", *confPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	h := NewHandler(cfg)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	log.Printf("listening on %s, %d repos configured", cfg.Listen, len(cfg.Repos))
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		log.Fatal(err)
	case <-ctx.Done():
	}
	stop() // a second signal terminates the process right away

	log.Print("shutting down: waiting for running commands")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	h.Shutdown()
}
