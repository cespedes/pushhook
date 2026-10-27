// Command pushhook runs a configured command when a verified GitHub or GitLab
// push webhook is received.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	confPath := flag.String("config", "pushhook.conf", "path to the configuration file")
	flag.Parse()

	f, err := os.Open(*confPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := ParseConfig(f)
	f.Close()
	if err != nil {
		log.Fatalf("%s: %v", *confPath, err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           NewHandler(cfg),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	log.Printf("listening on %s, %d repos configured", cfg.Listen, len(cfg.Repos))
	log.Fatal(srv.ListenAndServe())
}
