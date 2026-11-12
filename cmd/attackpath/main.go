package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jvch0512/attackpath/internal/analysis"
	"github.com/jvch0512/attackpath/internal/gen"
	"github.com/jvch0512/attackpath/internal/graph"
	"github.com/jvch0512/attackpath/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "listen address")
	seed := flag.Int64("seed", 7, "seed for the generated demo environment")
	file := flag.String("graph", "", "load a graph from this JSON file instead of generating one")
	target := flag.String("target", gen.DomainAdmins, "id of the node to reach")
	report := flag.Bool("report", false, "print the analysis to the terminal and exit")
	flag.Parse()

	g := gen.Generate(*seed)
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}
		g, err = graph.Load(f)
		f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
	if _, ok := g.Node(*target); !ok {
		log.Fatalf("target %q not found in the graph", *target)
	}
	if *report {
		r := analysis.Analyze(g, *target, nil)
		fmt.Printf("%d of %d users (%.0f%%) can reach %s\n\nTop choke points:\n", r.Summary.AtRisk, r.Summary.Users, r.Summary.PercentRisk, *target)
		for i, c := range r.Chokepoints {
			fmt.Printf("%d. %s\n   fix: %s (cuts %d users off)\n", i+1, c.Summary, c.Fix, c.Impact)
		}
		return
	}
	srv := &http.Server{Addr: *addr, Handler: (&server.Server{Graph: g, Target: *target}).Handler(), ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("AttackPath on http://%s\n", *addr)
	log.Fatal(srv.ListenAndServe())
}
