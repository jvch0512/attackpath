// Package server serves the attack graph UI and its JSON API.
package server

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"

	"github.com/jvch0512/attackpath/internal/analysis"
	"github.com/jvch0512/attackpath/internal/graph"
)

//go:embed static
var static embed.FS

type Server struct {
	Graph  *graph.Graph
	Target string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/graph", s.graph)
	mux.HandleFunc("/api/analyze", s.analyze)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"graph": s.Graph, "target": s.Target})
}

func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	var req struct {
		Removed []int `json:"removed"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON like {\"removed\":[1,2]}"})
		return
	}
	for _, id := range req.Removed {
		if id < 0 || id >= len(s.Graph.Edges) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown edge id"})
			return
		}
	}
	writeJSON(w, 200, analysis.Analyze(s.Graph, s.Target, req.Removed))
}
