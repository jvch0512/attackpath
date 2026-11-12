package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jvch0512/attackpath/internal/analysis"
	"github.com/jvch0512/attackpath/internal/gen"
)

func setup(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer((&Server{Graph: gen.Generate(7), Target: gen.DomainAdmins}).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestGraphAndUI(t *testing.T) {
	ts := setup(t)
	r, _ := http.Get(ts.URL + "/api/graph")
	var body struct {
		Target string
		Graph  struct{ Nodes, Edges []any }
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Target != gen.DomainAdmins || len(body.Graph.Nodes) < 30 || len(body.Graph.Edges) < 40 {
		t.Fatalf("%+v", body.Target)
	}
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		r, err := http.Get(ts.URL + p)
		if err != nil || r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'self'") {
			t.Fatalf("%s: %v %v", p, err, r)
		}
	}
}

func post(ts *httptest.Server, body string) *http.Response {
	r, _ := http.Post(ts.URL+"/api/analyze", "application/json", strings.NewReader(body))
	return r
}

func TestAnalyzeAPI(t *testing.T) {
	ts := setup(t)
	var res analysis.Result
	r := post(ts, `{"removed":[]}`)
	if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&res) != nil || res.Summary.AtRisk == 0 || len(res.Paths) != res.Summary.AtRisk {
		t.Fatalf("%d %+v", r.StatusCode, res.Summary)
	}
	var after analysis.Result
	r = post(ts, `{"removed":[`+itoa(res.Chokepoints[0].Edge)+`]}`)
	json.NewDecoder(r.Body).Decode(&after)
	if after.Summary.AtRisk >= res.Summary.AtRisk {
		t.Fatalf("applying the top fix must reduce risk: %d -> %d", res.Summary.AtRisk, after.Summary.AtRisk)
	}
	if c := post(ts, `{"removed":[99999]}`).StatusCode; c != 400 {
		t.Errorf("unknown edge: %d", c)
	}
	if c := post(ts, `{"removed":[-1]}`).StatusCode; c != 400 {
		t.Errorf("negative edge: %d", c)
	}
	if c := post(ts, `garbage`).StatusCode; c != 400 {
		t.Errorf("garbage: %d", c)
	}
	if r, _ := http.Get(ts.URL + "/api/analyze"); r.StatusCode != 405 {
		t.Errorf("GET must be refused: %d", r.StatusCode)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestFullyRemediatedGraphSerializesEmptyListsNotNull(t *testing.T) {
	ts := setup(t)
	g := gen.Generate(7)
	var removed []int
	for i := 0; i < 20; i++ {
		r := analysis.Analyze(g, gen.DomainAdmins, removed)
		if r.Summary.AtRisk == 0 {
			break
		}
		removed = append(removed, r.Chokepoints[0].Edge)
	}
	b, _ := json.Marshal(map[string]any{"removed": removed})
	resp := post(ts, string(b))
	var raw map[string]json.RawMessage
	json.NewDecoder(resp.Body).Decode(&raw)
	if string(raw["chokepoints"]) != "[]" || string(raw["paths"]) != "{}" {
		t.Fatalf("the UI needs empty collections, got chokepoints=%s paths=%s", raw["chokepoints"], raw["paths"])
	}
}
