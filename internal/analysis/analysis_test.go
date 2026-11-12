package analysis

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jvch0512/attackpath/internal/gen"
	"github.com/jvch0512/attackpath/internal/graph"
)

func mk(nodes []string, edges ...[3]string) *graph.Graph {
	g := &graph.Graph{}
	for _, n := range nodes {
		typ := graph.User
		if strings.HasPrefix(n, "G") {
			typ = graph.Group
		}
		if strings.HasPrefix(n, "C") {
			typ = graph.Computer
		}
		g.Nodes = append(g.Nodes, graph.Node{ID: n, Name: n, Type: typ})
	}
	for _, e := range edges {
		g.Edges = append(g.Edges, graph.Edge{From: e[0], To: e[1], Type: graph.EdgeType(e[2])})
	}
	g.Normalize()
	return g
}

func TestDijkstraPrefersCheaperPathOverFewerHops(t *testing.T) {
	// one hop by RDP costs 3, but membership (free) plus GenericAll (1) costs only 1 over two hops.
	g2 := mk([]string{"u", "G1", "T"}, [3]string{"u", "T", "CanRDP"}, [3]string{"u", "G1", "MemberOf"}, [3]string{"G1", "T", "GenericAll"})
	p, _ := New(g2, nil).PathFrom("u", "T")
	if p.Cost != 1 || len(p.Edges) != 2 {
		t.Fatalf("zero-cost membership then GenericAll (cost 1) beats RDP (cost 3): %+v", p)
	}
}

func TestUnreachableCyclesAndSelf(t *testing.T) {
	g := mk([]string{"a", "b", "T"}, [3]string{"a", "b", "MemberOf"}, [3]string{"b", "a", "MemberOf"})
	if _, ok := New(g, nil).PathFrom("a", "T"); ok {
		t.Error("no path expected")
	}
	if _, ok := New(g, nil).PathFrom("a", "a"); ok {
		t.Error("a node is not a path to itself")
	}
}

func TestRemovedEdgesAreIgnored(t *testing.T) {
	g := mk([]string{"u", "T"}, [3]string{"u", "T", "GenericAll"})
	if _, ok := New(g, []int{0}).PathFrom("u", "T"); ok {
		t.Error("removed edge must not be used")
	}
	if _, ok := New(g, nil).PathFrom("u", "T"); !ok {
		t.Error("control")
	}
}

func TestDeterministicTieBreak(t *testing.T) {
	g := mk([]string{"u", "x", "y", "T"},
		[3]string{"u", "y", "GenericAll"}, [3]string{"u", "x", "GenericAll"},
		[3]string{"x", "T", "GenericAll"}, [3]string{"y", "T", "GenericAll"})
	first, _ := New(g, nil).PathFrom("u", "T")
	for i := 0; i < 20; i++ {
		again, _ := New(g, nil).PathFrom("u", "T")
		if !reflect.DeepEqual(first.Edges, again.Edges) {
			t.Fatal("equal-cost paths must resolve the same way every time")
		}
	}
}

func TestStepsAreNarrated(t *testing.T) {
	p, _ := New(gen.Generate(7), nil).PathFrom("IT-HELPDESK@CORP.LOCAL", gen.DomainAdmins)
	var text []string
	for _, s := range p.Steps {
		text = append(text, s.Text)
	}
	all := strings.Join(text, " | ")
	for _, want := range []string{"reset the password", "local administrator", "active session"} {
		if !strings.Contains(all, want) {
			t.Errorf("narration missing %q: %s", want, all)
		}
	}
}

func TestAnalyzeSummaryAndChokepoints(t *testing.T) {
	g := gen.Generate(7)
	r := Analyze(g, gen.DomainAdmins, nil)
	if r.Summary.Users == 0 || r.Summary.AtRisk == 0 || r.Summary.AtRisk > r.Summary.Users {
		t.Fatalf("%+v", r.Summary)
	}
	if r.Summary.PercentRisk <= 0 || r.Summary.PercentRisk > 100 || r.Summary.ShortestLen < 2 {
		t.Fatalf("%+v", r.Summary)
	}
	if len(r.Chokepoints) == 0 || len(r.Chokepoints) > 8 {
		t.Fatalf("chokepoints: %d", len(r.Chokepoints))
	}
	for i := 1; i < len(r.Chokepoints); i++ {
		if r.Chokepoints[i-1].Impact < r.Chokepoints[i].Impact {
			t.Fatal("choke points must be ordered by impact")
		}
	}
	for _, c := range r.Chokepoints {
		if g.Edges[c.Edge].Type == graph.MemberOf {
			t.Error("membership edges are not actionable choke points")
		}
		if c.Impact < 0 || c.Impact > r.Summary.AtRisk || c.Fix == "" {
			t.Fatalf("%+v", c)
		}
	}
}

func TestRemediationDrivesRiskToZero(t *testing.T) {
	g := gen.Generate(7)
	var removed []int
	prev := Analyze(g, gen.DomainAdmins, nil).Summary.AtRisk
	for round := 0; round < 30; round++ {
		r := Analyze(g, gen.DomainAdmins, removed)
		if r.Summary.AtRisk > prev {
			t.Fatalf("removing edges can never add paths: %d > %d", r.Summary.AtRisk, prev)
		}
		prev = r.Summary.AtRisk
		if prev == 0 {
			return
		}
		removed = append(removed, r.Chokepoints[0].Edge)
	}
	t.Fatalf("risk did not reach zero after 30 fixes (%d users still exposed)", prev)
}

func TestFirstFixDoesNotSolveEverything(t *testing.T) {
	g := gen.Generate(7)
	r := Analyze(g, gen.DomainAdmins, nil)
	after := Analyze(g, gen.DomainAdmins, []int{r.Chokepoints[0].Edge})
	if after.Summary.AtRisk == 0 || after.Summary.AtRisk >= r.Summary.AtRisk {
		t.Fatalf("the demo story needs a second route: before %d after %d", r.Summary.AtRisk, after.Summary.AtRisk)
	}
}
