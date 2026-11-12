// Package analysis finds the cheapest attack paths to a target with Dijkstra, ranks the edges that
// most attack paths depend on (choke points), and measures what fixing them achieves.
package analysis

import (
	"container/heap"
	"fmt"
	"sort"

	"github.com/jvch0512/attackpath/internal/graph"
)

// Path is a sequence of edge IDs from the source to the target.
type Path struct {
	From  string `json:"from"`
	Edges []int  `json:"edges"`
	Cost  int    `json:"cost"`
	Steps []Step `json:"steps"`
}

type Step struct {
	Edge int    `json:"edge"`
	Text string `json:"text"`
}

type item struct {
	node string
	dist int
	idx  int
}
type pq []*item

func (p pq) Len() int { return len(p) }
func (p pq) Less(i, j int) bool {
	if p[i].dist != p[j].dist {
		return p[i].dist < p[j].dist
	}
	return p[i].node < p[j].node // deterministic tie-break
}
func (p pq) Swap(i, j int) { p[i], p[j] = p[j], p[i]; p[i].idx = i; p[j].idx = j }
func (p *pq) Push(x any)   { it := x.(*item); it.idx = len(*p); *p = append(*p, it) }
func (p *pq) Pop() any     { o := *p; n := len(o); it := o[n-1]; *p = o[:n-1]; return it }

// Engine holds adjacency so many queries on one graph are cheap.
type Engine struct {
	G       *graph.Graph
	out     map[string][]graph.Edge
	removed map[int]bool
}

func New(g *graph.Graph, removed []int) *Engine {
	e := &Engine{G: g, out: map[string][]graph.Edge{}, removed: map[int]bool{}}
	for _, id := range removed {
		e.removed[id] = true
	}
	for _, ed := range g.Edges {
		if !e.removed[ed.ID] {
			e.out[ed.From] = append(e.out[ed.From], ed)
		}
	}
	for k := range e.out { // stable order regardless of input order
		es := e.out[k]
		sort.Slice(es, func(i, j int) bool { return es[i].ID < es[j].ID })
	}
	return e
}

// PathFrom returns the cheapest path from src to target, or false if the target is unreachable.
func (e *Engine) PathFrom(src, target string) (Path, bool) {
	dist := map[string]int{src: 0}
	prev := map[string]graph.Edge{}
	h := &pq{}
	heap.Push(h, &item{node: src})
	done := map[string]bool{}
	for h.Len() > 0 {
		it := heap.Pop(h).(*item)
		if done[it.node] {
			continue
		}
		done[it.node] = true
		if it.node == target {
			break
		}
		for _, ed := range e.out[it.node] {
			nd := it.dist + graph.Cost[ed.Type]
			if d, ok := dist[ed.To]; !ok || nd < d {
				dist[ed.To] = nd
				prev[ed.To] = ed
				heap.Push(h, &item{node: ed.To, dist: nd})
			}
		}
	}
	d, ok := dist[target]
	if !ok || src == target {
		return Path{}, false
	}
	var edges []int
	for cur := target; cur != src; cur = prev[cur].From {
		edges = append([]int{prev[cur].ID}, edges...)
	}
	return Path{From: src, Edges: edges, Cost: d, Steps: e.narrate(edges)}, true
}

func (e *Engine) narrate(ids []int) []Step {
	var out []Step
	for _, id := range ids {
		ed := e.G.Edges[id]
		out = append(out, Step{Edge: id, Text: Describe(ed, e.G)})
	}
	return out
}

// Describe explains one step in plain English.
func Describe(ed graph.Edge, g *graph.Graph) string {
	f, t := short(g, ed.From), short(g, ed.To)
	switch ed.Type {
	case graph.MemberOf:
		return fmt.Sprintf("%s is a member of %s and inherits its rights", f, t)
	case graph.AdminTo:
		return fmt.Sprintf("%s is local administrator on %s", f, t)
	case graph.HasSession:
		return fmt.Sprintf("%s has an active session on %s, so its credentials can be stolen from memory", t, f)
	case graph.CanRDP:
		return fmt.Sprintf("%s can log on remotely (RDP) to %s", f, t)
	case graph.GenericAll:
		return fmt.Sprintf("%s has full control over %s", f, t)
	case graph.ForceChangePassword:
		return fmt.Sprintf("%s can reset the password of %s without knowing it", f, t)
	case graph.WriteDacl:
		return fmt.Sprintf("%s can rewrite the permissions of %s", f, t)
	case graph.AllowedToDelegate:
		return fmt.Sprintf("%s is trusted for delegation to %s", f, t)
	case graph.DCSync:
		return fmt.Sprintf("%s can replicate directory secrets from %s (DCSync)", f, t)
	}
	return string(ed.Type)
}

func short(g *graph.Graph, id string) string {
	n, ok := g.Node(id)
	if !ok {
		return id
	}
	for i, c := range n.Name {
		if c == '@' || (n.Type == graph.Computer && c == '.') {
			return n.Name[:i]
		}
	}
	return n.Name
}

// Fix is a suggested remediation for an edge.
func Fix(ed graph.Edge, g *graph.Graph) string {
	f, t := short(g, ed.From), short(g, ed.To)
	switch ed.Type {
	case graph.MemberOf:
		return fmt.Sprintf("Remove %s from %s (or split the role)", f, t)
	case graph.AdminTo:
		return fmt.Sprintf("Remove %s from the local administrators of %s; use just-in-time admin access", f, t)
	case graph.HasSession:
		return fmt.Sprintf("Stop %s from logging on to %s: privileged accounts only on privileged hosts", t, f)
	case graph.CanRDP:
		return fmt.Sprintf("Remove the RDP right of %s on %s or require a jump host", f, t)
	case graph.ForceChangePassword:
		return fmt.Sprintf("Remove the password reset delegation of %s over %s", f, t)
	case graph.GenericAll, graph.WriteDacl:
		return fmt.Sprintf("Remove the excessive ACL of %s on %s", f, t)
	case graph.AllowedToDelegate:
		return fmt.Sprintf("Disable delegation from %s to %s", f, t)
	case graph.DCSync:
		return fmt.Sprintf("Restrict replication rights on %s", t)
	}
	return "Review this relationship"
}

type Choke struct {
	Edge    int    `json:"edge"`
	Paths   int    `json:"paths"`  // number of shortest paths that use this edge
	Impact  int    `json:"impact"` // number of users that lose every path if this edge is removed
	Fix     string `json:"fix"`
	Summary string `json:"summary"`
}

type Summary struct {
	Users       int     `json:"users"`
	AtRisk      int     `json:"at_risk"`
	PercentRisk float64 `json:"percent_risk"`
	ShortestLen int     `json:"shortest_hops"`
	AvgCost     float64 `json:"avg_cost"`
}

type Result struct {
	Summary     Summary         `json:"summary"`
	Paths       map[string]Path `json:"paths"` // by source user id, only users with a path
	Chokepoints []Choke         `json:"chokepoints"`
}

// Analyze computes every user's cheapest path to the target and ranks choke points.
func Analyze(g *graph.Graph, target string, removed []int) Result {
	eng := New(g, removed)
	res := Result{Paths: map[string]Path{}, Chokepoints: []Choke{}}
	var cost, shortest int
	shortest = -1
	use := map[int]int{}
	for _, n := range g.Nodes {
		if n.Type != graph.User || n.HighValue {
			continue
		}
		res.Summary.Users++
		if p, ok := eng.PathFrom(n.ID, target); ok {
			res.Paths[n.ID] = p
			cost += p.Cost
			if shortest < 0 || len(p.Edges) < shortest {
				shortest = len(p.Edges)
			}
			for _, id := range p.Edges {
				use[id]++
			}
		}
	}
	res.Summary.AtRisk = len(res.Paths)
	if res.Summary.Users > 0 {
		res.Summary.PercentRisk = float64(res.Summary.AtRisk) * 100 / float64(res.Summary.Users)
	}
	if shortest > 0 {
		res.Summary.ShortestLen = shortest
	}
	if res.Summary.AtRisk > 0 {
		res.Summary.AvgCost = float64(cost) / float64(res.Summary.AtRisk)
	}
	type kv struct{ id, n int }
	var ranked []kv
	for id, n := range use {
		if g.Edges[id].Type != graph.MemberOf { // membership of the target group itself is not actionable noise
			ranked = append(ranked, kv{id, n})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].n != ranked[j].n {
			return ranked[i].n > ranked[j].n
		}
		return ranked[i].id < ranked[j].id
	})
	if len(ranked) > 8 {
		ranked = ranked[:8]
	}
	for _, r := range ranked {
		ed := g.Edges[r.id]
		after := Analyze2(g, target, append(append([]int(nil), removed...), r.id))
		res.Chokepoints = append(res.Chokepoints, Choke{Edge: r.id, Paths: r.n, Impact: res.Summary.AtRisk - after, Fix: Fix(ed, g), Summary: Describe(ed, g)})
	}
	sort.SliceStable(res.Chokepoints, func(i, j int) bool { return res.Chokepoints[i].Impact > res.Chokepoints[j].Impact })
	return res
}

// Analyze2 returns only how many users still have a path (used for what-if impact).
func Analyze2(g *graph.Graph, target string, removed []int) int {
	eng := New(g, removed)
	n := 0
	for _, node := range g.Nodes {
		if node.Type == graph.User && !node.HighValue {
			if _, ok := eng.PathFrom(node.ID, target); ok {
				n++
			}
		}
	}
	return n
}
