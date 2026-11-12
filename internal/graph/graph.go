// Package graph defines an Active Directory style attack graph: principals and the primitives that let one
// principal take control of another (group membership, local admin, sessions, ACL abuse, delegation).
package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type NodeType string

const (
	User     NodeType = "user"
	Computer NodeType = "computer"
	Group    NodeType = "group"
	Domain   NodeType = "domain"
)

type EdgeType string

const (
	MemberOf            EdgeType = "MemberOf"
	AdminTo             EdgeType = "AdminTo"
	HasSession          EdgeType = "HasSession"
	CanRDP              EdgeType = "CanRDP"
	GenericAll          EdgeType = "GenericAll"
	ForceChangePassword EdgeType = "ForceChangePassword"
	WriteDacl           EdgeType = "WriteDacl"
	AllowedToDelegate   EdgeType = "AllowedToDelegate"
	DCSync              EdgeType = "DCSync"
)

// Cost is how hard an attacker finds the step: lower is easier. MemberOf is free because membership is inherited.
var Cost = map[EdgeType]int{MemberOf: 0, HasSession: 1, GenericAll: 1, ForceChangePassword: 1, DCSync: 1, AdminTo: 2, WriteDacl: 2, CanRDP: 3, AllowedToDelegate: 3}

type Node struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Type NodeType `json:"type"`
	// HighValue marks crown-jewel targets such as Domain Admins.
	HighValue bool `json:"high_value,omitempty"`
}

type Edge struct {
	ID   int      `json:"id"`
	From string   `json:"from"`
	To   string   `json:"to"`
	Type EdgeType `json:"type"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Validate checks structure and returns every problem found at once.
func (g *Graph) Validate() error {
	var problems []string
	ids := map[string]bool{}
	for i, n := range g.Nodes {
		switch {
		case n.ID == "":
			problems = append(problems, fmt.Sprintf("node[%d]: id is required", i))
		case ids[n.ID]:
			problems = append(problems, fmt.Sprintf("node %q: duplicate id", n.ID))
		}
		ids[n.ID] = true
		if n.Type != User && n.Type != Computer && n.Type != Group && n.Type != Domain {
			problems = append(problems, fmt.Sprintf("node %q: unknown type %q", n.ID, n.Type))
		}
	}
	for i, e := range g.Edges {
		if _, ok := Cost[e.Type]; !ok {
			problems = append(problems, fmt.Sprintf("edge[%d]: unknown type %q", i, e.Type))
		}
		if !ids[e.From] || !ids[e.To] {
			problems = append(problems, fmt.Sprintf("edge[%d]: endpoint not found (%s -> %s)", i, e.From, e.To))
		}
		if e.From == e.To {
			problems = append(problems, fmt.Sprintf("edge[%d]: self loop on %s", i, e.From))
		}
	}
	if len(g.Nodes) == 0 {
		problems = append(problems, "graph has no nodes")
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("invalid graph:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// Normalize assigns sequential edge IDs so removals can refer to them stably.
func (g *Graph) Normalize() {
	for i := range g.Edges {
		g.Edges[i].ID = i
	}
}

// Load reads and validates a graph from JSON.
func Load(r io.Reader) (*Graph, error) {
	var g Graph
	dec := json.NewDecoder(io.LimitReader(r, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("invalid graph JSON: %w", err)
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	g.Normalize()
	return &g, nil
}

func (g *Graph) Node(id string) (Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}
