package graph

import (
	"strings"
	"testing"
)

func TestValidateReportsEveryProblem(t *testing.T) {
	g := &Graph{
		Nodes: []Node{{ID: "a", Type: User}, {ID: "a", Type: User}, {ID: "", Type: User}, {ID: "c", Type: "robot"}},
		Edges: []Edge{{From: "a", To: "zzz", Type: MemberOf}, {From: "a", To: "a", Type: MemberOf}, {From: "a", To: "c", Type: "Teleport"}},
	}
	err := g.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"duplicate id", "id is required", `unknown type "robot"`, "endpoint not found", "self loop", `unknown type "Teleport"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	if (&Graph{}).Validate() == nil {
		t.Error("an empty graph is invalid")
	}
}

func TestLoadRejectsUnknownFieldsAndNormalizes(t *testing.T) {
	if _, err := Load(strings.NewReader(`{"nodes":[],"edges":[],"extra":1}`)); err == nil {
		t.Error("unknown fields must be rejected")
	}
	if _, err := Load(strings.NewReader(`nope`)); err == nil {
		t.Error("bad JSON")
	}
	g, err := Load(strings.NewReader(`{"nodes":[{"id":"u","name":"u","type":"user"},{"id":"g","name":"g","type":"group"}],"edges":[{"from":"u","to":"g","type":"MemberOf"},{"from":"g","to":"u","type":"GenericAll"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if g.Edges[0].ID != 0 || g.Edges[1].ID != 1 {
		t.Fatalf("edge ids must be sequential: %+v", g.Edges)
	}
	if n, ok := g.Node("g"); !ok || n.Type != Group {
		t.Fatal("Node lookup")
	}
}
