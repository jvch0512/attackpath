package gen

import (
	"reflect"
	"testing"

	"github.com/jvch0512/attackpath/internal/analysis"
)

func TestDeterministicAndValid(t *testing.T) {
	a, b := Generate(7), Generate(7)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same seed must give the same environment")
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a, Generate(8)) {
		t.Fatal("different seeds should differ")
	}
}

func TestPlantedPathsExist(t *testing.T) {
	g := Generate(7)
	eng := analysis.New(g, nil)
	for _, from := range []string{"IT-HELPDESK@CORP.LOCAL", "BACKUP-OPERATORS@CORP.LOCAL", "DEVELOPERS@CORP.LOCAL"} {
		p, ok := eng.PathFrom(from, DomainAdmins)
		if !ok || len(p.Edges) < 3 {
			t.Errorf("%s should reach Domain Admins through a multi-step path: %+v", from, p)
		}
	}
	if _, ok := eng.PathFrom("PRINT-OPERATORS@CORP.LOCAL", DomainAdmins); ok {
		t.Error("PRINT-OPERATORS is a dead-end decoy and must not reach Domain Admins")
	}
	for _, seed := range []int64{1, 2, 3, 99} {
		if err := Generate(seed).Validate(); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
	}
}
