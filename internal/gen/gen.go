// Package gen builds a fictional corp.local Active Directory with a planted, realistic attack path
// plus decoys and random noise. Same seed, same environment.
package gen

import (
	"fmt"
	"math/rand"

	"github.com/jvch0512/attackpath/internal/graph"
)

const DomainAdmins = "DOMAIN ADMINS@CORP.LOCAL"

type b struct {
	g     graph.Graph
	known map[string]bool
}

func (x *b) node(id string, t graph.NodeType, hv bool) {
	if x.known[id] {
		return
	}
	x.known[id] = true
	x.g.Nodes = append(x.g.Nodes, graph.Node{ID: id, Name: id, Type: t, HighValue: hv})
}

func (x *b) edge(from, to string, t graph.EdgeType) {
	for _, e := range x.g.Edges {
		if e.From == from && e.To == to && e.Type == t {
			return
		}
	}
	x.g.Edges = append(x.g.Edges, graph.Edge{From: from, To: to, Type: t})
}

func Generate(seed int64) *graph.Graph {
	r := rand.New(rand.NewSource(seed))
	x := &b{known: map[string]bool{}}
	groups := []string{"IT-HELPDESK@CORP.LOCAL", "SERVER-ADMINS@CORP.LOCAL", "DEVELOPERS@CORP.LOCAL", "HR@CORP.LOCAL", "FINANCE@CORP.LOCAL", "BACKUP-OPERATORS@CORP.LOCAL"}
	x.node("CORP.LOCAL", graph.Domain, true)
	x.node(DomainAdmins, graph.Group, true)
	for _, gname := range groups {
		x.node(gname, graph.Group, false)
	}
	first := []string{"ana", "bruno", "carla", "diego", "elena", "felipe", "gina", "hugo", "iris", "joao", "karla", "luis", "marta", "nuno", "olga", "pedro", "rita", "sergio", "tania", "ugo"}
	var users []string
	for i, f := range first {
		u := fmt.Sprintf("%s.%02d@CORP.LOCAL", f, i+1)
		x.node(u, graph.User, false)
		users = append(users, u)
		x.edge(u, groups[r.Intn(len(groups))], graph.MemberOf)
	}
	var ws, srv []string
	for i := 1; i <= 8; i++ {
		c := fmt.Sprintf("WS-%03d.CORP.LOCAL", 10+i)
		x.node(c, graph.Computer, false)
		ws = append(ws, c)
	}
	for _, s := range []string{"SRV-FILE01", "SRV-SQL01", "SRV-WEB01", "SRV-BACKUP01"} {
		c := s + ".CORP.LOCAL"
		x.node(c, graph.Computer, false)
		srv = append(srv, c)
	}
	x.node("DC01.CORP.LOCAL", graph.Computer, true)
	x.edge("DC01.CORP.LOCAL", "CORP.LOCAL", graph.DCSync)

	// Privileged accounts.
	x.node("adm.silva@CORP.LOCAL", graph.User, true)
	x.edge("adm.silva@CORP.LOCAL", DomainAdmins, graph.MemberOf)
	x.node("svc-sql@CORP.LOCAL", graph.User, false)
	x.node("svc-backup@CORP.LOCAL", graph.User, false)
	x.edge("DOMAIN ADMINS@CORP.LOCAL", "CORP.LOCAL", graph.GenericAll)

	// Planted path 1 (classic): a helpdesk member can reset a service account that is local admin on a server
	// where a Domain Admin has a session.
	x.edge("IT-HELPDESK@CORP.LOCAL", "svc-sql@CORP.LOCAL", graph.ForceChangePassword)
	x.edge("svc-sql@CORP.LOCAL", "SRV-SQL01.CORP.LOCAL", graph.AdminTo)
	x.edge("SRV-SQL01.CORP.LOCAL", "adm.silva@CORP.LOCAL", graph.HasSession)

	// Planted path 2: backup operators administer the backup server, where svc-backup has a session; svc-backup administers the DC.
	x.edge("BACKUP-OPERATORS@CORP.LOCAL", "SRV-BACKUP01.CORP.LOCAL", graph.AdminTo)
	x.edge("SRV-BACKUP01.CORP.LOCAL", "svc-backup@CORP.LOCAL", graph.HasSession)
	x.edge("svc-backup@CORP.LOCAL", "DC01.CORP.LOCAL", graph.AdminTo)
	x.edge("DC01.CORP.LOCAL", "adm.silva@CORP.LOCAL", graph.HasSession) // a Domain Admin logs on to the DC: a second route to the same crown jewel

	// Planted path 3 (long): developers can RDP into a web server where the file server admin group has a session.
	x.edge("DEVELOPERS@CORP.LOCAL", "SRV-WEB01.CORP.LOCAL", graph.CanRDP)
	x.edge("SRV-WEB01.CORP.LOCAL", "SERVER-ADMINS@CORP.LOCAL", graph.HasSession)
	x.edge("SERVER-ADMINS@CORP.LOCAL", "SRV-SQL01.CORP.LOCAL", graph.AdminTo)

	// Decoys and noise: workstation sessions and RDP rights that lead nowhere privileged.
	for _, u := range users {
		x.edge(ws[r.Intn(len(ws))], u, graph.HasSession)
		if r.Intn(3) == 0 {
			x.edge(u, ws[r.Intn(len(ws))], graph.CanRDP)
		}
	}
	x.edge("HR@CORP.LOCAL", ws[0], graph.AdminTo)
	x.edge("FINANCE@CORP.LOCAL", srv[0], graph.CanRDP)
	x.edge("SRV-FILE01.CORP.LOCAL", users[0], graph.HasSession)

	// A true dead end: administers a print server where nobody privileged ever logs on.
	x.node("PRINT-OPERATORS@CORP.LOCAL", graph.Group, false)
	x.node("PRN-01.CORP.LOCAL", graph.Computer, false)
	x.edge("PRINT-OPERATORS@CORP.LOCAL", "PRN-01.CORP.LOCAL", graph.AdminTo)

	x.g.Normalize()
	return &x.g
}
