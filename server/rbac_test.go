package server

import (
	"sort"
	"strings"
	"testing"
)

// The permission table must cover exactly the routes the server registers: a route
// without an entry is denied at run time, and a stale entry hides a removed route.
// testOnlyRoutes are registered by the auth test rig, not by the real server.
var testOnlyRoutes = map[string]string{"GET /api/ping": permAny, "POST /api/ping": permAny}

func init() {
	for p, perm := range testOnlyRoutes {
		routePerms[p] = perm
	}
}

func TestEveryRouteHasAPermission(t *testing.T) {
	s := &Server{}
	s.Handler()
	if s.routes == nil || len(s.routes.patterns) < 200 {
		t.Fatalf("expected the real route set, got %d patterns", len(s.routes.patterns))
	}
	registered := map[string]bool{}
	for _, p := range s.routes.patterns {
		registered[p] = true
		if _, ok := routePerms[p]; !ok {
			t.Errorf("route %q has no permission entry (add it to routePerms in rbac.go)", p)
		}
	}
	var stale []string
	for p := range routePerms {
		if _, isTest := testOnlyRoutes[p]; !registered[p] && !isTest {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("permission entries for routes that are not registered: %v", stale)
	}
}

func routesWithPerm(perm string) []string {
	var out []string
	for p, v := range routePerms {
		if v == perm {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Invariants of the role design, checked over every real route.
func TestRoleInvariants(t *testing.T) {
	allowed := func(role string) map[string]bool {
		m := map[string]bool{}
		for p, perm := range routePerms {
			if perm != permPublic && roleHas(role, perm) {
				m[p] = true
			}
		}
		return m
	}
	viewer, analyst, operator, admin := allowed(RoleViewer), allowed(RoleAnalyst), allowed(RoleOperator), allowed(RoleAdmin)

	// Cumulative: every role holds everything the role below it holds.
	for p := range viewer {
		if !analyst[p] {
			t.Errorf("analyst lost viewer route %s", p)
		}
	}
	for p := range analyst {
		if !operator[p] {
			t.Errorf("operator lost analyst route %s", p)
		}
	}
	for p := range operator {
		if !admin[p] {
			t.Errorf("admin lost operator route %s", p)
		}
	}
	// Viewers never change anything.
	for p := range viewer {
		method := strings.SplitN(p, " ", 2)[0]
		if isMutatingMethod(method) && routePerms[p] != permAny {
			t.Errorf("viewer may call the state-changing route %s", p)
		}
	}
	// Analysts may only triage findings among state-changing routes.
	for p := range analyst {
		method := strings.SplitN(p, " ", 2)[0]
		if isMutatingMethod(method) && routePerms[p] != permAny && routePerms[p] != permFindingTriage {
			t.Errorf("analyst may call the state-changing route %s (%s)", p, routePerms[p])
		}
	}
	// Operators never reach configuration, secrets, LLM keys, system or users.
	for _, perm := range []string{permConfigWrite, permSecretsRead, permLLMAdmin, permSystemAdmin, permUserManage, permAuditRead, permTokenManage} {
		for _, p := range routesWithPerm(perm) {
			if operator[p] {
				t.Errorf("operator reaches the admin route %s", p)
			}
			if !admin[p] {
				t.Errorf("admin cannot reach %s", p)
			}
		}
	}
	// Raw evidence stays away from viewers.
	for _, p := range routesWithPerm(permEvidenceRead) {
		if viewer[p] {
			t.Errorf("viewer can read raw evidence via %s", p)
		}
	}
	// Anything that can run an agent or a command needs operator or higher.
	for _, p := range []string{"POST /api/chat", "POST /api/tasks", "POST /api/tasks/{id}/control", "POST /api/exploration/findings/{id}/deepen"} {
		if analyst[p] || !operator[p] {
			t.Errorf("%s must be operator-and-up only", p)
		}
	}
	if _, ok := routePermission("POST /api/not/registered"); ok {
		t.Error("unknown routes must report unknown so the middleware denies them")
	}
	if roleHas("root", permAny) || roleHas("", permTaskRead) {
		t.Error("an unknown role holds nothing")
	}
}

func TestPermissionsForIsCumulativeAndSorted(t *testing.T) {
	prev := 0
	for _, r := range roleOrder {
		n := len(permissionsFor(r))
		if n <= prev {
			t.Errorf("role %s should hold more permissions than the one below (%d <= %d)", r, n, prev)
		}
		prev = n
		ps := permissionsFor(r)
		if !sort.StringsAreSorted(ps) {
			t.Errorf("permissions for %s not sorted", r)
		}
	}
}
