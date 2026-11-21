package server

import (
	"net/http"
	"sort"
	"strings"
)

// Roles and permissions (docs/multiuser-design.md). Permissions are resource:action
// strings; roles are cumulative. Every registered route must appear in routePerms:
// a route with no entry is denied (and TestEveryRouteHasAPermission fails), so a new
// endpoint cannot ship unprotected.

const (
	RoleViewer   = "viewer"
	RoleAnalyst  = "analyst"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// roleLevel orders the roles; a higher level includes every lower level's permissions.
var roleLevel = map[string]int{RoleViewer: 10, RoleAnalyst: 20, RoleOperator: 30, RoleAdmin: 40}

const (
	// Not tied to a role: the route authenticates itself, or any signed-in user may call it.
	permPublic = "public" // /api/auth/* and /api/health: no session required
	permAny    = "any"    // any signed-in user

	// viewer
	permTaskRead    = "task:read"
	permFindingRead = "finding:read"
	permReportRead  = "report:read"
	permUsageRead   = "usage:read"

	// analyst
	permEvidenceRead  = "evidence:read" // raw captured traffic, intercept history, workspace files
	permFindingTriage = "finding:triage"
	permExportRun     = "export:run"
	permChatRead      = "chat:read"
	permWorkspaceRead = "workspace:read"

	// operator
	permTaskWrite       = "task:write"
	permChatUse         = "chat:use"
	permWorkspaceWrite  = "workspace:write"
	permFindingWrite    = "finding:write"
	permInterceptDecide = "intercept:decide"
	permLogsRead        = "logs:read"
	permConfigRead      = "config:read" // non-sensitive configuration lists

	// admin
	permConfigWrite = "config:write"
	permSecretsRead = "secrets:read" // configuration that can carry credentials
	permLLMAdmin    = "llm:admin"
	permSystemAdmin = "system:admin"
	permUserManage  = "user:manage"
	permAuditRead   = "audit:read"
	permTokenManage = "token:manage"
)

// rolePerms lists the permissions each role adds on top of the roles below it.
var rolePerms = map[string][]string{
	RoleViewer:   {permTaskRead, permFindingRead, permReportRead, permUsageRead},
	RoleAnalyst:  {permEvidenceRead, permFindingTriage, permExportRun, permChatRead, permWorkspaceRead},
	RoleOperator: {permTaskWrite, permChatUse, permWorkspaceWrite, permFindingWrite, permInterceptDecide, permLogsRead, permConfigRead},
	RoleAdmin:    {permConfigWrite, permSecretsRead, permLLMAdmin, permSystemAdmin, permUserManage, permAuditRead, permTokenManage},
}

var roleOrder = []string{RoleViewer, RoleAnalyst, RoleOperator, RoleAdmin}

// permissionsFor returns every permission the role holds (cumulative), sorted.
func permissionsFor(role string) []string {
	lvl, ok := roleLevel[role]
	if !ok {
		return nil
	}
	var out []string
	for _, r := range roleOrder {
		if roleLevel[r] <= lvl {
			out = append(out, rolePerms[r]...)
		}
	}
	sort.Strings(out)
	return out
}

// roleHas reports whether role holds perm. permAny is held by every valid role.
func roleHas(role, perm string) bool {
	if _, ok := roleLevel[role]; !ok {
		return false
	}
	if perm == permAny {
		return true
	}
	for _, p := range permissionsFor(role) {
		if p == perm {
			return true
		}
	}
	return false
}

// validRole reports whether r is one of the four roles.
func validRole(r string) bool { _, ok := roleLevel[r]; return ok }

// ---- route registration with recording -------------------------------------

// routeRegistrar is the part of *http.ServeMux that route registration uses.
type routeRegistrar interface {
	HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request))
	Handle(pattern string, h http.Handler)
}

// routeMux wraps a ServeMux and remembers every registered pattern, so the permission
// table can be checked against the real route set and the middleware can look up the
// matched pattern before dispatch.
type routeMux struct {
	*http.ServeMux
	patterns []string
}

func newRouteMux() *routeMux { return &routeMux{ServeMux: http.NewServeMux()} }

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, h)
}

func (m *routeMux) Handle(pattern string, h http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, h)
}

// patternFor returns the registered pattern that serves r ("" when none matches).
func (m *routeMux) patternFor(r *http.Request) string {
	_, p := m.ServeMux.Handler(r)
	return p
}

// ---- route -> permission table ---------------------------------------------

var routePerms = map[string]string{}

func grant(perm string, patterns ...string) {
	for _, p := range patterns {
		if _, dup := routePerms[p]; dup {
			panic("rbac: duplicate route " + p)
		}
		routePerms[p] = perm
	}
}

func init() {
	grant(permPublic, "GET /api/health", "GET /api/auth/status", "POST /api/auth/init", "POST /api/auth/login",
		"POST /api/auth/logout", "GET /api/auth/session", "POST /api/auth/change-password")
	grant(permAny, "GET /api/stats")

	// ---- viewer: read tasks, findings, reports, usage ----
	grant(permTaskRead,
		"GET /api/tasks", "GET /api/tasks/{id}", "GET /api/tasks/{id}/asset-refs", "GET /api/tasks/{id}/constraints",
		"GET /api/tasks/{id}/coverage", "GET /api/tasks/{id}/coverage-graph", "GET /api/tasks/{id}/goals",
		"GET /api/tasks/{id}/intent-assets", "GET /api/tasks/{id}/llm/resolution", "GET /api/tasks/{id}/scope",
		"GET /api/task-categories", "GET /api/task-templates", "GET /api/task-archives", "GET /api/task-archives/{id}",
		"GET /api/assets", "GET /api/assets/counts", "GET /api/companies", "GET /api/companies/{id}",
		"GET /api/exploration/activity", "GET /api/exploration/activity/history", "GET /api/exploration/activity/{seq}",
		"GET /api/exploration/activity/stream", "GET /api/exploration/frontier", "GET /api/exploration/graph",
		"GET /api/exploration/intents", "GET /api/exploration/main-sessions", "GET /api/exploration/nodes",
		"GET /api/exploration/tokens", "GET /api/visibility/{kind}/{id}", "GET /api/visibility/skill/{name}",
		"GET /api/tasks/{id}/chat/status", "GET /api/commands", "GET /api/commands/stats")
	grant(permFindingRead,
		"GET /api/exploration/findings", "GET /api/exploration/findings/asset-tree", "GET /api/exploration/findings/groups",
		"GET /api/exploration/findings/stats", "GET /api/exploration/findings/{id}", "GET /api/exploration/findings/{id}/lineage",
		"GET /api/exploration/findings/{id}/retests", "GET /api/exploration/findings/retests/active")
	grant(permReportRead, "GET /api/report")
	grant(permUsageRead, "GET /api/tokens/conversations", "GET /api/tokens/daily", "GET /api/tokens/usage",
		"GET /api/intercept/judge/usage")

	// ---- analyst: evidence, triage, export, chat history, workspace read ----
	grant(permEvidenceRead,
		"GET /api/traffic", "GET /api/traffic/blob", "GET /api/traffic/exchange", "GET /api/traffic/hosts",
		"GET /api/intercept/history", "GET /api/intercept/history/{id}", "GET /api/intercept/history/{id}/execution",
		"GET /api/intercept/pending", "GET /api/intercept/pending/{id}", "GET /api/intercept/task/{taskID}",
		"GET /api/exploration/findings/{id}/traffic", "GET /api/exploration/findings/{id}/traffic/{binding_id}",
		"GET /api/exploration/findings/{id}/traffic/{binding_id}/body")
	grant(permFindingTriage, "PATCH /api/exploration/findings/{id}")
	grant(permExportRun, "GET /api/exploration/findings/export")
	grant(permChatRead,
		"GET /api/conversations", "GET /api/conversations/{id}/messages", "GET /api/conversations/{id}/messages/{seq}",
		"GET /api/chat/mentions", "GET /api/side-questions/{requestID}/events",
		"GET /api/conversations/{id}/side-questions", "GET /api/tasks/{id}/chat/side-questions",
		"GET /api/tasks/{id}/intents/{iid}/side-questions")
	grant(permWorkspaceRead, "GET /api/workspace/list", "GET /api/workspace/read", "GET /api/workspace/download")

	// ---- operator: run and manage tasks, chat, workspace write ----
	grant(permTaskWrite,
		"POST /api/tasks", "PATCH /api/tasks/{id}", "DELETE /api/tasks/{id}", "POST /api/tasks/archive/batch",
		"POST /api/tasks/category/batch", "POST /api/tasks/control/batch", "POST /api/tasks/{id}/archive",
		"POST /api/tasks/{id}/assets", "DELETE /api/tasks/{id}/assets/{assetID}", "PATCH /api/tasks/{id}/category",
		"POST /api/tasks/{id}/constraints", "DELETE /api/tasks/{id}/constraints/{cid}", "PATCH /api/tasks/{id}/constraints/{cid}",
		"POST /api/tasks/{id}/control", "POST /api/tasks/{id}/goals", "DELETE /api/tasks/{id}/goals/{gid}",
		"PATCH /api/tasks/{id}/goals/{gid}", "POST /api/tasks/{id}/intents/{iid}/control",
		"POST /api/tasks/{id}/intents/{iid}/rerun", "POST /api/tasks/{id}/intents/rerun-blocked",
		"GET /api/tasks/{id}/intercept-rules", "POST /api/tasks/{id}/intercept-rules",
		"DELETE /api/tasks/{id}/intercept-rules/{rid}", "PUT /api/tasks/{id}/intercept-rules/{rid}",
		"POST /api/tasks/{id}/intercept-rules/{rid}/toggle", "PUT /api/tasks/{id}/llm", "POST /api/tasks/{id}/scope",
		"DELETE /api/tasks/{id}/scope/{sid}", "POST /api/task-categories", "PATCH /api/task-categories/{id}",
		"DELETE /api/task-categories/{id}", "POST /api/task-templates", "PATCH /api/task-templates/{id}",
		"DELETE /api/task-templates/{id}", "POST /api/task-archives/delete/batch", "DELETE /api/task-archives/{id}",
		"POST /api/task-archives/{id}/restore", "POST /api/task-archives/restore/batch", "POST /api/assets",
		"DELETE /api/assets", "POST /api/companies", "DELETE /api/companies/{id}", "POST /api/companies/{id}/scope",
		"POST /api/companies/reattribute", "POST /api/exploration/main-session/new", "POST /api/active")
	grant(permChatUse,
		"POST /api/chat", "POST /api/chat/upload", "POST /api/tasks/{id}/chat/stop", "POST /api/tasks/{id}/intents/{iid}/messages",
		"POST /api/conversations", "POST /api/conversations/delete/batch", "DELETE /api/conversations/{id}",
		"PATCH /api/conversations/{id}", "POST /api/conversations/{id}/messages", "PATCH /api/conversations/{id}/profile",
		"POST /api/conversations/{id}/stop", "POST /api/side-questions/{requestID}/cancel",
		"POST /api/conversations/{id}/side-questions", "POST /api/tasks/{id}/chat/side-questions",
		"POST /api/tasks/{id}/intents/{iid}/side-questions", "DELETE /api/conversations/{id}/side-questions",
		"DELETE /api/tasks/{id}/chat/side-questions", "DELETE /api/tasks/{id}/intents/{iid}/side-questions")
	grant(permWorkspaceWrite, "POST /api/workspace/upload", "POST /api/workspace/mkdir", "POST /api/workspace/write",
		"DELETE /api/workspace/delete")
	grant(permFindingWrite, "DELETE /api/exploration/findings/{id}", "POST /api/exploration/findings/{id}/deepen",
		"POST /api/exploration/findings/{id}/retests", "POST /api/exploration/findings/{id}/traffic",
		"PATCH /api/exploration/findings/{id}/traffic/{binding_id}", "PUT /api/exploration/findings/{id}/traffic/order", "DELETE /api/exploration/findings/{id}/traffic/{binding_id}")
	grant(permInterceptDecide, "POST /api/intercept/pending/{id}/decide")
	grant(permLogsRead, "GET /api/logs", "GET /api/logs/history", "GET /api/logs/stream")
	grant(permConfigRead,
		"GET /api/settings", "GET /api/agents", "GET /api/agents/{key}", "GET /api/agents/{key}/prompts",
		"GET /api/agents/{key}/triggers", "GET /api/agents/{key}/variables", "GET /api/agents/{key}/visibility",
		"GET /api/skills", "GET /api/skills/missing", "GET /api/skills/{name}/usage", "GET /api/tools",
		"GET /api/llm", "GET /api/llm/profiles", "GET /api/llm/pool", "GET /api/llm/retry-policy",
		"GET /api/mcp/{id}/tools", "GET /api/intercept/rules", "GET /api/intercept/tool-config", "GET /api/intercept/judge",
		"GET /api/asset-intercept/rules", "GET /api/notify/meta", "GET /api/update/check")

	// ---- admin: configuration, secrets, LLM, system, users, audit ----
	grant(permConfigWrite,
		"PUT /api/settings", "POST /api/settings/python/detect", "POST /api/settings/web-search/test",
		"POST /api/agents", "DELETE /api/agents/{key}", "PATCH /api/agents/{key}", "PUT /api/agents/{key}/config",
		"PUT /api/agents/{key}/prompt", "POST /api/agents/{key}/prompt/preview", "POST /api/agents/{key}/prompt/reset",
		"POST /api/agents/{key}/triggers", "PUT /api/agents/{key}/visibility", "PUT /api/agents/{key}/wrapup",
		"POST /api/agents/{key}/wrapup/reset", "PUT /api/agents/{key}/wrapup/task-timeout",
		"POST /api/agents/{key}/wrapup/task-timeout/reset", "DELETE /api/triggers/{id}", "PATCH /api/triggers/{id}",
		"POST /api/skills", "DELETE /api/skills/{name}", "POST /api/skills/{name}/dirs", "GET /api/skills/{name}/files",
		"DELETE /api/skills/{name}/files/{file...}", "GET /api/skills/{name}/files/{file...}",
		"PUT /api/skills/{name}/files/{file...}", "PUT /api/skills/{name}/meta", "POST /api/skills/upload",
		"POST /api/tools/custom", "DELETE /api/tools/custom/{key}", "PUT /api/tools/custom/{key}", "POST /api/tools/custom/test",
		"PUT /api/tools/{key}", "POST /api/tools/{key}/reset", "POST /api/mcp", "DELETE /api/mcp/{id}",
		"POST /api/mcp/{id}/refresh", "POST /api/visibility/skill/toggle", "POST /api/visibility/toggle",
		"POST /api/asset-intercept/rules", "DELETE /api/asset-intercept/rules/{id}", "PUT /api/asset-intercept/rules/{id}",
		"POST /api/asset-intercept/rules/{id}/toggle", "POST /api/intercept/rules", "DELETE /api/intercept/rules/{id}",
		"PUT /api/intercept/rules/{id}", "POST /api/intercept/rules/{id}/toggle", "PUT /api/intercept/tool-config",
		"PUT /api/intercept/judge", "POST /api/sync/scopesentry/datasource", "POST /api/sync/scopesentry/sync",
		"GET /api/sync/scopesentry/projects", "GET /api/sync/scopesentry/status", "GET /api/sync/scopesentry/tasks",
		"POST /api/notify/channels", "DELETE /api/notify/channels/{id}", "PATCH /api/notify/channels/{id}",
		"POST /api/notify/channels/{id}/test", "POST /api/notify/deliveries/{id}/retry")
	grant(permSecretsRead, "GET /api/mcp", "GET /api/notify/channels", "GET /api/notify/deliveries")
	grant(permLLMAdmin,
		"POST /api/llm", "POST /api/llm/models", "POST /api/llm/pool/reset", "POST /api/llm/profiles",
		"POST /api/llm/profiles/active", "DELETE /api/llm/profiles/{id}", "DELETE /api/llm/records",
		"GET /api/llm/records", "GET /api/llm/records/by-model", "GET /api/llm/records/{id}", "GET /api/llm/records/tasks",
		"POST /api/llm/retry-policy", "POST /api/llm/test")
	grant(permSystemAdmin, "POST /api/update/apply", "POST /api/update/rollback", "GET /api/update/stream", "POST /api/gc",
		"DELETE /api/traffic", "DELETE /api/traffic/all", "DELETE /api/traffic/hosts", "GET /api/audit", "GET /api/audit/verify")
	grant(permUserManage, "GET /api/users", "POST /api/users", "PATCH /api/users/{id}", "POST /api/users/{id}/reset-password")
	grant(permAuditRead, "GET /api/security-log")
	grant(permTokenManage, "GET /api/api-tokens", "POST /api/api-tokens", "DELETE /api/api-tokens/{id}")
}

// routePermission returns the permission a route pattern requires and whether the
// pattern is known. Unknown patterns are denied by the middleware.
func routePermission(pattern string) (string, bool) {
	p, ok := routePerms[pattern]
	return p, ok
}

// isMutatingMethod reports whether the HTTP method changes state (these requests are
// written to the security log).
func isMutatingMethod(m string) bool {
	switch strings.ToUpper(m) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}
