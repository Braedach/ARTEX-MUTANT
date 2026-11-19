package server

import "strings"

// normEndpoint canonicalises an LLM base URL for comparison: trimmed, lower-cased,
// without trailing slashes or the provider-appended API suffixes the config
// tolerates, so "https://x/v1/" and "https://x/v1" compare equal.
func normEndpoint(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	for _, suf := range []string{"/chat/completions", "/responses", "/v1/messages"} {
		u = strings.TrimSuffix(u, suf)
	}
	return strings.TrimRight(u, "/")
}

// sameLLMEndpoint reports whether a request's base URL and proxy equal the stored
// ones. ARTEX-MUTANT hardening: the connection-test and model-list endpoints may
// fall back to a STORED API key (the browser never sees it), but only against the
// address and proxy it was saved with. Otherwise anyone holding a session could
// point the request at a server they control and have the stored key sent there
// ("change the address, keep the credentials"). Identified in the same class as a
// critical fix in BaaRai/ARTEX; implemented fresh here.
func sameLLMEndpoint(reqBase, reqProxy, storedBase, storedProxy string) bool {
	return normEndpoint(reqBase) == normEndpoint(storedBase) &&
		strings.TrimSpace(reqProxy) == strings.TrimSpace(storedProxy)
}

const errStoredKeyOtherEndpoint = "the stored API key is only used for the address and proxy it was saved with; enter the API key to test a different address"
