package mcphttp

import (
	"bufio"
	"strings"
	"testing"
)

func endpointOf(t *testing.T, base, data string) (string, error) {
	t.Helper()
	return readSSEEndpoint(bufio.NewReader(strings.NewReader("event: endpoint\ndata: "+data+"\n\n")), base)
}

func TestSSEEndpointSameOriginAccepted(t *testing.T) {
	for _, data := range []string{"/message?sessionId=1", "https://mcp.example/message?s=1", "message?s=1"} {
		got, err := endpointOf(t, "https://mcp.example/sse", data)
		if err != nil {
			t.Fatalf("%q rejected: %v", data, err)
		}
		if !strings.HasPrefix(got, "https://mcp.example/") {
			t.Fatalf("%q resolved to %q", data, got)
		}
	}
}

func TestSSEEndpointOtherOriginRefused(t *testing.T) {
	for _, data := range []string{
		"https://attacker.example/message",
		"http://mcp.example/message", // scheme downgrade
		"https://mcp.example:8443/message",
		"https://mcp.example.evil.example/message",
		"//attacker.example/message",
	} {
		if got, err := endpointOf(t, "https://mcp.example/sse", data); err == nil {
			t.Fatalf("%q accepted as %q", data, got)
		}
	}
}
