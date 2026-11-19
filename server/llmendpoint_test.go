package server

import "testing"

func TestSameLLMEndpoint(t *testing.T) {
	same := [][4]string{
		{"https://api.x.com/v1", "", "https://api.x.com/v1/", ""},
		{"HTTPS://API.X.COM/v1/chat/completions", "", "https://api.x.com/v1", ""},
		{"", "", "", ""},
		{"https://a/b", " http://p:1 ", "https://a/b", "http://p:1"},
	}
	for _, c := range same {
		if !sameLLMEndpoint(c[0], c[1], c[2], c[3]) {
			t.Fatalf("expected same: %v", c)
		}
	}
	diff := [][4]string{
		{"https://attacker.example", "", "https://api.x.com/v1", ""},
		{"https://api.x.com/v1", "http://attacker:8080", "https://api.x.com/v1", ""},
		{"", "", "https://api.x.com/v1", ""},
		{"https://api.x.com/v1", "", "", ""},
		{"https://api.x.com.evil.example/v1", "", "https://api.x.com/v1", ""},
	}
	for _, c := range diff {
		if sameLLMEndpoint(c[0], c[1], c[2], c[3]) {
			t.Fatalf("expected different: %v", c)
		}
	}
}
