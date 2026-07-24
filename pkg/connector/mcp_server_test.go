package connector

import "testing"

func TestParseMCPServer(t *testing.T) {
	tests := []struct {
		name       string
		cmdline    string
		wantName   string
		wantPkg    string
		wantLaunch string
		wantOK     bool
	}{
		{
			name:       "npx scoped server",
			cmdline:    "npx -y @modelcontextprotocol/server-filesystem /tmp",
			wantName:   "filesystem",
			wantPkg:    "@modelcontextprotocol/server-filesystem",
			wantLaunch: "npx",
			wantOK:     true,
		},
		{
			// An npx-cached path contains "_npx", so npx provenance is reported.
			name:       "node bin from npx cache resolves as npx",
			cmdline:    "node /home/u/.npm/_npx/abc/node_modules/.bin/mcp-server-everything",
			wantName:   "everything",
			wantPkg:    "mcp-server-everything",
			wantLaunch: "npx",
			wantOK:     true,
		},
		{
			name:       "pure node invocation",
			cmdline:    "node /opt/mcp/bin/mcp-server-fetch",
			wantName:   "fetch",
			wantPkg:    "mcp-server-fetch",
			wantLaunch: "node",
			wantOK:     true,
		},
		{
			// A bare .js entrypoint normalizes to the same name/pkg as the package form.
			name:       "js entrypoint normalizes",
			cmdline:    "node /opt/mcp/dist/mcp-server-fetch.js",
			wantName:   "fetch",
			wantPkg:    "mcp-server-fetch",
			wantLaunch: "node",
			wantOK:     true,
		},
		{
			name:       "uvx python server",
			cmdline:    "uvx mcp-server-time",
			wantName:   "time",
			wantPkg:    "mcp-server-time",
			wantLaunch: "uvx",
			wantOK:     true,
		},
		{
			name:       "python module underscore package",
			cmdline:    "python -m mcp_server_git",
			wantName:   "git",
			wantPkg:    "mcp_server_git",
			wantLaunch: "python",
			wantOK:     true,
		},
		{
			name:       "shell wrapper without launcher token still matches",
			cmdline:    "sh -c mcp-server-everything",
			wantName:   "everything",
			wantPkg:    "mcp-server-everything",
			wantLaunch: "unknown",
			wantOK:     true,
		},
		{
			name:    "non-mcp process",
			cmdline: "/usr/bin/bash -c ls -la /tmp",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, pkg, launcher, transport, ok := parseMCPServer(tt.cmdline)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if pkg != tt.wantPkg {
				t.Errorf("pkg = %q, want %q", pkg, tt.wantPkg)
			}
			if launcher != tt.wantLaunch {
				t.Errorf("launcher = %q, want %q", launcher, tt.wantLaunch)
			}
			if transport != "stdio" {
				t.Errorf("transport = %q, want stdio", transport)
			}
		})
	}
}

func TestParseMCPServerSSETransport(t *testing.T) {
	_, _, _, transport, ok := parseMCPServer("node server.js mcp-server-fetch --sse --port 8080")
	if !ok {
		t.Fatal("expected match")
	}
	if transport != "sse/http" {
		t.Errorf("transport = %q, want sse/http", transport)
	}
}

func TestResolveIdentityAmbiguous(t *testing.T) {
	index := map[string]*resolvedIdentity{
		"ambig":  nil, // ambiguous: two identities shared this samAccountName
		"asmith": {email: "asmith@example.com", externalID: "ext-1", displayName: "A. Smith"},
	}
	if got := resolveIdentity(index, "ambig"); got != nil {
		t.Errorf("ambiguous key resolved to %v, want nil", got)
	}
	if got := resolveIdentity(index, "unknown"); got != nil {
		t.Errorf("unknown key resolved to %v, want nil", got)
	}
	got := resolveIdentity(index, "ASmith") // case-insensitive
	if got == nil || got.externalID != "ext-1" {
		t.Errorf("expected A. Smith (ext-1), got %v", got)
	}
}
