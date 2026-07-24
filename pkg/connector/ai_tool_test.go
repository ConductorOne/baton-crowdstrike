package connector

import (
	"context"
	"testing"
	"time"

	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func TestClassifyHarness(t *testing.T) {
	tests := []struct {
		name     string
		cmdline  string
		wantTool string // "" means expect no match
	}{
		// Claude Code (must win over Claude Desktop when the package name is present).
		{"claude code npm package", `node C:\Users\a\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`, "Claude Code"},
		{"claude code shim", "claude-code --print hello", "Claude Code"},
		// Claude Desktop (Electron app).
		{"claude desktop exe", `C:\Users\a\AppData\Local\AnthropicClaude\app-0.1\Claude.exe --type=renderer`, "Claude Desktop"},
		{"claude desktop path only", `/Applications/Claude.app/Contents/MacOS/claude.exe`, "Claude Desktop"},
		// IDEs.
		{"cursor exe", `C:\Users\a\AppData\Local\Programs\cursor\Cursor.exe`, "Cursor"},
		{"cursor agent cli", "cursor-agent --resume", "Cursor"},
		{"windsurf exe", `C:\Program Files\Windsurf\Windsurf.exe`, "Windsurf"},
		{"windsurf word", "/usr/local/bin/windsurf", "Windsurf"},
		// CLI harnesses.
		{"codex npm scope", `node /home/u/.npm/_npx/x/node_modules/@openai/codex/bin.js`, "Codex CLI"},
		{"codex cli suffix", "openai-codex-cli run", "Codex CLI"},
		{"gemini cli scope", "npx @google/gemini-cli chat", "Gemini CLI"},
		{"github copilot cli", "npx @github/copilot suggest", "GitHub Copilot CLI"},
		{"opencode", "/usr/local/bin/opencode", "opencode"},
		{"aider python", "python -m aider --model gpt-4o", "Aider"},

		// Negatives — guard the bare-word / broad patterns against false positives.
		{"shadow mcp server is not a harness", "npx -y @modelcontextprotocol/server-filesystem /tmp", ""},
		{"bare codex word does not match", "run the codex please", ""},
		{"bare gemini word does not match", "gemini horoscope generator", ""},
		{"bare copilot word does not match", "microsoft copilot app", ""},
		{"plain node app", "node /srv/app/index.js", ""},
		{"db cursor usage", "psql -c 'DECLARE cur CURSOR FOR SELECT 1'", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyHarness(tt.cmdline)
			if tt.wantTool == "" {
				if got != nil {
					t.Fatalf("classifyHarness(%q) = %q, want no match", tt.cmdline, got.name)
				}
				if matchesHarness(tt.cmdline) {
					t.Fatalf("matchesHarness(%q) = true, want false", tt.cmdline)
				}
				return
			}
			if got == nil {
				t.Fatalf("classifyHarness(%q) = nil, want %q", tt.cmdline, tt.wantTool)
			}
			if got.name != tt.wantTool {
				t.Fatalf("classifyHarness(%q) = %q, want %q", tt.cmdline, got.name, tt.wantTool)
			}
			if !matchesHarness(tt.cmdline) {
				t.Fatalf("matchesHarness(%q) = false, want true", tt.cmdline)
			}
		})
	}
}

func TestBuildAIToolInstances(t *testing.T) {
	early := time.Date(2026, 1, 2, 8, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	dets := []mcpDetection{
		// Two spellings of the same tool for the same (host, user) collapse to one, keep
		// the earliest timestamp and the shortest command line.
		{AID: "aid1", UserName: "Alice", CommandLine: "node .../@anthropic-ai/claude-code/cli.js --long-flags", Timestamp: late},
		{AID: "aid1", UserName: "alice", CommandLine: "claude-code", Timestamp: early},
		// Same tool, different host → distinct instance.
		{AID: "aid2", UserName: "alice", CommandLine: "claude-code", Timestamp: late},
		// Different tool, same host/user → distinct instance.
		{AID: "aid1", UserName: "alice", CommandLine: `C:\cursor\Cursor.exe`, Timestamp: late},
		// Non-harness rows are ignored.
		{AID: "aid1", UserName: "alice", CommandLine: "npx @modelcontextprotocol/server-git", Timestamp: late},
		// Unattributable rows are skipped.
		{AID: "", UserName: "bob", CommandLine: "claude-code", Timestamp: late},
	}
	got := buildAIToolInstances(dets)
	if len(got) != 3 {
		t.Fatalf("got %d instances, want 3: %+v", len(got), keysOf(got))
	}

	// The aid1/alice/Claude Code instance should have collapsed both spellings.
	var cc *aiToolInstance
	for _, inst := range got {
		if inst.det.AID == "aid1" && inst.entry.name == "Claude Code" {
			cc = inst
		}
	}
	if cc == nil {
		t.Fatal("missing aid1 Claude Code instance")
	}
	if cc.count != 2 {
		t.Errorf("count = %d, want 2", cc.count)
	}
	if !cc.det.Timestamp.Equal(early) {
		t.Errorf("timestamp = %v, want earliest %v", cc.det.Timestamp, early)
	}
	if cc.bestCmdline != "claude-code" {
		t.Errorf("bestCmdline = %q, want shortest %q", cc.bestCmdline, "claude-code")
	}
	if len(cc.objectID()) == 0 || cc.objectID()[:3] != "ai-" {
		t.Errorf("objectID = %q, want ai- prefix", cc.objectID())
	}
}

// A disabled ai_tool syncer must emit nothing and must not touch its source (so a nil
// source is safe) — this is the opt-in, no-API-call guarantee.
func TestAIToolDisabledEmitsNothing(t *testing.T) {
	rt := aiToolBuilder(nil, false)
	res, _, err := rt.List(context.Background(), nil, rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("disabled List returned %d resources, want 0", len(res))
	}
}

func keysOf(m map[string]*aiToolInstance) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
