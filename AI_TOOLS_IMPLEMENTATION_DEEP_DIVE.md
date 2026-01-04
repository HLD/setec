# Deep Dive: AI Coding Tool Integration Implementation

This document provides detailed implementation analysis for enhancing setec to manage authentication credentials for AI coding tools.

---

## 1. Environment Variable Injection

### Current State Analysis

The existing CLI (`cmd/setec/setec.go`) only supports direct secret operations (get, put, list, etc.). There's no mechanism to inject secrets into subprocess environments.

**Key integration points:**
- `client/setec/client.go:146-151` - `Client.Get()` fetches secrets
- `client/setec/store.go:311-321` - `Store.Secret()` provides cached access

### Implementation Approach

#### Option A: Exec Wrapper (Recommended - Low Complexity)

```go
// cmd/setec/env.go

var execArgs struct {
    Secrets  []string `flag:"secret,Map secrets to env vars (format: secret-name:ENV_VAR)"`
    Profile  string   `flag:"profile,Use a named secret profile"`
    Timeout  int      `flag:"timeout,default=30,Timeout in seconds for fetching secrets"`
}

func runExec(env *command.Env, args []string) error {
    if len(args) == 0 {
        return errors.New("command required")
    }

    ctx, cancel := context.WithTimeout(env.Context(), time.Duration(execArgs.Timeout)*time.Second)
    defer cancel()

    client, err := newClient()
    if err != nil {
        return err
    }

    // Build environment with injected secrets
    environ := os.Environ()
    for _, mapping := range execArgs.Secrets {
        parts := strings.SplitN(mapping, ":", 2)
        if len(parts) != 2 {
            return fmt.Errorf("invalid mapping %q (expected secret:ENV_VAR)", mapping)
        }
        secretName, envVar := parts[0], parts[1]

        secret, err := client.Get(ctx, secretName)
        if err != nil {
            return fmt.Errorf("fetching secret %q: %w", secretName, err)
        }
        environ = append(environ, fmt.Sprintf("%s=%s", envVar, string(secret.Value)))
    }

    // Find the executable
    binary, err := exec.LookPath(args[0])
    if err != nil {
        return fmt.Errorf("finding command %q: %w", args[0], err)
    }

    // Replace current process with the target command
    return syscall.Exec(binary, args, environ)
}
```

**Usage:**
```bash
setec exec --secret ai/anthropic/key:ANTHROPIC_API_KEY -- claude
setec exec --secret ai/openai/key:OPENAI_API_KEY --secret gh/token:GITHUB_TOKEN -- cursor
```

#### Option B: Shell Integration (Higher Complexity)

Provide shell functions that can be sourced:

```bash
# ~/.setec.sh
setec-env() {
    eval "$(setec env-export "$@")"
}

# Usage
setec-env ai/anthropic/key:ANTHROPIC_API_KEY
claude  # Now has ANTHROPIC_API_KEY
```

**Trade-offs:**

| Approach | Pros | Cons |
|----------|------|------|
| Exec Wrapper | Clean process isolation, no shell eval | Replaces process, can't use in existing shell |
| Shell Integration | Works in current shell | Security risk (eval), shell-specific |

### Security Implications

1. **Process Isolation**: The exec approach ensures secrets only exist in the child process environment, not the parent shell history
2. **Memory Exposure**: Secrets briefly in memory during fetch; consider `mlock()` for high-security scenarios
3. **Audit Trail**: Each fetch generates an audit entry - AI tool launches are tracked

---

## 2. Secret Profiles/Bundles

### Design Considerations

Profiles need to solve:
1. **Atomicity**: Fetch multiple secrets in one operation
2. **Naming**: Map internal secret names to expected environment variables
3. **Versioning**: Handle profile schema changes
4. **Storage**: Where do profiles live?

### Storage Options

#### Option A: Profiles as Secrets (Metadata Pattern)

Store profile definitions as regular secrets with a naming convention:

```json
// Secret name: _profiles/claude-code
{
    "version": 1,
    "description": "Claude Code development credentials",
    "mappings": {
        "ANTHROPIC_API_KEY": "ai/anthropic/api-key",
        "GITHUB_TOKEN": "dev/github/pat",
        "OPENAI_API_KEY": "ai/openai/key"
    },
    "restrictions": {
        "allowed_hosts": ["*.company.ts.net"],
        "max_ttl_seconds": 28800
    }
}
```

**Pros**: No schema changes, uses existing ACL system
**Cons**: Two-phase fetch (profile then secrets), profile updates create versions

#### Option B: First-Class Profile API

Add new API endpoints:

```go
// types/api/profiles.go

type Profile struct {
    Name        string            `json:"name"`
    Description string            `json:"description,omitempty"`
    Mappings    map[string]string `json:"mappings"` // ENV_VAR -> secret_name
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

type ProfileGetRequest struct {
    Name string `json:"name"`
}

type ProfileGetResponse struct {
    Profile Profile               `json:"profile"`
    Secrets map[string][]byte     `json:"secrets"` // ENV_VAR -> value
}

// New endpoints:
// POST /api/profiles/create
// POST /api/profiles/get     - Returns profile + all secret values
// POST /api/profiles/update
// POST /api/profiles/delete
// POST /api/profiles/list
```

**Pros**: Atomic fetch, cleaner API, can add profile-specific ACLs
**Cons**: Schema changes, new ACL action needed

### Recommended: Hybrid Approach

Use Option A (profiles as secrets) initially for faster implementation, then migrate to Option B for better UX:

```go
// Phase 1: Profile helper in client library
func (c *Client) GetProfile(ctx context.Context, name string) (*ProfileBundle, error) {
    // 1. Fetch profile definition from _profiles/{name}
    profileDef, err := c.Get(ctx, "_profiles/"+name)
    if err != nil {
        return nil, fmt.Errorf("fetching profile: %w", err)
    }

    var profile ProfileDefinition
    if err := json.Unmarshal(profileDef.Value, &profile); err != nil {
        return nil, fmt.Errorf("parsing profile: %w", err)
    }

    // 2. Fetch all referenced secrets concurrently
    bundle := &ProfileBundle{
        Name:    name,
        Secrets: make(map[string][]byte),
    }

    var g errgroup.Group
    var mu sync.Mutex

    for envVar, secretName := range profile.Mappings {
        envVar, secretName := envVar, secretName
        g.Go(func() error {
            secret, err := c.Get(ctx, secretName)
            if err != nil {
                return fmt.Errorf("fetching %s: %w", secretName, err)
            }
            mu.Lock()
            bundle.Secrets[envVar] = secret.Value
            mu.Unlock()
            return nil
        })
    }

    if err := g.Wait(); err != nil {
        return nil, err
    }

    return bundle, nil
}
```

---

## 3. MCP Server for Claude Code

### MCP Protocol Overview

The Model Context Protocol (MCP) enables Claude Code to interact with external tools. An MCP server exposes:
- **Tools**: Functions Claude can call
- **Resources**: Data Claude can read
- **Prompts**: Pre-defined prompts

### Implementation Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Claude Code                       │
│                                                      │
│  "Get the API key from setec and make a request"    │
└──────────────────────┬──────────────────────────────┘
                       │ MCP Protocol (stdio/SSE)
                       ▼
┌─────────────────────────────────────────────────────┐
│              setec MCP Server                        │
│                                                      │
│  Tools:                                              │
│    - get_secret(name) -> value                       │
│    - get_profile(name) -> {env_var: value, ...}     │
│    - list_secrets() -> [names...]                    │
│    - secret_info(name) -> {versions, active}        │
│                                                      │
│  Resources:                                          │
│    - setec://secrets/{name}                          │
│    - setec://profiles/{name}                         │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS (Tailscale)
                       ▼
┌─────────────────────────────────────────────────────┐
│                 setec Server                         │
└─────────────────────────────────────────────────────┘
```

### MCP Server Implementation

```go
// cmd/setec/mcp.go

package main

import (
    "context"
    "encoding/json"
    "os"

    "github.com/tailscale/setec/client/setec"
)

type MCPServer struct {
    client *setec.Client
}

type MCPRequest struct {
    JSONRPC string          `json:"jsonrpc"`
    ID      int             `json:"id"`
    Method  string          `json:"method"`
    Params  json.RawMessage `json:"params,omitempty"`
}

type MCPResponse struct {
    JSONRPC string      `json:"jsonrpc"`
    ID      int         `json:"id"`
    Result  interface{} `json:"result,omitempty"`
    Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}

func (s *MCPServer) handleToolCall(ctx context.Context, name string, args json.RawMessage) (interface{}, error) {
    switch name {
    case "get_secret":
        var params struct {
            Name string `json:"name"`
        }
        if err := json.Unmarshal(args, &params); err != nil {
            return nil, err
        }
        secret, err := s.client.Get(ctx, params.Name)
        if err != nil {
            return nil, err
        }
        return map[string]interface{}{
            "value":   string(secret.Value),
            "version": secret.Version,
        }, nil

    case "get_profile":
        var params struct {
            Name string `json:"name"`
        }
        if err := json.Unmarshal(args, &params); err != nil {
            return nil, err
        }
        bundle, err := s.client.GetProfile(ctx, params.Name)
        if err != nil {
            return nil, err
        }
        // Convert []byte values to strings for JSON
        result := make(map[string]string)
        for k, v := range bundle.Secrets {
            result[k] = string(v)
        }
        return result, nil

    case "list_secrets":
        secrets, err := s.client.List(ctx)
        if err != nil {
            return nil, err
        }
        names := make([]string, len(secrets))
        for i, s := range secrets {
            names[i] = s.Name
        }
        return names, nil

    default:
        return nil, fmt.Errorf("unknown tool: %s", name)
    }
}

func (s *MCPServer) manifest() map[string]interface{} {
    return map[string]interface{}{
        "name":        "setec",
        "version":     "1.0.0",
        "description": "Secure secrets management for AI coding tools",
        "tools": []map[string]interface{}{
            {
                "name":        "get_secret",
                "description": "Retrieve a secret value by name",
                "inputSchema": map[string]interface{}{
                    "type": "object",
                    "properties": map[string]interface{}{
                        "name": map[string]interface{}{
                            "type":        "string",
                            "description": "The name of the secret to retrieve",
                        },
                    },
                    "required": []string{"name"},
                },
            },
            {
                "name":        "get_profile",
                "description": "Get all secrets in a profile as environment variables",
                "inputSchema": map[string]interface{}{
                    "type": "object",
                    "properties": map[string]interface{}{
                        "name": map[string]interface{}{
                            "type":        "string",
                            "description": "The profile name",
                        },
                    },
                    "required": []string{"name"},
                },
            },
            {
                "name":        "list_secrets",
                "description": "List all accessible secret names",
                "inputSchema": map[string]interface{}{
                    "type":       "object",
                    "properties": map[string]interface{}{},
                },
            },
        },
    }
}

func runMCPServer(env *command.Env) error {
    client, err := newClient()
    if err != nil {
        return err
    }

    server := &MCPServer{client: client}

    // MCP uses JSON-RPC over stdio
    decoder := json.NewDecoder(os.Stdin)
    encoder := json.NewEncoder(os.Stdout)

    for {
        var req MCPRequest
        if err := decoder.Decode(&req); err != nil {
            return err
        }

        var resp MCPResponse
        resp.JSONRPC = "2.0"
        resp.ID = req.ID

        switch req.Method {
        case "initialize":
            resp.Result = server.manifest()

        case "tools/call":
            var params struct {
                Name      string          `json:"name"`
                Arguments json.RawMessage `json:"arguments"`
            }
            if err := json.Unmarshal(req.Params, &params); err != nil {
                resp.Error = &MCPError{Code: -32602, Message: err.Error()}
            } else {
                result, err := server.handleToolCall(env.Context(), params.Name, params.Arguments)
                if err != nil {
                    resp.Error = &MCPError{Code: -32000, Message: err.Error()}
                } else {
                    resp.Result = result
                }
            }

        default:
            resp.Error = &MCPError{Code: -32601, Message: "method not found"}
        }

        if err := encoder.Encode(resp); err != nil {
            return err
        }
    }
}
```

### Claude Code Configuration

```json
// ~/.config/claude/settings.json
{
    "mcpServers": {
        "setec": {
            "command": "setec",
            "args": ["mcp-server", "--server", "https://secrets.company.ts.net"],
            "env": {}
        }
    }
}
```

### Security Considerations for MCP

1. **Prompt Injection Risk**: Claude could be tricked into calling `get_secret` for sensitive secrets
   - **Mitigation**: Implement per-tool ACLs in the MCP server
   - **Mitigation**: Add `allowed_for_mcp: true` flag to secret metadata

2. **Audit Trail**: All MCP tool calls should be logged with Claude session context

3. **Rate Limiting**: Prevent bulk secret extraction:
```go
type MCPServer struct {
    client      *setec.Client
    rateLimiter *rate.Limiter // e.g., 10 requests per minute
}
```

---

## 4. OAuth Token Management

### Complexity Analysis

OAuth introduces significant complexity:

| Component | Complexity | Notes |
|-----------|------------|-------|
| Token storage | Low | Just another secret type |
| Refresh logic | Medium | Background goroutine, error handling |
| Provider integration | High | Each provider has quirks |
| Error handling | High | Network failures, revoked tokens, etc. |

### Design Options

#### Option A: Server-Side Refresh (Recommended)

The setec server handles all refresh logic:

```go
// db/oauth.go

type OAuthSecret struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"` // Never exposed to clients
    ExpiresAt    time.Time `json:"expires_at"`
    TokenURL     string    `json:"token_url"`
    ClientID     string    `json:"client_id"`
    ClientSecret string    `json:"client_secret_ref"` // Reference to another secret
    Scopes       []string  `json:"scopes"`
}

// Server maintains a background refresh loop
func (s *Server) oauthRefreshLoop(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            s.refreshExpiringTokens(ctx)
        }
    }
}

func (s *Server) refreshExpiringTokens(ctx context.Context) {
    // Find OAuth secrets expiring within 5 minutes
    expiring := s.db.FindExpiringOAuthSecrets(5 * time.Minute)

    for _, secret := range expiring {
        if err := s.refreshOAuthToken(ctx, secret); err != nil {
            log.Printf("Failed to refresh %s: %v", secret.Name, err)
        }
    }
}
```

#### Option B: Client-Side Refresh

Clients handle refresh themselves:

```go
// client/setec/oauth.go

type OAuthStore struct {
    *Store
    tokens map[string]*oauth2.Token
    mu     sync.RWMutex
}

func (s *OAuthStore) GetOAuth(ctx context.Context, name string) (*oauth2.Token, error) {
    s.mu.RLock()
    token := s.tokens[name]
    s.mu.RUnlock()

    if token != nil && token.Valid() {
        return token, nil
    }

    // Fetch fresh token from server
    secret, err := s.Store.LookupSecret(ctx, name)
    if err != nil {
        return nil, err
    }

    var oauthData OAuthSecret
    if err := json.Unmarshal(secret.Get(), &oauthData); err != nil {
        return nil, err
    }

    token = &oauth2.Token{
        AccessToken: oauthData.AccessToken,
        Expiry:      oauthData.ExpiresAt,
    }

    s.mu.Lock()
    s.tokens[name] = token
    s.mu.Unlock()

    return token, nil
}
```

### Provider-Specific Considerations

| Provider | Token Lifetime | Refresh Notes |
|----------|---------------|---------------|
| GitHub | 8 hours (fine-grained) | Use installation tokens for apps |
| Google | 1 hour | Refresh tokens can expire after 6 months inactivity |
| Azure AD | 1 hour | Refresh tokens last 90 days |
| Anthropic | N/A | API keys don't expire (static) |
| OpenAI | N/A | API keys don't expire (static) |

### Recommendation

Start with static API key support (Anthropic, OpenAI) since those are the primary AI tool credentials. Defer OAuth to Phase 2 when GitHub integration is needed.

---

## 5. Security Deep Dive

### Threat Model for AI Coding Tools

```
┌─────────────────────────────────────────────────────────────────────┐
│                        THREAT CATEGORIES                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. CREDENTIAL EXFILTRATION VIA AI                                  │
│     ├─ AI outputs secret in generated code                         │
│     ├─ AI includes secret in error messages/logs                   │
│     ├─ AI sends secret to external service                         │
│     └─ Prompt injection tricks AI into revealing secrets           │
│                                                                     │
│  2. COMPROMISED DEVELOPER WORKSTATION                               │
│     ├─ Malware reads cached secrets                                │
│     ├─ Attacker gains shell access                                 │
│     └─ Memory dump reveals secrets                                 │
│                                                                     │
│  3. SUPPLY CHAIN ATTACKS                                            │
│     ├─ Malicious AI tool update                                    │
│     ├─ Compromised MCP server                                      │
│     └─ Dependency with credential harvesting                       │
│                                                                     │
│  4. INSIDER THREATS                                                 │
│     ├─ Developer exfiltrates credentials                           │
│     ├─ Overly broad ACL grants                                     │
│     └─ Shared credentials across environments                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Mitigation Matrix

| Threat | Mitigation | Implementation |
|--------|------------|----------------|
| AI exfiltration | Short-lived tokens | Token vending with 4-8h TTL |
| AI exfiltration | Scope restrictions | Per-secret `allowed_operations` field |
| AI exfiltration | Rate limiting | Max 10 secret fetches per minute |
| Prompt injection | Secret filtering | Don't expose `prod/*` secrets to MCP |
| Workstation compromise | Keyring encryption | System keyring for local cache |
| Workstation compromise | No persistent cache | `--no-cache` flag for high-security |
| Supply chain | Binary attestation | Verify AI tool signatures |
| Insider | Audit logging | Already implemented |
| Insider | Time-based ACLs | Restrict to work hours |

### Implementation: Enhanced ACL Rules

Extend the existing ACL system with new restriction types:

```go
// acl/acl.go (extended)

type Rule struct {
    Action      []Action   `json:"action"`
    Secret      []Secret   `json:"secret"`

    // New fields for AI tool security
    TimeWindow  *TimeWindow `json:"time_window,omitempty"`
    RateLimit   *RateLimit  `json:"rate_limit,omitempty"`
    AllowMCP    *bool       `json:"allow_mcp,omitempty"`
    RequireMFA  bool        `json:"require_mfa,omitempty"`
}

type TimeWindow struct {
    AllowedDays  []time.Weekday `json:"allowed_days"`  // 0=Sunday
    StartHour    int            `json:"start_hour"`    // 0-23
    EndHour      int            `json:"end_hour"`      // 0-23
    Timezone     string         `json:"timezone"`
}

type RateLimit struct {
    MaxRequests int           `json:"max_requests"`
    Window      time.Duration `json:"window"`
}

func (r *Rule) Allow(action Action, secret string, ctx AccessContext) bool {
    // Basic action/secret check
    if !r.allowsAction(action) || !r.allowsSecret(secret) {
        return false
    }

    // Time window check
    if r.TimeWindow != nil && !r.TimeWindow.IsWithinWindow(ctx.Time) {
        return false
    }

    // MCP restriction
    if ctx.IsMCP && r.AllowMCP != nil && !*r.AllowMCP {
        return false
    }

    return true
}
```

### Audit Enhancements for AI Tools

Extend audit entries to capture AI-specific context:

```go
// audit/audit.go (extended)

type Entry struct {
    // ... existing fields ...

    // AI tool context
    AIToolContext *AIToolContext `json:"ai_tool_context,omitempty"`
}

type AIToolContext struct {
    ToolName    string `json:"tool_name"`     // "claude-code", "cursor", etc.
    ToolVersion string `json:"tool_version"`
    IsMCP       bool   `json:"is_mcp"`        // Accessed via MCP
    SessionID   string `json:"session_id"`    // For correlation
}
```

---

## 6. Implementation Roadmap

### Phase 1: Core CLI Enhancements (2-3 weeks)

**Deliverables:**
1. `setec exec` command with secret-to-env mapping
2. Profile support via `_profiles/*` naming convention
3. `setec profile create/get/list` commands

**Files to modify:**
- `cmd/setec/setec.go` - Add new subcommands
- `client/setec/client.go` - Add `GetProfile()` helper
- New file: `cmd/setec/exec.go`
- New file: `cmd/setec/profile.go`

**Testing:**
- Unit tests for profile parsing
- Integration tests with mock secrets
- Manual testing with Claude Code

### Phase 2: MCP Integration (2-3 weeks)

**Deliverables:**
1. MCP server implementation
2. Claude Code configuration documentation
3. MCP-specific ACL restrictions

**Files to create:**
- `cmd/setec/mcp.go` - MCP server
- `docs/mcp-integration.md` - Setup guide

**Testing:**
- MCP protocol conformance tests
- Security tests (prompt injection scenarios)
- Load tests (concurrent MCP requests)

### Phase 3: Security Hardening (2-3 weeks)

**Deliverables:**
1. Time-based ACL rules
2. Rate limiting
3. Enhanced audit logging with AI context
4. Local cache encryption via system keyring

**Files to modify:**
- `acl/acl.go` - Extended rule types
- `audit/audit.go` - AI context fields
- `client/setec/cache.go` - Keyring integration

**Dependencies:**
- `github.com/zalando/go-keyring` or similar

### Phase 4: OAuth Support (4-6 weeks)

**Deliverables:**
1. OAuth secret type
2. Server-side token refresh
3. Provider integrations (GitHub, Google)

**Files to create:**
- `db/oauth.go` - OAuth secret handling
- `server/oauth.go` - Refresh loop
- `client/setec/oauth.go` - Client helpers

**Complexity notes:**
- Each OAuth provider requires testing
- Error handling for revoked tokens
- Consider using existing oauth2 libraries

---

## 7. Alternative Approaches Considered

### Why Not HashiCorp Vault?

| Aspect | Vault | Setec |
|--------|-------|-------|
| Complexity | High (separate infra) | Low (single binary) |
| Auth | Multiple options | Tailscale-native |
| Scaling | Enterprise features | Simple single-node |
| Cost | Enterprise license | Open source |
| AI tool fit | Generic | Can be tailored |

**Verdict**: Setec's simplicity and Tailscale integration make it better for developer-focused AI tool use cases. Vault is overkill for teams already using Tailscale.

### Why Not 1Password CLI?

| Aspect | 1Password | Setec |
|--------|-----------|-------|
| Audit | Limited | Full audit log |
| Programmatic | CLI only | HTTP API |
| ACLs | Basic | Tailscale-native |
| Cost | Per-seat | Free |

**Verdict**: 1Password works for human-centric workflows but lacks the programmatic access and detailed audit logging needed for AI tools.

### Why Not Environment Variables Directly?

Just setting `ANTHROPIC_API_KEY` in `.bashrc`:

| Risk | Impact |
|------|--------|
| Shell history exposure | Credentials in plaintext logs |
| Dotfile sync | Credentials in git repos |
| No rotation | Manual update required |
| No audit | No visibility into usage |

**Verdict**: Environment variables are convenient but provide no security controls. Setec adds rotation, auditing, and access control.

---

## 8. Estimated Effort Summary

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1: CLI | 2-3 weeks | P0 |
| Phase 2: MCP | 2-3 weeks | P1 |
| Phase 3: Security | 2-3 weeks | P1 |
| Phase 4: OAuth | 4-6 weeks | P2 |
| **Total** | **10-15 weeks** | |

With parallel development of independent components, the timeline could compress to 8-10 weeks.
