# Setec Analysis for AI Coding Tool Credential Management

## Executive Summary

**Setec** is a lightweight, encrypted secrets management service built on Tailscale's identity infrastructure. It provides centralized storage with audit logging, versioning, and AWS KMS encryption. This analysis evaluates its suitability for managing authentication credentials for AI coding tools (Claude Code, GitHub Copilot, Cursor, etc.) and proposes enhancements.

---

## Current Architecture Overview

### Strengths for AI Tool Integration

| Feature | Benefit for AI Tools |
|---------|---------------------|
| **Tailscale-based auth** | Zero-config PKI; developers already on tailnet get automatic identity |
| **Encrypted at rest** | AWS KMS + Tink encryption protects API keys even if database leaked |
| **Audit logging** | Track which tools/users accessed which credentials and when |
| **Version rotation** | Seamless key rotation without service interruption |
| **Caching client** | `setec.Store` provides in-memory + persistent caching with background polling |
| **Struct field injection** | `setec:"secret-name"` tags auto-populate config structs |

### Current Limitations for AI Coding Tools

1. **Tailscale dependency** - Requires all clients on same tailnet
2. **No short-lived tokens** - All secrets are static values
3. **No secret grouping** - Can't fetch related credentials atomically
4. **No environment injection** - Must integrate via Go client library
5. **No OAuth flow support** - Can't handle token refresh automatically
6. **Single authorization model** - ACLs only, no time-based or usage-based controls

---

## Proposed Enhancements

### 1. Environment Variable Injection for AI Tools

**Problem**: AI coding tools like Claude Code read credentials from environment variables (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, etc.). Currently, developers must manually export these.

**Solution**: Add an `env-inject` command and wrapper script:

```bash
# Proposed usage
setec env-inject --profile ai-tools -- claude

# Or as a wrapper
setec exec --secrets "anthropic-key:ANTHROPIC_API_KEY,github-token:GITHUB_TOKEN" -- claude
```

**Implementation sketch**:
```go
// cmd/setec/env.go
type EnvMapping struct {
    SecretName string
    EnvVar     string
}

func runEnvInject(env *command.Env, mappings []EnvMapping, cmd []string) error {
    client, _ := newClient()
    environ := os.Environ()

    for _, m := range mappings {
        secret, err := client.Get(env.Context(), m.SecretName)
        if err != nil {
            return err
        }
        environ = append(environ, fmt.Sprintf("%s=%s", m.EnvVar, secret.Value))
    }

    return syscall.Exec(cmd[0], cmd, environ)
}
```

---

### 2. Secret Profiles/Bundles

**Problem**: AI coding tools need multiple related credentials (API key + org ID + project ID). Fetching them individually is error-prone and inefficient.

**Solution**: Introduce "profiles" - named collections of secrets with metadata:

```json
{
  "name": "claude-code-dev",
  "secrets": {
    "ANTHROPIC_API_KEY": "ai/anthropic/api-key",
    "GITHUB_TOKEN": "dev/github/pat",
    "OPENAI_API_KEY": "ai/openai/key"
  },
  "env_file_format": "export",
  "expires": "2024-12-31T23:59:59Z"
}
```

**New API endpoints**:
- `POST /api/profiles/create` - Create profile
- `POST /api/profiles/get` - Fetch all secrets in profile atomically
- `POST /api/profiles/export` - Generate `.env` file or shell exports

---

### 3. Short-Lived Token Generation

**Problem**: Static API keys in developer environments are high-risk. If a developer's machine is compromised, long-lived keys can be exfiltrated.

**Solution**: Implement a token vending pattern where setec issues short-lived credentials:

```
Developer -> setec -> "I need anthropic access for 4 hours"
                   <- Issues wrapped token with 4h TTL

AI Tool uses token -> setec proxy -> validates TTL -> forwards to Anthropic API
```

**Components**:
1. **Token wrapping service**: Signs short-lived tokens that embed the real credential
2. **Proxy mode**: Setec can proxy API calls, injecting real credentials server-side
3. **Token refresh client**: Background refresh before expiration

```go
// Proposed types
type TemporaryToken struct {
    Token     string        // Opaque token for client use
    ExpiresAt time.Time
    SecretRef string        // Which underlying secret this wraps
    Scope     []string      // Optional: limit operations
}

// POST /api/token/issue
type IssueTokenRequest struct {
    SecretName string
    TTL        time.Duration
    Scopes     []string      // e.g., ["chat:read", "chat:write"]
}
```

---

### 4. OAuth Token Management

**Problem**: Many AI tools need OAuth tokens (GitHub, GitLab, Google Cloud). These expire and need refresh.

**Solution**: Add OAuth credential type with automatic refresh:

```go
type OAuthCredential struct {
    AccessToken  string
    RefreshToken string    // Stored encrypted, never exposed
    ExpiresAt    time.Time
    TokenURL     string    // For refresh
    ClientID     string
    ClientSecret string    // Reference to another secret
    Scopes       []string
}

// Client always gets fresh access token
func (c *Client) GetOAuth(ctx context.Context, name string) (*OAuthToken, error)
```

**Features**:
- Automatic refresh when access token near expiration
- Refresh token never leaves server
- Audit log shows token refresh events
- Support for common OAuth providers (GitHub, Google, Azure AD)

---

### 5. MCP Server for Claude Code

**Problem**: Claude Code uses MCP (Model Context Protocol) for tool integrations. No native secrets integration exists.

**Solution**: Implement a setec MCP server that Claude Code can use:

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "setec": {
      "command": "setec",
      "args": ["mcp-server"],
      "env": {
        "SETEC_SERVER": "https://setec.tailnet-name.ts.net"
      }
    }
  }
}
```

**MCP Tools provided**:
```typescript
// Tools exposed to Claude Code via MCP
tools: [
  {
    name: "get_secret",
    description: "Retrieve a secret value",
    inputSchema: { secretName: string }
  },
  {
    name: "get_env_bundle",
    description: "Get environment variables for a profile",
    inputSchema: { profileName: string }
  },
  {
    name: "rotate_secret",
    description: "Trigger rotation for a secret",
    inputSchema: { secretName: string }
  }
]
```

---

### 6. Time-Based Access Controls

**Problem**: Development credentials might only be needed during work hours. Weekend/night access could indicate compromise.

**Solution**: Add time-based ACL rules:

```json
{
  "action": ["get"],
  "secret": ["dev/*"],
  "timeRestriction": {
    "allowedHours": [9, 18],    // 9 AM - 6 PM
    "allowedDays": [1, 2, 3, 4, 5],  // Mon-Fri
    "timezone": "America/Los_Angeles"
  },
  "exceptionGroups": ["oncall"]  // Bypass for on-call
}
```

---

### 7. Usage-Based Anomaly Detection

**Problem**: Stolen credentials often exhibit unusual access patterns (sudden spike in requests, access from new locations).

**Solution**: Add metrics and alerting:

```go
type AccessMetrics struct {
    SecretName      string
    RequestsPerHour map[string]int  // Per principal
    UniquePrincipals []string
    LastAccess      time.Time
}

// Alert rules
type AlertRule struct {
    Condition string  // "requests_per_hour > 100"
    Action    string  // "notify:slack", "revoke:temporary"
}
```

---

### 8. Credential Health Dashboard

**Problem**: No visibility into credential status (age, rotation needed, unused secrets).

**Solution**: Enhanced web dashboard:

```
┌─────────────────────────────────────────────────────────────┐
│  SETEC CREDENTIAL HEALTH                                    │
├─────────────────────────────────────────────────────────────┤
│  ⚠️  3 secrets older than 90 days                          │
│  ⚠️  2 secrets unused in 30 days                           │
│  ✅ 15 secrets healthy                                      │
├─────────────────────────────────────────────────────────────┤
│  RECENT ACTIVITY                                            │
│  • claude@dev-laptop accessed ai/anthropic/key (2m ago)    │
│  • ci-runner accessed dev/github/token (15m ago)           │
│  • DENIED: unknown@external tried prod/* (1h ago)          │
└─────────────────────────────────────────────────────────────┘
```

---

### 9. Local Development Mode Enhancements

**Problem**: Developers working offline or without Tailscale need credential access.

**Current**: `FileClient` reads from local JSON, but no sync mechanism.

**Enhanced solution**:

```bash
# Sync secrets to encrypted local cache for offline use
setec cache sync --profile ai-tools --encrypt-with-keyring

# Use cached secrets when offline
setec exec --offline --profile ai-tools -- claude
```

**Features**:
- System keyring integration (macOS Keychain, GNOME Keyring, Windows Credential Manager)
- Encrypted local cache with configurable TTL
- Automatic sync when network available
- Clear cache on logout/lock

---

### 10. Multi-Provider Secret Sync

**Problem**: Organizations may have secrets in multiple systems (AWS Secrets Manager, HashiCorp Vault, 1Password).

**Solution**: Bidirectional sync adapters:

```yaml
# setec-sync.yaml
sources:
  - type: aws-secrets-manager
    region: us-west-2
    filter: "ai-tools/*"
    sync_to: "aws/"

  - type: 1password
    vault: "Engineering"
    items: ["Anthropic API", "OpenAI Key"]
    sync_to: "1p/"

destinations:
  - type: aws-secrets-manager
    secrets: ["prod/*"]
```

---

## Implementation Priority Matrix

| Enhancement | Effort | Impact | Priority |
|-------------|--------|--------|----------|
| Environment variable injection | Low | High | P0 |
| Secret profiles/bundles | Medium | High | P0 |
| MCP server for Claude Code | Medium | High | P1 |
| OAuth token management | High | High | P1 |
| Local cache with keyring | Medium | Medium | P2 |
| Time-based access controls | Medium | Medium | P2 |
| Short-lived token generation | High | High | P2 |
| Usage anomaly detection | High | Medium | P3 |
| Health dashboard | Medium | Low | P3 |
| Multi-provider sync | High | Medium | P3 |

---

## Specific AI Tool Integration Patterns

### Claude Code

```bash
# Recommended integration
# 1. Store API key
setec put ai/anthropic/api-key

# 2. Create wrapper script: ~/bin/claude-with-secrets
#!/bin/bash
exec setec exec \
  --secret ai/anthropic/api-key:ANTHROPIC_API_KEY \
  -- claude "$@"

# 3. Or use MCP server (proposed)
# Configure in ~/.config/claude/settings.json
```

### GitHub Copilot

```bash
# GitHub token for Copilot authentication
setec put dev/github/copilot-token

# Inject into VS Code environment
setec exec --secret dev/github/copilot-token:GITHUB_TOKEN \
  -- code .
```

### Cursor IDE

```bash
# Multiple AI provider keys
setec put ai/openai/key
setec put ai/anthropic/key

# Profile for Cursor
setec profile create cursor-ide \
  --map ai/openai/key:OPENAI_API_KEY \
  --map ai/anthropic/key:ANTHROPIC_API_KEY

# Launch with all credentials
setec exec --profile cursor-ide -- cursor .
```

---

## Security Considerations

### Threat Model for AI Coding Tools

1. **Credential exfiltration via AI**: AI tools could inadvertently leak credentials in generated code or logs
   - *Mitigation*: Short-lived tokens, audit logging, scope restrictions

2. **Compromised developer workstation**: Full access to all cached credentials
   - *Mitigation*: Time-limited local cache, system keyring encryption, MFA for high-value secrets

3. **Supply chain attacks on AI tools**: Malicious updates could harvest credentials
   - *Mitigation*: Proxy mode (credentials never touch client), allowlisting of tool binaries

4. **Prompt injection attacks**: AI tool convinced to exfiltrate secrets
   - *Mitigation*: Rate limiting, anomaly detection, restricted scopes per tool

### Recommended Security Defaults

```yaml
ai_tool_defaults:
  max_ttl: 8h                    # Secrets expire after workday
  require_mfa_for:
    - "prod/*"
    - "**/billing/*"
  rate_limit: 100/hour           # Prevent bulk exfiltration
  allowed_ips: ["tailscale"]     # Only from tailnet
  audit_level: "verbose"         # Log all access attempts
```

---

## Conclusion

Setec provides a solid foundation for AI coding tool credential management with its encrypted storage, Tailscale-based identity, and audit logging. The proposed enhancements focus on:

1. **Developer Experience**: Environment injection, profiles, offline mode
2. **Security**: Short-lived tokens, time-based controls, anomaly detection
3. **AI Tool Integration**: MCP server, OAuth handling, health monitoring

The P0 items (env injection + profiles) could be implemented in 1-2 weeks and would immediately improve developer workflows with AI coding tools.
