# Extended Analysis: setec + tsidp for AI Coding Tool Credential Management

This document extends the previous analysis by incorporating **tsidp** (Tailscale Identity Provider), creating a comprehensive identity and secrets management architecture for AI coding tools.

---

## tsidp Overview

[tsidp](https://github.com/tailscale/tsidp) is an experimental OIDC/OAuth 2.1 Identity Provider that converts Tailscale network identity into standard OAuth tokens. Key capabilities:

| Feature | Description |
|---------|-------------|
| **OIDC/OAuth 2.1** | Full protocol compliance with modern security requirements |
| **Dynamic Client Registration (DCR)** | RFC 7591 - crucial for MCP server registration |
| **STS Token Exchange** | RFC 8693 - enables token transformation for gateway patterns |
| **MCP Authorization Spec** | Native support for AI tool authentication |
| **Tailscale Identity** | Cryptographically guaranteed network identity |

---

## The Combined Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DEVELOPER WORKSTATION                              │
│                                                                              │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────────────────────┐   │
│   │ Claude Code │     │   Cursor    │     │     Other AI Tools          │   │
│   │  (MCP)      │     │             │     │                             │   │
│   └──────┬──────┘     └──────┬──────┘     └─────────────┬───────────────┘   │
│          │                   │                          │                    │
│          │    OAuth 2.1 + PKCE / MCP Auth               │                    │
│          └───────────────────┴──────────────────────────┘                    │
│                              │                                               │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
                    ╔══════════╧══════════╗
                    ║   TAILSCALE MESH    ║
                    ╚══════════╤══════════╝
                               │
        ┌──────────────────────┴──────────────────────┐
        │                                             │
        ▼                                             ▼
┌───────────────────────────┐           ┌───────────────────────────┐
│         tsidp              │           │          setec            │
│  (Identity Provider)       │           │   (Secrets Manager)       │
├───────────────────────────┤           ├───────────────────────────┤
│ • OIDC Discovery           │           │ • Encrypted secret store  │
│ • OAuth 2.1 Authorization  │◄─────────►│ • ACL-based access        │
│ • Dynamic Client Reg (DCR) │  Token    │ • Version management      │
│ • STS Token Exchange       │ Exchange  │ • Audit logging           │
│ • MCP Auth endpoints       │           │ • S3 backup               │
└───────────────────────────┘           └───────────────────────────┘
        │                                             │
        │         ┌───────────────────────┐           │
        └────────►│  External Services    │◄──────────┘
                  │  (Anthropic, OpenAI,  │
                  │   GitHub, etc.)       │
                  └───────────────────────┘
```

---

## Complementary Roles

### tsidp Handles: Identity ("Who are you?")

- Issues OAuth access tokens and OIDC ID tokens
- Authenticates users/nodes via Tailscale identity
- Supports DCR for MCP servers and AI tools
- Provides token exchange for complex delegation patterns

### setec Handles: Secrets ("What can you access?")

- Stores static credentials (API keys, service accounts)
- Manages credential rotation and versioning
- Enforces fine-grained ACLs on secret access
- Provides audit trail of credential usage

---

## Integration Patterns

### Pattern 1: Token-Gated Secret Access

Use tsidp tokens to authenticate to setec, replacing Tailscale-only auth:

```
┌──────────────┐     1. OAuth flow      ┌──────────────┐
│  Claude Code │ ◄────────────────────► │    tsidp     │
│              │     (get ID token)     │              │
└──────┬───────┘                        └──────────────┘
       │
       │ 2. Request secret with ID token
       ▼
┌──────────────┐     3. Validate token  ┌──────────────┐
│    setec     │ ◄────────────────────► │    tsidp     │
│              │     (introspection)    │ (/.well-known│
└──────────────┘                        │  /jwks.json) │
       │                                └──────────────┘
       │ 4. Return secret if authorized
       ▼
   API Key for Anthropic
```

**Benefits:**
- Standard OAuth flows work with any OIDC-capable client
- Token introspection adds identity claims to audit logs
- Works for non-Tailscale clients via token exchange

**Implementation:**

```go
// server/oidc.go - Add OIDC token validation to setec

type OIDCConfig struct {
    Issuer   string // tsidp issuer URL
    Audience string // setec audience
    jwks     *jwk.Set
}

func (s *Server) validateOIDCToken(r *http.Request) (*OIDCClaims, error) {
    // Extract bearer token
    auth := r.Header.Get("Authorization")
    if !strings.HasPrefix(auth, "Bearer ") {
        return nil, nil // Fall back to Tailscale WhoIs
    }
    token := strings.TrimPrefix(auth, "Bearer ")

    // Validate JWT signature against tsidp JWKS
    claims, err := s.oidcConfig.ValidateToken(token)
    if err != nil {
        return nil, fmt.Errorf("invalid token: %w", err)
    }

    return claims, nil
}

// Enhanced getIdentity supporting both auth methods
func (s *Server) getIdentity(r *http.Request) (db.Caller, error) {
    // Try OIDC token first (for non-Tailscale clients)
    if claims, err := s.validateOIDCToken(r); err != nil {
        return db.Caller{}, err
    } else if claims != nil {
        return db.Caller{
            Principal: audit.Principal{
                User: claims.Subject,
                // Additional claims from tsidp
            },
            Permissions: s.claimsToACL(claims),
        }, nil
    }

    // Fall back to Tailscale WhoIs
    return s.getTailscaleIdentity(r)
}
```

### Pattern 2: STS Token Exchange for AI Tool Sessions

Use tsidp's STS to create session-scoped tokens that setec accepts:

```
┌──────────────┐  1. Authenticate    ┌──────────────┐
│  Developer   │ ──────────────────► │    tsidp     │
│              │  (Tailscale ID)     │              │
└──────────────┘                     └──────┬───────┘
                                            │
                                            │ 2. Issue long-lived
                                            │    refresh token
                                            ▼
                                     ┌──────────────┐
                                     │   Refresh    │
                                     │    Token     │
                                     └──────┬───────┘
                                            │
┌──────────────┐  3. Token exchange  ┌──────┴───────┐
│  Claude Code │ ──────────────────► │    tsidp     │
│              │  (RFC 8693)         │    /sts      │
└──────────────┘                     └──────┬───────┘
       │                                    │
       │ 4. Session token                   │
       │    (4h TTL, scoped)                │
       ▼                                    │
┌──────────────┐  5. Request secrets ┌──────┴───────┐
│    setec     │ ◄───────────────────│  Validates   │
│              │  with session token │  via JWKS    │
└──────────────┘                     └──────────────┘
```

**Token Exchange Request:**
```http
POST /sts HTTP/1.1
Host: tsidp.tailnet.ts.net
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<refresh_token>
&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=setec:read:ai/*
&audience=https://setec.tailnet.ts.net
```

**Response:**
```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 14400,
    "scope": "setec:read:ai/*"
}
```

**Benefits:**
- Short-lived tokens (4h) limit exposure window
- Scoped to specific secret paths (`ai/*`)
- Session binding prevents token theft across sessions
- Audit trail shows token exchange events

### Pattern 3: MCP-Native Authentication

Claude Code and other MCP clients can authenticate directly to setec's MCP server via tsidp:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLAUDE CODE                                   │
│                                                                      │
│  1. $ claude mcp add setec-secrets https://setec.tailnet.ts.net/mcp │
│                                                                      │
│  2. Claude detects 401, reads WWW-Authenticate header               │
│     WWW-Authenticate: Bearer resource_metadata="/.well-known/oauth" │
│                                                                      │
│  3. Claude discovers tsidp as authorization server                  │
│     GET /.well-known/oauth-authorization-server                     │
│     → { "issuer": "https://tsidp.tailnet.ts.net", ... }            │
│                                                                      │
│  4. Claude performs OAuth 2.1 + PKCE flow with tsidp               │
│     (browser opens for Tailscale authentication)                    │
│                                                                      │
│  5. Claude receives access token, calls setec MCP endpoints        │
│     Authorization: Bearer <access_token>                            │
└─────────────────────────────────────────────────────────────────────┘
```

**setec MCP Server Enhancement:**

```go
// cmd/setec/mcp.go - OAuth-aware MCP server

func (s *MCPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
    // Check for valid OAuth token
    token, err := s.validateToken(r)
    if err != nil || token == nil {
        // Return 401 with MCP-compliant discovery
        w.Header().Set("WWW-Authenticate",
            `Bearer resource_metadata="/.well-known/oauth-protected-resource"`)
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "unauthorized",
            "error_description": "Valid OAuth token required",
        })
        return
    }

    // Token is valid, process MCP request
    s.handleMCPRequest(w, r, token)
}

// Serve OAuth discovery for MCP clients
func (s *MCPServer) serveOAuthMetadata(w http.ResponseWriter, r *http.Request) {
    metadata := map[string]interface{}{
        "resource": "https://setec.tailnet.ts.net/mcp",
        "authorization_servers": []string{
            "https://tsidp.tailnet.ts.net",
        },
        "scopes_supported": []string{
            "setec:read",
            "setec:write",
            "setec:admin",
        },
    }
    json.NewEncoder(w).Encode(metadata)
}
```

### Pattern 4: Secret-Backed OAuth Client Credentials

Store OAuth client credentials in setec, use them for machine-to-machine auth:

```
┌──────────────┐                      ┌──────────────┐
│   CI/CD      │  1. Fetch client     │    setec     │
│   Pipeline   │ ───────────────────► │              │
│              │     credentials      │              │
└──────┬───────┘                      └──────────────┘
       │                                     │
       │ client_id: gh-actions               │
       │ client_secret: ***                  │
       ▼                                     │
┌──────────────┐  2. Client credentials     │
│    tsidp     │ ◄──────────────────────────┘
│              │     grant
└──────┬───────┘
       │
       │ 3. Access token for
       │    downstream services
       ▼
┌──────────────┐
│  Anthropic   │
│     API      │
└──────────────┘
```

**Use Case:** GitHub Actions needs to call Anthropic API for code review.

```yaml
# .github/workflows/review.yml
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Get OAuth credentials from setec
        run: |
          # Fetch client credentials (via Tailscale connector)
          eval $(setec exec --profile ci/anthropic-reviewer --export-env)

      - name: Exchange for access token
        run: |
          TOKEN=$(curl -X POST https://tsidp.company.ts.net/token \
            -d "grant_type=client_credentials" \
            -d "client_id=$CLIENT_ID" \
            -d "client_secret=$CLIENT_SECRET" \
            -d "scope=anthropic:chat" | jq -r .access_token)

      - name: Call Anthropic API
        run: |
          curl https://api.anthropic.com/v1/messages \
            -H "Authorization: Bearer $TOKEN" \
            -d '{"model": "claude-sonnet-4-20250514", ...}'
```

---

## Enhanced Security Model

### Defense in Depth with tsidp + setec

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY LAYERS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Layer 1: NETWORK IDENTITY (Tailscale)                                      │
│  ├─ Cryptographic device identity                                           │
│  ├─ Encrypted WireGuard tunnels                                             │
│  └─ Network-level ACLs                                                      │
│                                                                              │
│  Layer 2: AUTHENTICATION (tsidp)                                            │
│  ├─ OAuth 2.1 with PKCE (no client secrets for public clients)             │
│  ├─ Short-lived access tokens (1h default)                                  │
│  ├─ Token binding to Tailscale node                                         │
│  └─ Refresh token rotation                                                  │
│                                                                              │
│  Layer 3: AUTHORIZATION (setec ACLs + tsidp scopes)                         │
│  ├─ Fine-grained secret ACLs (get, put, delete, etc.)                      │
│  ├─ OAuth scopes limit token capabilities                                   │
│  ├─ Resource Indicators (RFC 8707) prevent token misuse                     │
│  └─ Time-based restrictions                                                 │
│                                                                              │
│  Layer 4: AUDIT & MONITORING                                                │
│  ├─ setec audit log (all secret access)                                     │
│  ├─ tsidp token issuance logs                                               │
│  ├─ Correlation via session IDs                                             │
│  └─ Anomaly detection alerts                                                │
│                                                                              │
│  Layer 5: SECRET PROTECTION                                                 │
│  ├─ AWS KMS encryption at rest                                              │
│  ├─ Version management for rotation                                         │
│  ├─ No persistent local cache (optional)                                    │
│  └─ Memory protection (mlock)                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Token Scoping for AI Tools

Define granular scopes that map to setec ACL actions:

```go
// Proposed scope definitions
var ScopeDefinitions = map[string]acl.Rules{
    "setec:read:ai/*": {
        {Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"ai/*"}},
    },
    "setec:read:dev/*": {
        {Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"dev/*"}},
    },
    "setec:admin": {
        {Action: []acl.Action{acl.ActionGet, acl.ActionPut, acl.ActionDelete},
         Secret: []acl.Secret{"*"}},
    },
    "setec:mcp": {
        {Action: []acl.Action{acl.ActionGet, acl.ActionInfo},
         Secret: []acl.Secret{"ai/*", "mcp/*"}},
        // Explicitly exclude prod secrets from MCP access
    },
}
```

### Claude Code Configuration with tsidp

```json
// ~/.config/claude/settings.json
{
    "mcpServers": {
        "setec": {
            "url": "https://setec.company.ts.net/mcp",
            "transport": "http",
            "auth": {
                "type": "oauth",
                "authorization_server": "https://tsidp.company.ts.net",
                "scopes": ["setec:mcp"],
                "pkce": true
            }
        }
    }
}
```

---

## Implementation Considerations

### tsidp Deployment Alongside setec

```yaml
# docker-compose.yml
version: '3.8'

services:
  tsidp:
    image: ghcr.io/tailscale/tsidp:latest
    environment:
      - TAILSCALE_USE_WIP_CODE=1
      - TS_AUTHKEY=${TS_AUTHKEY}
      - TSIDP_HOSTNAME=tsidp
      - TSIDP_ENABLE_STS=1
    volumes:
      - tsidp-state:/var/lib/tsidp

  setec:
    build: .
    command: server --hostname setec --state-dir /data
    environment:
      - TS_AUTHKEY=${TS_AUTHKEY}
      - SETEC_KMS_KEY_NAME=${KMS_KEY_ARN}
      # Enable OIDC validation against tsidp
      - SETEC_OIDC_ISSUER=https://tsidp.${TAILNET}.ts.net
    volumes:
      - setec-state:/data

volumes:
  tsidp-state:
  setec-state:
```

### ACL Configuration (tailnet policy)

```hujson
{
    "grants": [
        // tsidp admin access
        {
            "src": ["autogroup:admin"],
            "dst": ["tag:tsidp"],
            "app": {
                "tailscale.com/cap/tsidp": [{
                    "allow_admin_ui": true,
                    "allow_dcr": true,
                    "users": ["*"],
                    "resources": ["*"]
                }]
            }
        },
        // setec access for AI tools (via tsidp tokens)
        {
            "src": ["autogroup:member"],
            "dst": ["tag:setec"],
            "app": {
                "tailscale.com/cap/secrets": [{
                    "action": ["get", "info"],
                    "secret": ["ai/*", "dev/*"]
                }]
            }
        },
        // Allow Claude Code MCP access
        {
            "src": ["tag:claude-code"],
            "dst": ["tag:setec"],
            "app": {
                "tailscale.com/cap/secrets": [{
                    "action": ["get"],
                    "secret": ["ai/*"],
                    "allow_mcp": true
                }]
            }
        }
    ]
}
```

---

## New Integration Possibilities with tsidp

### 1. Federated Identity for External Collaborators

tsidp can exchange tokens from external IdPs, allowing contractors to access secrets:

```
External User → Corporate IdP → tsidp (token exchange) → setec
```

### 2. Workload Identity for Kubernetes

Pods can use SPIFFE/SPIRE identity, exchange for tsidp tokens:

```yaml
# Kubernetes pod annotation
annotations:
  spiffe.io/spiffe-id: "spiffe://company.com/ns/prod/sa/ai-worker"
```

The pod exchanges its SPIFFE SVID for a tsidp token, then accesses setec.

### 3. MCP Gateway Pattern

For complex deployments with multiple MCP servers, tsidp enables secure delegation:

```
Claude Code → MCP Gateway → tsidp (STS exchange) → Backend MCP Servers
                                ↓
                            setec (credentials for backends)
```

### 4. Ephemeral Developer Environments

Codespaces/Gitpod can authenticate via GitHub → tsidp → setec:

```
GitHub OIDC → tsidp token exchange → setec access token → AI tool credentials
```

---

## Revised Implementation Roadmap

### Phase 1: Foundation (3-4 weeks)

| Task | Owner | Notes |
|------|-------|-------|
| Deploy tsidp alongside setec | Ops | Docker Compose setup |
| Add OIDC token validation to setec | Backend | Support both Tailscale and OIDC auth |
| `setec exec` with profile support | CLI | Environment injection |
| Basic MCP server | CLI | Stdio transport, Tailscale auth |

### Phase 2: OAuth Integration (3-4 weeks)

| Task | Owner | Notes |
|------|-------|-------|
| OAuth-aware MCP server | Backend | HTTP transport, tsidp auth |
| Token scope enforcement | Backend | Map scopes to ACLs |
| Claude Code integration docs | Docs | Configuration examples |
| DCR support for setec MCP | Backend | RFC 7591 compliance |

### Phase 3: Advanced Patterns (4-5 weeks)

| Task | Owner | Notes |
|------|-------|-------|
| STS token exchange integration | Backend | Session-scoped tokens |
| Enhanced audit with OAuth context | Backend | Token claims in audit entries |
| Rate limiting per token | Backend | Prevent bulk extraction |
| Anomaly detection | Backend | Unusual access patterns |

### Phase 4: Enterprise Features (4-6 weeks)

| Task | Owner | Notes |
|------|-------|-------|
| External IdP federation | Backend | Token exchange from Okta/Azure AD |
| Kubernetes workload identity | Backend | SPIFFE integration |
| MCP gateway support | Backend | Multi-backend delegation |
| Compliance reporting | Backend | SOC2/GDPR audit exports |

---

## Trade-offs: tsidp Integration

| Aspect | Without tsidp | With tsidp |
|--------|---------------|------------|
| **Auth complexity** | Simple (Tailscale only) | More moving parts |
| **Token lifetime** | N/A (session-based) | Configurable (1h-24h) |
| **External access** | Requires Tailscale | Token exchange enables federation |
| **MCP compliance** | Custom implementation | Standards-compliant |
| **Audit granularity** | IP + Tailscale ID | Full OAuth claims + scopes |
| **Ops overhead** | One service | Two services |

**Recommendation:** Start with Tailscale-only auth (current setec model), add tsidp integration as an optional enhancement for teams needing:
- MCP-native authentication
- External collaborator access
- Fine-grained token scoping
- Compliance requirements

---

## References

- [tsidp GitHub Repository](https://github.com/tailscale/tsidp)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [How Tailscale can make secure MCP access with DCR easier](https://tailscale.com/blog/dynamic-client-registration-dcr-for-mcp-ai)
- [OAuth 2.0 Token Exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693)
- [Dynamic Client Registration (RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591)
- [MCP Specs Update: All About Auth (Auth0)](https://auth0.com/blog/mcp-specs-update-all-about-auth/)
