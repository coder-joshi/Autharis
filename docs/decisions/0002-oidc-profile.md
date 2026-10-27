# 0002: OIDC profile

## Status
Accepted

## Context
A smaller, strict profile means a smaller attack surface and a discovery document that is
easy to keep truthful.

## Decision
| Topic | Decision |
|---|---|
| Flows | Authorization Code only. No implicit, hybrid, request objects, claims parameter or dynamic registration |
| PKCE | S256 only, required for every client by default; plain is rejected |
| ID token signing | RS256, RSA 3072, kid = RFC 7638 thumbprint |
| Access tokens | Opaque, 10 minutes, SHA-256 hash stored |
| ID tokens | 10 minutes |
| Refresh tokens | Only with offline_access; rotated on every use; reuse revokes the whole family; 30-day absolute life |
| Sessions | Opaque random id, hash stored, HttpOnly, SameSite=Lax, idle 2 h, absolute 12 h |
| Subject (sub) | users.id (UUID), subject type public |
| Passwords | Argon2id (19 MiB, t=2, p=1), NFKC-normalized, 12 to 128 characters |
| Issuer | Origin only, no trailing slash, https in production |
| Client secrets | 32 random bytes, SHA-256 stored, shown once |

## Consequences
Discovery must advertise exactly this profile and nothing more.