# 0003: Token formats

## Status
Accepted

## Context
Tokens need to be revocable and short-lived, and UserInfo is the only resource server in scope.

## Decision
- Access tokens are opaque (revocable instantly).
- ID tokens are JWTs.
- Refresh tokens rotate and are issued only with offline_access.

## Consequences
Token introspection will be needed if a separate resource server is added later.