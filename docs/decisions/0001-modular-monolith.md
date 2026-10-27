# 0001: Modular monolith

## Status

Accepted

## Context

Autharis needs to be easy to deploy and reason about, while keeping identity, clients, sessions,
OAuth, OIDC and tokens separated.

## Decision

One deployable process. Module boundaries are enforced by the module rule: a module may import
another module's service, never its repository. Protocol code never imports Express.

## Consequences

Simple deploys now. Modules can be extracted into separate services later if needed.
