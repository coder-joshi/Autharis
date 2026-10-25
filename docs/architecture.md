# Autharis Architecture

## 1. Purpose

This document describes the architectural principles, system boundaries, major components, and design decisions governing Autharis.

Autharis is a self-hostable identity provider intended to provide centralized identity and authentication infrastructure to applications through standardized protocols.

The architecture should prioritize security, maintainability, explicit boundaries, and interoperability while avoiding unnecessary complexity during early development.

This document describes the intended architecture. Implementation details may evolve as the project develops.

## 2. Architectural Principles

### 2.1 Identity Provider, Not an Authentication Library

Autharis is an identity provider rather than a library that applications embed to implement their own authentication.

Applications integrate with an Autharis instance and delegate supported authentication operations to it.

Autharis is responsible for managing the identity-provider side of the authentication process, including registered clients, authentication flows, token issuance, and relevant identity information.

Applications remain responsible for validating tokens appropriately and enforcing authorization within their own resources.

### 2.2 Modular Monolith

Autharis will initially use a modular monolith architecture.

The application will run as a single deployable service while its internal responsibilities are separated into well-defined modules.

This approach provides:

- Straightforward local development and deployment.
- Clear separation of responsibilities.
- Simpler transactions and data access.
- Lower operational complexity than a distributed architecture.
- The ability to evolve module boundaries as requirements grow.

Modules should communicate through explicit interfaces rather than depending unnecessarily on one another's internal implementation.

Microservices are not an initial requirement.

### 2.3 Standards-Based Protocols

Autharis will implement authentication and authorization using established standards.

The primary protocols are:

- OAuth 2.0 for delegated authorization.
- OpenID Connect for authentication and identity claims.
- Authorization Code Flow with PKCE for applicable client types.

Protocol behavior must follow the relevant specifications rather than introducing proprietary alternatives.

Relevant specifications should be consulted during implementation and testing.

### 2.4 Separation of Protocols and HTTP Routing

OAuth 2.0 and OpenID Connect protocol handling must remain separate from Express HTTP routing.

HTTP route handlers should handle transport-level responsibilities, including:

- Receiving HTTP requests.
- Parsing and validating request parameters.
- Calling the appropriate application service.
- Translating application results into HTTP responses.

Protocol services should implement the actual authorization, authentication, token, and validation rules.

This separation makes protocol logic easier to test independently and reduces the risk of security-sensitive behavior becoming scattered across route handlers.

### 2.5 Persistent Data

PostgreSQL will be the primary persistent datastore.

Drizzle ORM will manage database interactions, schema definitions, and migrations.

Persistent entities are expected to include users, registered clients, authorization codes, sessions, and token-related records where persistence is required.

The final schema and persistence requirements will depend on the implementation and security model.

Database access should be centralized within appropriate data-access components rather than duplicated throughout the application.

### 2.6 Established Cryptographic Libraries

Cryptographic operations must use established libraries rather than custom cryptographic implementations.

The project intends to use `jose` for appropriate JOSE operations, including JWT signing and verification.

Signing keys will be generated using a Bash script and suitable cryptographic tooling.

Private keys must remain protected and must never be exposed through public endpoints, committed to version control, or included in application logs.

Key generation, loading, rotation, and verification must have explicit responsibilities and well-defined failure behavior.

## 3. High-Level Architecture

The intended architecture consists of the following layers:

```text
                    Client Applications
                            |
                            | OIDC / OAuth 2.0
                            |
                            v
                 +-----------------------+
                 |    Express Server     |
                 |                       |
                 | HTTP Routing Layer    |
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 |  Protocol and API     |
                 |      Layer            |
                 |                       |
                 | Authorization         |
                 | Token Endpoints       |
                 | Discovery / JWKS      |
                 | UserInfo               |
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 |   Application Layer   |
                 |                       |
                 | Identity Services     |
                 | Client Services       |
                 | Session Services      |
                 | Token Services        |
                 | Key Management        |
                 +-----------+-----------+
                             |
                  +----------+----------+
                  |                     |
                  v                     v
        +------------------+  +------------------+
        | Persistence Layer|  | Cryptographic    |
        |                  |  | Operations       |
        | Drizzle ORM      |  |                  |
        | PostgreSQL       |  | jose             |
        +------------------+  +------------------+
```

This diagram represents logical responsibilities, not separate processes or independently deployed services.

The exact module boundaries may change as the implementation develops.

## 4. Core Modules

### 4.1 Identity Module

Responsible for managing user identity records and the operations required to retrieve and update identity information.

Expected responsibilities include:

- Defining the user identity model.
- Retrieving identity records.
- Supporting identity-related application services.
- Exposing appropriate identity claims to authorized protocol operations.

Identity records must not automatically expose every stored field to client applications.

The information returned to clients must be limited to the claims and attributes they are permitted to receive.

### 4.2 Client Management Module

Responsible for registered applications that integrate with Autharis.

Expected responsibilities include:

- Creating and retrieving client registrations.
- Validating client configuration.
- Managing redirect URI configuration.
- Distinguishing public and confidential clients.
- Handling confidential-client credentials where applicable.

Client validation must be enforced server-side.

Public clients must not be treated as confidential merely because they provide a client identifier or embed a static secret in distributed code.

### 4.3 Authorization Module

Responsible for authorization requests and the creation and validation of authorization codes.

Expected responsibilities include:

- Validating authorization requests.
- Checking registered client configuration.
- Validating redirect URIs.
- Processing applicable PKCE parameters.
- Issuing short-lived, single-use authorization codes.
- Enforcing authorization-code expiration and consumption rules.

Authorization codes must be bound to the relevant client and authorization request context.

They must not be reusable after successful redemption.

### 4.4 Authentication Module

Responsible for authenticating users and establishing the identity context required by supported authentication flows.

Expected responsibilities include:

- Validating user authentication attempts.
- Establishing authenticated user context.
- Integrating with session management.
- Communicating authentication outcomes to the protocol layer.

User authentication must be implemented with appropriate credential protection and abuse controls.

### 4.5 Token Module

Responsible for token issuance and validation-related operations.

Expected responsibilities include:

- Issuing ID tokens for supported OIDC flows.
- Issuing access tokens where appropriate.
- Managing refresh-token behavior when implemented.
- Applying expiration and claim requirements.
- Coordinating signing and verification operations.
- Supporting token revocation or invalidation mechanisms where applicable.

ID tokens and access tokens serve different purposes and must not be treated as interchangeable.

Token validation requirements depend on the token type and its intended recipient.

### 4.6 Session Module

Responsible for managing authenticated sessions.

Expected responsibilities include:

- Creating and validating sessions.
- Applying session expiration.
- Invalidating sessions when required.
- Associating sessions with the relevant user.
- Enforcing secure cookie and session-handling policies where applicable.

Session identifiers must be sufficiently unpredictable and protected against unauthorized access.

Session lifecycle rules must be explicit rather than being scattered across route handlers.

### 4.7 Cryptographic Key Management

Responsible for loading and managing the keys used for signing and verification.

Expected responsibilities include:

- Supporting locally generated signing keys.
- Loading private keys from protected storage.
- Exposing only appropriate public verification material.
- Managing signing-key identifiers.
- Supporting key rotation as the system evolves.
- Failing safely when key configuration is invalid.

Private-key access should be limited to components that genuinely require it.

Public key publication must not disclose private key material.

### 4.8 Configuration Module

Responsible for validating environment configuration and application settings.

Zod will be used to validate configuration at runtime.

Invalid or missing required configuration should cause a clear startup failure rather than leaving the application partially configured.

Secrets must not be included in error messages or diagnostic output.

### 4.9 Persistence Module

Responsible for database interactions through PostgreSQL and Drizzle ORM.

Expected responsibilities include:

- Defining database schemas.
- Managing migrations.
- Encapsulating data-access operations.
- Supporting transactional operations where required.
- Enforcing relevant persistence constraints.

Database constraints should complement application-level validation.

Security-sensitive operations that involve multiple database changes should be designed with appropriate transactional guarantees.

## 5. Request Flow

A typical OIDC authentication flow is expected to follow this sequence:

1. A client application redirects the user to Autharis's authorization endpoint.
2. Autharis validates the authorization request and registered client configuration.
3. Autharis authenticates the user when necessary.
4. Autharis establishes the appropriate authentication and authorization context.
5. Autharis issues an authorization code bound to the relevant request.
6. The client exchanges the authorization code at the token endpoint.
7. Autharis validates the code, client requirements, and PKCE proof where applicable.
8. Autharis issues the appropriate tokens.
9. The client validates the tokens according to the relevant protocol requirements.
10. The client establishes its own application session as appropriate.

The exact behavior depends on the client type, configured flow, and protocol requirements.

## 6. Planned HTTP Endpoints

The following endpoints represent the intended protocol surface.

| Endpoint | Purpose |
|---|---|
| `/authorize` | Initiate an authorization request. |
| `/token` | Exchange authorization codes and handle supported token requests. |
| `/.well-known/openid-configuration` | Publish OpenID Provider metadata. |
| `/jwks` | Publish public signing-key information in JWKS format. |
| `/userinfo` | Return authorized identity claims. |

These paths are provisional and may be adjusted to follow the final endpoint configuration and protocol requirements.

Additional endpoints may be introduced for session management, client administration, health checks, and other operational needs.

Only implemented and tested endpoints should be documented as currently available.

## 7. Data Model

PostgreSQL will store persistent application data.

The initial logical entities are expected to include:

- Users.
- Registered clients.
- Authorization codes.
- Sessions.
- Refresh tokens or other persistent token records where required.
- Supporting records for key metadata or administrative operations where appropriate.

Not every token must necessarily be stored as a persistent record. Storage decisions must consider token type, revocation requirements, security, and operational needs.

Sensitive values should be minimized, protected, and retained only for as long as required.

The final database schema will be documented separately as it is implemented.

## 8. Security Boundaries

Security-sensitive operations must have explicit boundaries.

In particular:

- Route handlers must not independently implement cryptographic signing.
- Authorization-code validation must not be bypassed by direct service calls.
- Client credentials must not be exposed in public API responses.
- Private signing keys must never be returned by HTTP endpoints.
- Token claims must be validated according to the relevant protocol.
- Redirect URIs must be validated against registered client configuration.
- User identity data must be filtered before being returned to clients.
- Administrative operations must enforce appropriate authorization.

These requirements apply regardless of whether an operation is invoked through an HTTP endpoint or an internal application service.

## 9. Testing Strategy

The project will use Vitest for automated tests and Supertest for HTTP-level testing.

Testing should cover:

- Unit tests for protocol and application services.
- Validation of malformed and incomplete requests.
- Authorization-code expiration and replay attempts.
- PKCE verification.
- Client authentication requirements.
- Token claims and expiration.
- Session lifecycle behavior.
- Unauthorized administrative access.
- Database constraints and transactional behavior.
- Integration tests for supported authentication flows.

Successful authentication is only one part of testing. Invalid requests, expired credentials, unauthorized access, and other failure paths must also be covered.

## 10. Deployment

Autharis is intended to be self-hostable.

Docker Compose is planned to support a reproducible deployment environment, including the application and PostgreSQL where appropriate.

Deployment documentation should explain:

- Required environment variables.
- Database initialization and migrations.
- Signing-key generation and storage.
- Persistent database storage.
- Network exposure and TLS requirements.
- Secret management.
- Backups and recovery.
- Upgrade procedures.

Development configuration must remain separate from production configuration.

Production deployment must not depend on insecure defaults or development-only credentials.

## 11. Architectural Evolution

The modular monolith is the initial architecture, not a commitment to preserve every internal boundary indefinitely.

Module boundaries may be refined as requirements become clearer.

Any substantial architectural change should include an explanation of the problem being addressed, alternatives considered, trade-offs, and consequences.

Security-sensitive changes should receive additional review and appropriate automated testing.

## 12. Current Status

This document describes the intended architecture.

A design decision or planned module must not be interpreted as evidence that the corresponding implementation is complete.

As Autharis develops, this document should be updated to reflect meaningful changes to architecture, security boundaries, and implementation decisions.