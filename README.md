# Autharis

**Your identity infrastructure. Your control.**

Autharis is a self-hostable identity and authentication platform that gives developers control over how their applications manage users, logins, and identity.

The project aims to make identity infrastructure easier to build, deploy, and maintain by providing a standards-based foundation for authentication and authorization.

Rather than requiring every application to implement its own identity system, Autharis aims to provide a centralized identity provider that applications can integrate with using established protocols such as OpenID Connect (OIDC) and OAuth 2.0.

> **Project status:** Early development. Autharis is not production-ready. Features and APIs are subject to change.

## Why Autharis?

Authentication is a fundamental component of modern applications, but implementing it securely requires careful handling of identities, sessions, tokens, cryptographic keys, and authorization flows.

Developers often rely on managed identity services or build authentication systems themselves. While managed services simplify development, they can introduce external dependencies, pricing constraints, and limitations on infrastructure control. Building everything independently requires significant time and security expertise.

Autharis aims to provide an alternative: **identity infrastructure that developers can self-host and control.**

### Project goals

- **Self-hostable:** Run identity infrastructure on infrastructure you control.
- **Standards-based:** Build around established identity and authorization protocols.
- **Developer-focused:** Make integration, configuration, and operation straightforward.
- **Security-conscious:** Treat secure authentication, key management, and token handling as core requirements.
- **Extensible:** Maintain a modular architecture that can evolve alongside the project.
- **Transparent:** Keep implementation decisions and operational requirements documented.

These are project goals, not claims that every capability is already implemented.

## Intended Audience

Autharis is being developed for:

- Developers building web applications and APIs.
- Teams seeking greater control over their authentication infrastructure.
- Self-hosting enthusiasts who prefer operating their own services.
- Developers exploring identity providers, OIDC, and OAuth 2.0.

## Planned Features

The following capabilities represent the project's intended direction. Their implementation status will evolve as development progresses.

| Feature                           | Description                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------ |
| Identity management               | Manage user identities and associated information.                                   |
| Client registration               | Register applications that integrate with Autharis.                                  |
| OpenID Connect                    | Enable standardized user authentication for compatible applications.                 |
| Authorization Code Flow with PKCE | Support a modern authorization flow for public clients and other applicable clients. |
| Provider discovery                | Publish provider configuration through a standard discovery endpoint.                |
| JWKS endpoint                     | Expose public signing keys for token verification.                                   |
| ID tokens                         | Communicate authenticated user identity to OIDC clients.                             |
| UserInfo endpoint                 | Provide identity claims to authorized clients.                                       |
| Session management                | Establish and manage authenticated user sessions.                                    |
| Token lifecycle management        | Handle token issuance, expiration, renewal, and revocation where applicable.         |
| Management interface              | Provide tools for managing users, clients, and provider configuration.               |
| Self-hosted deployment            | Document deployment, configuration, upgrades, and operational procedures.            |

Only features that have been implemented and tested should be described as available.

## Technology

Autharis currently uses the following development stack.

| Component                            | Technology            |
| ------------------------------------ | --------------------- |
| Language                             | TypeScript            |
| Runtime                              | Node.js               |
| HTTP framework                       | Express 5             |
| Request and configuration validation | Zod                   |
| Environment configuration            | dotenv                |
| HTTP security headers                | Helmet                |
| Database                             | PostgreSQL (planned)  |
| ORM                                  | Drizzle ORM (planned) |
| Testing                              | Vitest and Supertest  |
| Linting                              | ESLint                |
| Formatting                           | Prettier              |
| Development execution                | tsx                   |

The database and ORM are part of the intended architecture; they are not listed among the current dependencies in `package.json`.

## Architecture

Autharis is intended to follow a **modular monolith architecture**.

The application will initially run as a single deployable service, with responsibilities separated into modules. This keeps development and deployment manageable without prematurely introducing the operational complexity of microservices.

Planned architectural boundaries include:

- **Identity:** User identities and associated data.
- **Clients:** Applications registered with the identity provider.
- **Authorization:** Authorization requests, consent where applicable, and authorization codes.
- **Tokens:** Token issuance, signing, validation, and lifecycle management.
- **Sessions:** Authenticated session creation and management.
- **Configuration:** Environment configuration and validation.
- **Database:** Persistence, schema definitions, and migrations.
- **Security:** Cryptographic key management and security-sensitive operations.

These boundaries describe the intended architecture and may change as implementation progresses.

## Getting Started

### Prerequisites

Before setting up Autharis, install:

- Node.js and npm.
- Git.
- Bash and OpenSSL for the planned signing-key generation workflow.

PostgreSQL will also be required once database integration is implemented.

### 1. Clone the repository

```bash
git clone https://github.com/coder-joshi/Autharis.git
cd Autharis
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create a local `.env` file using the project's example configuration, if available:

```bash
cp .env.example .env
```

Configure the variables required by the current implementation.

Never commit environment files containing credentials, secrets, or other sensitive configuration.

### 4. Start the development server

```bash
npm run dev
```

This executes the configured development command:

```bash
tsx watch apps/server/src/server.ts
```

The server restarts automatically when watched files change.

### 5. Run type checking

```bash
npm run typecheck
```

This runs the TypeScript compiler without emitting output.

### 6. Build the project

```bash
npm run build
```

This invokes the TypeScript compiler using the repository's `tsconfig.json`.

### 7. Run the tests

```bash
npm test
```

To run tests in watch mode:

```bash
npm run test:watch
```

### 8. Lint the codebase

```bash
npm run lint
```

### 9. Check formatting

```bash
npm run format:check
```

To format the codebase:

```bash
npm run format
```

**Note:** These commands are configured in `package.json`. Their successful execution depends on the corresponding configuration files and implementation being in place.

## Development Roadmap

Autharis is being developed incrementally, with an emphasis on establishing a reliable foundation before expanding its identity capabilities.

### Phase 1 — Project foundation

- Establish the repository structure.
- Configure TypeScript and development tooling.
- Set up environment configuration and validation.
- Establish linting, formatting, and testing conventions.
- Introduce continuous integration.
- Document architectural decisions.

### Phase 2 — Database and cryptographic foundations

- Integrate PostgreSQL and Drizzle ORM.
- Define the initial database schema.
- Establish versioned database migrations.
- Implement signing-key generation and loading.
- Define secure key storage and configuration practices.

### Phase 3 — Identity and client management

- Define user and identity models.
- Implement client registration and persistence.
- Establish validation and error-handling conventions.
- Build authentication and session foundations.

### Phase 4 — Core authorization flow

- Implement the authorization endpoint.
- Add Authorization Code Flow with PKCE.
- Validate client configuration and redirect URIs.
- Implement authorization-code issuance and validation.
- Introduce the token endpoint.

### Phase 5 — OpenID Connect

- Implement provider discovery.
- Publish the JWKS endpoint.
- Issue and validate ID tokens.
- Implement the UserInfo endpoint.
- Validate token claims and protocol requirements.

### Phase 6 — Sessions and token lifecycle

- Define session expiration and invalidation.
- Implement refresh-token handling where applicable.
- Add replay protection and relevant abuse controls.
- Establish signing-key rotation procedures.

### Phase 7 — Management interface

- Develop a management dashboard.
- Add user and client administration.
- Expose relevant configuration and operational information.

### Phase 8 — Security and deployment

- Document the threat model.
- Expand unit and integration test coverage.
- Test protocol conformance and security boundaries.
- Review secret handling and key rotation.
- Document deployment, backups, upgrades, and recovery.
- Establish production-readiness criteria.

This roadmap represents planned work, not a declaration that the listed features are complete.

## Security

Security is a core requirement for identity infrastructure.

Autharis aims to follow these principles:

- Use established authentication and authorization standards.
- Validate redirect URIs and client configuration.
- Protect authorization codes, tokens, sessions, and signing keys.
- Avoid logging credentials or sensitive token contents.
- Apply appropriate expiration and replay-prevention controls.
- Separate private signing keys from publicly accessible verification keys.
- Document security-sensitive configuration and deployment requirements.
- Test unauthorized access paths and failure cases.

Autharis is currently under development and should not be relied upon as a production identity provider until its implementation has undergone appropriate security review and testing.

### Reporting vulnerabilities

If you identify a security vulnerability, report it privately to the project maintainers rather than publicly disclosing exploitable details before a fix is available.

A dedicated security reporting process can be established as the project matures.

## Documentation

Architecture and implementation decisions will be documented in the `docs/` directory.

Planned documents include:

- `docs/architecture.md` — System architecture and module boundaries.
- `docs/threat-model.md` — Security assumptions, threats, and mitigations.
- `docs/decisions/0001-modular-monolith.md` — Rationale for the modular monolith architecture.

Additional documentation will cover protocol behavior, configuration, deployment, and operations as those capabilities are implemented.

## Contributing

Autharis is in early development, and its architecture and interfaces may change.

Potential contributions include:

- Bug reports and reproducible test cases.
- Documentation improvements.
- Protocol and security reviews.
- Automated tests.
- Implementation improvements.
- Deployment and operational guidance.

Before contributing, review the existing issues and repository conventions.

Contribution guidelines will be expanded as the project establishes its development workflow.

## License

Autharis is licensed under the MIT License.

See the [`LICENSE`](LICENSE) file for the complete license text.

## Project Status

Autharis is an early-stage project focused on building a self-hostable, standards-based identity provider.

The immediate priority is to establish a maintainable foundation, implement the core authentication and authorization flows, and validate the security properties of the system before pursuing production deployments.

The long-term goal is to make identity infrastructure easier for developers to understand, operate, and control.

---

**Repository:** [coder-joshi/Autharis](https://github.com/coder-joshi/Autharis)
