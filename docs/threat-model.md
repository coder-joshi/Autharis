# Autharis Threat Model

## 1. Purpose

This document identifies the assets, trust boundaries, potential attackers, and security threats relevant to Autharis.

Autharis is a self-hostable identity provider designed to authenticate users and provide identity and authorization capabilities to client applications through established protocols.

Because the system will handle authentication credentials, authorization codes, tokens, signing keys, and administrative operations, security must be considered throughout the design and implementation process.

This document establishes an initial threat model. It is not a security audit, penetration-test report, or guarantee that the implementation is secure.

The model must be updated as features, deployment assumptions, and attack surfaces evolve.

## 2. Security Objectives

Autharis should preserve the following properties.

### 2.1 Confidentiality

Prevent unauthorized disclosure of:

- User credentials and authentication material.
- Authorization codes and access tokens.
- Refresh tokens and session identifiers.
- Private signing keys.
- Confidential-client credentials.
- Sensitive user information.
- Administrative credentials and configuration secrets.

### 2.2 Integrity

Prevent unauthorized modification of:

- User identity records.
- Client registrations.
- Redirect URI configuration.
- Authorization decisions.
- Token claims and signing material.
- Session state.
- Administrative configuration.

### 2.3 Authentication Assurance

Ensure that an authenticated identity is established through the intended authentication process and cannot be impersonated merely by manipulating request parameters or client-supplied data.

### 2.4 Authorization Enforcement

Ensure that only appropriately authorized users, clients, and administrators can perform protected operations.

### 2.5 Protocol Correctness

Ensure that authorization requests, authorization codes, tokens, and identity claims are processed according to the applicable OAuth 2.0 and OpenID Connect requirements.

### 2.6 Availability

Reduce the likelihood that malicious or excessive requests prevent legitimate users and client applications from using the service.

Availability protections must account for resource-intensive requests, authentication abuse, database load, and administrative recovery.

## 3. Assets to Protect

The following assets require explicit protection.

| Asset | Security concern |
|---|---|
| User credentials | Account compromise and impersonation. |
| User identity data | Unauthorized disclosure or modification. |
| Authorization codes | Unauthorized token issuance through code theft or replay. |
| Access tokens | Unauthorized access to protected resources. |
| Refresh tokens | Unauthorized acquisition of replacement tokens. |
| Signing keys | Forged tokens and compromise of token trust. |
| Confidential-client secrets | Unauthorized client authentication. |
| User sessions | Session hijacking and unauthorized account access. |
| Client registrations | Malicious redirects and client impersonation. |
| Redirect URI configuration | Authorization-code or token leakage. |
| Administrative privileges | Unauthorized control over users and clients. |
| Database credentials | Unauthorized access to persistent application data. |
| Environment secrets | Compromise of application and infrastructure security. |
| Audit and security logs | Loss of investigation capability or exposure of sensitive information. |

The system must protect both the assets themselves and the operations that create, validate, modify, and revoke them.

## 4. Trust Boundaries

### 4.1 Client Applications and Autharis

Client applications are separate security principals.

Autharis must not assume that a client is trustworthy merely because it has a registered client identifier.

Client configuration, redirect URIs, authentication requirements, and authorization requests must be validated.

### 4.2 Users and the Authorization Endpoint

Authorization requests contain attacker-controllable input.

Parameters such as client identifiers, redirect URIs, scopes, state values, and PKCE parameters must be validated according to the applicable protocol requirements.

User authentication and authorization decisions must not rely solely on values supplied by the client.

### 4.3 HTTP Layer and Application Services

Express route handlers receive untrusted requests.

They must validate request data and invoke application services through defined interfaces.

Security-sensitive operations must enforce their own required invariants rather than assuming every caller has performed the necessary checks.

### 4.4 Application and Database

The application communicates with PostgreSQL using configured database credentials.

Database access must be restricted to the required permissions and network boundaries.

Database constraints and transactions should reinforce application-level security controls.

### 4.5 Application and Cryptographic Keys

Private signing keys must be accessible only to authorized application components and operational processes.

Public verification keys may be published when appropriate, but private key material must never cross the public API boundary.

### 4.6 Application and Deployment Environment

The application depends on its runtime environment, environment variables, file permissions, network configuration, and deployment infrastructure.

A compromised host or deployment account may undermine otherwise correct application-level controls.

Self-hosting documentation must clearly communicate these operational risks.

## 5. Threat Actors

The initial threat model considers the following actors.

### 5.1 Unauthenticated External Attacker

An attacker who can send requests to publicly exposed endpoints without having an account or registered client.

Potential objectives include exploiting input-validation flaws, discovering sensitive information, abusing authentication flows, or exhausting resources.

### 5.2 Malicious or Compromised Client

A client application that is malicious, compromised, incorrectly configured, or attempting to bypass protocol requirements.

Potential objectives include obtaining tokens improperly, redirecting authorization responses, or accessing claims beyond the intended permissions.

### 5.3 Malicious Authenticated User

An authenticated user attempting to access another user's information, abuse session behavior, or perform operations outside their permissions.

### 5.4 Compromised Administrator Account

An attacker with access to an administrative account may be able to modify client registrations, change configuration, or access sensitive identity-management operations.

Administrative access therefore requires strong protection and appropriate auditing.

### 5.5 Host or Deployment Compromise

An attacker who gains access to the server, deployment environment, filesystem, or database credentials may bypass application-level protections.

This threat requires operational safeguards in addition to application security controls.

## 6. Threats and Mitigations

### 6.1 Credential Theft and Account Compromise

**Threat**

An attacker obtains a user's credentials through brute-force attacks, credential stuffing, phishing, insecure storage, or accidental disclosure.

**Potential impact**

Unauthorized access to user accounts and the ability to initiate authentication flows as the victim.

**Planned mitigations**

- Use an established password-hashing algorithm and library if password authentication is implemented.
- Never store plaintext passwords.
- Apply rate limiting and appropriate abuse controls to authentication endpoints.
- Return generic authentication failure messages where appropriate.
- Protect authentication requests with TLS in deployed environments.
- Avoid logging passwords or credential material.
- Establish secure credential-reset and account-recovery procedures before exposing these features.

**Verification**

Test password-storage behavior where applicable, authentication rate limits, invalid credential handling, and recovery-flow security.

### 6.2 Authorization-Code Theft and Replay

**Threat**

An attacker obtains an authorization code and attempts to exchange it for tokens or redeem it more than once.

**Potential impact**

Unauthorized token issuance and possible account impersonation.

**Planned mitigations**

- Generate authorization codes using cryptographically secure randomness.
- Apply short expiration periods.
- Bind codes to the relevant client and authorization request.
- Enforce PKCE where required by the selected flow.
- Ensure authorization codes are single-use.
- Atomically validate and consume codes to prevent concurrent replay.
- Avoid placing authorization codes in application logs.

**Verification**

Test expired codes, incorrect PKCE verifiers, mismatched clients, repeated redemption, and concurrent redemption attempts.

### 6.3 Malicious Redirect URI

**Threat**

An attacker attempts to register or use an unauthorized redirect URI to capture an authorization response.

**Potential impact**

Authorization-code theft, token leakage, or account compromise.

**Planned mitigations**

- Validate redirect URIs against the registered client's configuration.
- Avoid unsafe wildcard matching.
- Apply the redirect URI comparison rules required by the relevant protocol and client-registration policy.
- Reject invalid redirect URIs before issuing authorization responses.
- Never redirect to an arbitrary attacker-supplied URI following an authentication failure.

**Verification**

Test unregistered redirect URIs, lookalike domains, unexpected ports, path variations, and malformed URI inputs.

### 6.4 PKCE Downgrade or Bypass

**Threat**

An attacker attempts to bypass PKCE validation or exploit a client flow that does not enforce the required code challenge.

**Potential impact**

Unauthorized authorization-code redemption.

**Planned mitigations**

- Implement PKCE according to the applicable specification.
- Support the appropriate challenge methods, including `S256`.
- Bind the authorization-code record to the original challenge.
- Verify the submitted code verifier during redemption.
- Reject invalid or missing PKCE parameters when required.
- Avoid silently weakening security requirements for convenience.

**Verification**

Test missing challenges, unsupported methods, incorrect verifiers, and attempts to redeem codes under different client contexts.

### 6.5 Token Forgery and Invalid Token Acceptance

**Threat**

An attacker submits a forged, expired, incorrectly signed, or otherwise invalid token.

**Potential impact**

Unauthorized access to protected resources or acceptance of an untrusted identity.

**Planned mitigations**

- Use established JOSE libraries for applicable signing and verification operations.
- Explicitly allow only supported signing algorithms.
- Validate issuer, audience, expiration, and other required claims.
- Reject unsigned tokens where signatures are required.
- Validate token type and intended use.
- Keep private signing keys protected.
- Use stable key identifiers and appropriate key-management procedures.

**Verification**

Test invalid signatures, expired tokens, unexpected issuers and audiences, unsupported algorithms, and missing required claims.

### 6.6 Signing-Key Compromise

**Threat**

An attacker obtains a private signing key through filesystem access, leaked environment configuration, source control, logs, or a compromised deployment.

**Potential impact**

The attacker may be able to create tokens that relying parties accept as authentic.

**Planned mitigations**

- Generate keys using established cryptographic tooling.
- Store private keys outside the public source tree.
- Exclude local development keys from version control.
- Restrict filesystem permissions.
- Never expose private keys through HTTP endpoints.
- Avoid logging key material.
- Establish key rotation and compromised-key response procedures.
- Keep public verification material separate from private signing material.

**Verification**

Review file permissions, repository exclusions, key-loading behavior, and the response to missing or invalid key configuration.

### 6.7 Confidential-Client Secret Exposure

**Threat**

A confidential-client secret is disclosed through source control, logs, API responses, or insecure storage.

**Potential impact**

An attacker may impersonate the affected client where the protocol permits client-secret authentication.

**Planned mitigations**

- Store client secrets securely.
- Avoid returning secret material in client-management responses.
- Do not embed confidential-client secrets in browser applications or distributed mobile code.
- Validate client authentication at the token endpoint where required.
- Consider storing a suitable verifier or hash rather than a recoverable plaintext secret.
- Support secret rotation and revocation as client-management capabilities develop.

**Verification**

Test that secrets are not exposed in responses, logs, or ordinary database query results and that invalid client credentials are rejected.

### 6.8 Session Hijacking and Fixation

**Threat**

An attacker obtains or manipulates a session identifier to gain access to an authenticated session.

**Potential impact**

Unauthorized use of a victim's authenticated identity.

**Planned mitigations**

- Generate unpredictable session identifiers.
- Apply appropriate cookie attributes, including `HttpOnly`, `Secure` in HTTPS deployments, and a suitable `SameSite` policy.
- Rotate session identifiers after authentication or other relevant privilege changes.
- Enforce session expiration and invalidation.
- Protect state-changing browser operations against cross-site request forgery where applicable.
- Avoid exposing session identifiers in URLs or logs.

**Verification**

Test session rotation, expiration, invalidation, cookie configuration, and unauthorized session reuse.

### 6.9 Cross-Site Request Forgery

**Threat**

An attacker causes a user's browser to submit an unintended state-changing request to Autharis.

**Potential impact**

Unintended account changes, administrative actions, or authentication-related state changes.

**Planned mitigations**

- Apply appropriate CSRF protections to browser-based state-changing operations.
- Use appropriate cookie policies.
- Validate request origins where suitable.
- Avoid relying on `SameSite` alone for every CSRF threat.
- Distinguish protocol-required browser redirects from ordinary state-changing application requests.

**Verification**

Test cross-origin state-changing requests and ensure that applicable protections reject unauthorized operations.

### 6.10 Cross-Site Scripting

**Threat**

Attacker-controlled content executes JavaScript in an Autharis browser origin.

**Potential impact**

Exposure of accessible application data, abuse of authenticated browser sessions, or unauthorized user actions.

**Planned mitigations**

- Escape untrusted content in rendered interfaces.
- Avoid unsafe HTML insertion.
- Apply an appropriate Content Security Policy.
- Use security headers through Helmet where appropriate.
- Validate input without treating validation as a substitute for output encoding.
- Avoid unnecessarily exposing sensitive values to browser JavaScript.

**Verification**

Test user-controlled content and ensure that it cannot execute as active script in application interfaces.

### 6.11 SQL Injection and Database Abuse

**Threat**

An attacker manipulates request input to alter database queries or access unauthorized records.

**Potential impact**

Unauthorized disclosure, modification, or deletion of persistent data.

**Planned mitigations**

- Use Drizzle ORM and safe parameterized database operations.
- Avoid concatenating untrusted input into SQL statements.
- Validate incoming request data with Zod.
- Apply least-privilege database permissions.
- Enforce appropriate database constraints.
- Avoid exposing database errors or query details to clients.

**Verification**

Test malformed inputs, boundary cases, and unauthorized data access. Review raw SQL usage carefully.

### 6.12 Broken Authorization and Privilege Escalation

**Threat**

A user or client accesses administrative functionality or another user's data without appropriate authorization.

**Potential impact**

Unauthorized user management, client modification, identity disclosure, or complete compromise of the identity provider.

**Planned mitigations**

- Enforce authorization on every protected operation.
- Distinguish authentication from authorization.
- Apply least privilege.
- Validate resource ownership and access permissions server-side.
- Protect administrative endpoints separately from public protocol endpoints.
- Avoid relying solely on hidden UI controls to restrict access.

**Verification**

Test direct requests to protected endpoints using unauthorized identities and insufficient privileges.

### 6.13 Denial of Service

**Threat**

An attacker submits excessive requests or resource-intensive input to overwhelm the application or database.

**Potential impact**

Authentication failures, increased latency, database exhaustion, or service unavailability.

**Planned mitigations**

- Apply appropriate rate limits.
- Restrict request body sizes and input complexity.
- Use appropriate timeouts.
- Limit resource-intensive authentication and cryptographic operations.
- Monitor database connection usage.
- Establish operational monitoring and recovery procedures.
- Avoid unbounded queries and uncontrolled resource allocation.

**Verification**

Test rate-limit behavior, oversized requests, repeated authentication failures, and database error handling.

### 6.14 Information Disclosure Through Errors and Logs

**Threat**

Error responses or logs reveal credentials, tokens, private keys, internal implementation details, or sensitive user information.

**Potential impact**

Credential theft, easier exploitation, or privacy violations.

**Planned mitigations**

- Return controlled error responses.
- Keep internal stack traces out of public responses.
- Redact sensitive values from logs.
- Avoid logging full authorization headers, cookies, authorization codes, or tokens.
- Restrict access to operational logs.
- Ensure errors do not expose private cryptographic material.

**Verification**

Inspect error responses and logs generated by malformed requests, failed authentication, and database errors.

### 6.15 Malicious Client Registration

**Threat**

An attacker registers or modifies a client to obtain unauthorized redirect behavior, excessive permissions, or access to protected identity information.

**Potential impact**

Abuse of the identity provider and possible compromise of users who authenticate through the malicious client.

**Planned mitigations**

- Validate client configuration.
- Restrict redirect URI configuration according to the registration policy.
- Enforce appropriate client-type requirements.
- Limit requested scopes to supported and permitted values.
- Protect administrative client-registration operations.
- Apply appropriate secret-management rules to confidential clients.

**Verification**

Test unauthorized client creation, invalid redirect URIs, unsupported scopes, and attempts to modify another client's configuration.

## 7. Data Protection Requirements

Sensitive information should receive protection appropriate to its security impact.

At a minimum:

- Passwords, if supported, must never be stored in plaintext.
- Confidential-client secrets must not be exposed in public responses.
- Private signing keys must be protected from unauthorized access.
- Authorization codes must be short-lived and single-use.
- Tokens must have appropriate lifetimes and validation requirements.
- Session identifiers must be unpredictable and protected.
- Logs must exclude sensitive authentication material.
- Database access must follow least-privilege principles.

Data retention and deletion policies should be established as the persistence model becomes clearer.

## 8. Operational Security

Self-hosting transfers important operational responsibilities to the operator.

Deployment documentation must address:

- TLS and secure network configuration.
- Protection of environment variables and secrets.
- Signing-key storage, backups, and rotation.
- Database access restrictions.
- Database backups and restoration.
- Security updates for runtime dependencies.
- Administrative account protection.
- Monitoring and log access.
- Recovery procedures after suspected compromise.

A secure application implementation cannot compensate for an unnecessarily exposed host or compromised deployment credentials.

## 9. Security Testing Strategy

Security testing should accompany feature implementation rather than being postponed until deployment.

The test suite should include:

- Unit tests for security-sensitive services.
- Integration tests for authorization and token flows.
- Invalid-request and input-validation tests.
- Authorization-code replay tests.
- PKCE verification tests.
- Token signature and claim-validation tests.
- Session security tests.
- Client-configuration validation tests.
- Administrative access-control tests.
- Error-handling and sensitive-data exposure tests.

Vitest and Supertest will support automated testing. Additional tools may be introduced where required by the project's security and deployment needs.

Automated tests are necessary but do not replace a security review.

## 10. Initial Risk Priorities

The following threats deserve particular attention during early implementation.

| Priority | Threat | Reason |
|---|---|---|
| Critical | Private signing-key compromise | May undermine trust in tokens issued by the provider. |
| Critical | Authorization-code theft or replay | Can result in unauthorized token issuance. |
| Critical | Token validation failures | May cause invalid identities or tokens to be accepted. |
| High | Redirect URI validation failures | Can expose authorization responses to attackers. |
| High | Client authentication weaknesses | Can permit unauthorized client impersonation. |
| High | Broken access control | Can expose user data or administrative operations. |
| High | Session hijacking | Can allow unauthorized use of authenticated sessions. |
| High | Credential compromise | Can enable account impersonation. |
| Medium to High | Denial of service | Can prevent legitimate authentication requests from succeeding. |
| Medium to High | Sensitive information in logs | Can expose credentials, tokens, or internal configuration. |

These are initial qualitative priorities, not the results of a completed risk assessment. Severity should be reassessed as implementation details and deployment assumptions become known.

## 11. Assumptions and Limitations

This threat model assumes that Autharis will operate in a deployment where:

- The operator controls the server and its configuration.
- PostgreSQL is configured with appropriate access restrictions.
- Private signing keys can be stored in a protected location.
- Production traffic uses appropriately secured transport.
- The application and its dependencies receive security updates.

The model does not assume that every client application is trustworthy.

A compromised host, operating system, database administrator account, or deployment credential may exceed the protections available to the application itself.

These assumptions must be revisited as deployment options evolve.

## 12. Incident Response Considerations

Autharis should eventually document procedures for responding to:

- Suspected signing-key compromise.
- Unauthorized client registration.
- Leaked confidential-client secrets.
- User credential compromise.
- Session hijacking.
- Token abuse.
- Database compromise.
- Administrative account compromise.

Response procedures should identify how to revoke or invalidate affected credentials and sessions, rotate compromised secrets or keys, investigate relevant logs, and restore trusted operation.

## 13. Review and Maintenance

This threat model must evolve alongside Autharis.

Review it when:

- A new authentication or authorization flow is introduced.
- A new token type is added.
- Client registration capabilities change.
- Administrative functionality is introduced.
- Key-management behavior changes.
- New deployment modes are supported.
- A security vulnerability reveals a missing control.

The existence of a documented mitigation does not prove that it has been implemented correctly.

Security requirements should be translated into implementation tasks and tests, and their completion should be verified.

## 14. Current Status

This document defines the initial security objectives and anticipated threat mitigations for Autharis.

It does not certify the implementation as secure.

Autharis must undergo appropriate testing and security review before being relied upon as a production identity provider.