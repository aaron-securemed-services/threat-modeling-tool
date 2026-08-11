# Patient portal (worked example)

STRIDE threat model report — generated 2026-08-11 15:17

- **System:** Web portal that lets patients view results and message their clinician
- **Author:** Teaching example
- **Date:** 2026-08-11
- **Scope / assumptions:** In scope: the portal web tier, its API, the records database and the billing integration. Out of scope: the clinical EHR itself, corporate IT and physical security of the data centre.
- **Methodology:** STRIDE per element

## 1. Summary

| Metric | Value |
| --- | --- |
| Elements analysed | 14 |
| Data flows | 6 |
| Trust boundaries | 2 |
| Assets | 2 |
| Threats identified | 58 |

| Risk | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- |
| Threats | 2 | 35 | 17 | 3 | 1 |

| STRIDE | Property | Threats |
| --- | --- | --- |
| S — Spoofing | Authentication | 6 |
| T — Tampering | Integrity | 13 |
| R — Repudiation | Non-repudiation | 7 |
| I — Information disclosure | Confidentiality | 14 |
| D — Denial of service | Availability | 15 |
| E — Elevation of privilege | Authorisation | 3 |

## 2. Diagram inventory

### 2.1 Trust boundaries

| Boundary | Kind | Description |
| --- | --- | --- |
| Internet | Internet / DMZ perimeter | Anything outside our control. |
| Hosting VPC (internal network) | Network segment | Our managed cloud environment. |

### 2.2 Elements

| Element | Type | Description | Classification | In boundary | Asset |
| --- | --- | --- | --- | --- | --- |
| Patient | Entity | Members of the public using the portal from their own devices. | Restricted (PII / PHI / PCI) | Internet |  |
| Clinician | Entity | Staff replying to messages and releasing results. | Restricted (PII / PHI / PCI) | Internet |  |
| Billing SaaS | Entity | Third-party billing provider. | Confidential | Internet |  |
| Portal web app | Process | Server-rendered front end. | Restricted (PII / PHI / PCI) | Hosting VPC (internal network) |  |
| Records API | Process | Reads and writes patient records. | Restricted (PII / PHI / PCI) | Hosting VPC (internal network) |  |
| Patient records DB | Data store | PostgreSQL: results, messages, demographics. | Restricted (PII / PHI / PCI) | Hosting VPC (internal network) | yes |
| Application log store | Data store | Aggregated application and access logs. | Confidential | Hosting VPC (internal network) |  |
| PHI | Asset | — | Restricted (PII / PHI / PCI) | Hosting VPC (internal network) | yes |

### 2.3 Data flows

| Flow | Source | Destination | Protocol | Encryption | Crosses boundary |
| --- | --- | --- | --- | --- | --- |
| Portal session | Patient | Portal web app (bi) | HTTPS / TLS | TLS (server authenticated) | Internet, Hosting VPC (internal network) |
| Clinician workspace | Clinician | Portal web app (bi) | HTTPS / TLS | TLS (server authenticated) | Internet, Hosting VPC (internal network) |
| Record lookup | Portal web app | Records API (bi) | HTTP (cleartext) | None (cleartext) | no |
| SQL queries | Records API | Patient records DB (bi) | SQL / database protocol | TLS (server authenticated) | no |
| Application logs | Portal web app | Application log store | HTTPS / TLS | TLS (server authenticated) | no |
| Billing export | Records API | Billing SaaS | Physical / manual transfer | None (cleartext) | Internet, Hosting VPC (internal network) |

## 3. STRIDE coverage matrix

| Element | Type | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Patient | Entity | 1 | · | 2 | · | · | · |
| Clinician | Entity | 1 | · | o | · | · | · |
| Billing SaaS | Entity | 1 | · | 1 | · | · | · |
| Portal web app | Process | 1 | 2 | o | 2 | 1 | o |
| Records API | Process | 2 | 2 | 1 | 1 | 1 | 3 |
| Patient records DB | Data store | · | 2 | 2 | 2 | 2 | · |
| Application log store | Data store | · | 1 | 1 | 2 | 1 | · |
| PHI | Asset | · | 1 | · | 1 | 1 | · |
| Portal session | Data flow | · | 1 | · | 1 | 2 | · |
| Clinician workspace | Data flow | · | 1 | · | 1 | 2 | · |
| Record lookup | Data flow | · | 1 | · | 1 | 1 | · |
| SQL queries | Data flow | · | o | · | o | 1 | · |
| Application logs | Data flow | · | o | · | o | 1 | · |
| Billing export | Data flow | · | 2 | · | 3 | 2 | · |

## 4. Threats and recommended mitigations

### Patient records DB (Data store)

_PostgreSQL: results, messages, demographics._

#### T-28 · [D] Loss of Patient records DB may be unrecoverable — **CRITICAL**

_Denial of service — violates Availability_

Deletion or corruption of Patient records DB - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-22 · [T] Modification of Patient records DB would go unnoticed — **HIGH**

_Tampering — violates Integrity_

Nothing proves that the contents of Patient records DB are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-23 · [T] Unrestricted write access to Patient records DB — **HIGH**

_Tampering — violates Integrity_

Write access to Patient records DB is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-24 · [R] No access log for Patient records DB — **HIGH**

_Repudiation — violates Non-repudiation_

Reads and writes against Patient records DB are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-25 · [R] Regulated records in Patient records DB without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Patient records DB holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-26 · [I] Weak access control on Patient records DB — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Patient records DB depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-27 · [I] Backups of Patient records DB are a second copy of the sensitive data — **HIGH**

_Information disclosure — violates Confidentiality_

Backups and snapshots of Patient records DB carry the same sensitive contents but usually live somewhere with looser access control, longer retention and less monitoring than the primary store.

**Recommended mitigations:**
- Encrypt backups with their own keys and restrict who can restore them.
- Apply the same classification and retention rules to backups as to production data.
- Audit restore operations - a restore is an easy way to exfiltrate a whole database.

#### T-29 · [D] Resource exhaustion against Patient records DB — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Patient records DB unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Records API (Process)

_Reads and writes patient records._

#### T-21 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Records API executes it, and it executes as a privileged account.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-13 · [S] Records API accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Records API is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-58 · [S] Unauthenticated inbound flow "Record lookup" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Record lookup" from Portal web app carry no proof of who sent them. Records API therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Record lookup

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-14 · [T] Untrusted input reaches Records API without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Records API is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-17 · [I] Weak authorisation over sensitive data in Records API — **HIGH**

_Information disclosure — violates Confidentiality_

Records API handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-20 · [E] Coarse authorisation in Records API — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-15 · [T] Integrity of the code and configuration of Records API — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Records API runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-16 · [R] Records API keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Records API cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-18 · [D] Records API has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Records API has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-19 · [E] Records API holds a broadly privileged service account — **MEDIUM**

_Elevation of privilege — violates Authorisation_

Compromising Records API yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

### Patient (Entity)

_Members of the public using the portal from their own devices._

#### T-01 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate Patient. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-02 · [R] Actions by Patient are not attributable — **HIGH**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Patient did. Patient can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

#### T-03 · [R] Anonymous actor touches sensitive data — **HIGH**

_Repudiation — violates Non-repudiation_

Patient is untrusted and unidentified, yet the interaction involves sensitive data. Nothing can be attributed to a specific person, so abuse is invisible and disputes are unresolvable.

**Recommended mitigations:**
- Require identification before sensitive data is reached, even if the rest of the flow stays anonymous.
- If anonymity is a requirement, minimise what sensitive data is exposed on the anonymous path.

### Clinician (Entity)

_Staff replying to messages and releasing results._

#### T-04 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate Clinician. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

### Portal web app (Process)

_Server-rendered front end._

#### T-07 · [S] Clients cannot verify they are talking to the real Portal web app — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Portal web app. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-08 · [T] Untrusted input reaches Portal web app without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Portal web app is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-09 · [T] Integrity of the code and configuration of Portal web app — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Portal web app runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-11 · [I] Regulated data may be copied into logs by Portal web app — **HIGH**

_Information disclosure — violates Confidentiality_

Portal web app handles regulated data and logs heavily. Logs are usually held longer, replicated further and read by more people than the primary store, so they quietly become a second, less protected copy of the sensitive data.

**Recommended mitigations:**
- Redact or tokenise identifiers and payloads before they are written to logs.
- Apply the same classification, access control and retention to logs as to the primary store.
- Review log sinks (aggregators, crash reporters, APM vendors) as part of the data flow.

#### T-12 · [D] Portal web app has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Portal web app has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-10 · [I] Leakage through errors, responses and telemetry from Portal web app — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Portal web app - versions, paths, schema, and whether a given account exists.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Portal session (Data flow)

_Login, results, secure messaging._

#### T-38 · [T] No end-to-end integrity on "Portal session" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-39 · [I] Sensitive data leaves a trust boundary on "Portal session" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Internet" / "Hosting VPC (internal network)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-40 · [D] "Portal session" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-41 · [D] Availability of "Portal session" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Clinician workspace (Data flow)

_Review and release results, reply to messages._

#### T-42 · [T] No end-to-end integrity on "Clinician workspace" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-43 · [I] Sensitive data leaves a trust boundary on "Clinician workspace" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Internet" / "Hosting VPC (internal network)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-44 · [D] "Clinician workspace" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-45 · [D] Availability of "Clinician workspace" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Record lookup (Data flow)

_Internal service call._

#### T-46 · [T] Traffic on "Record lookup" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-47 · [I] Data on "Record lookup" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-48 · [D] Availability of "Record lookup" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Billing export (Data flow)

_Nightly claim export._

#### T-51 · [T] Traffic on "Billing export" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-52 · [T] No end-to-end integrity on "Billing export" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-53 · [I] Data on "Billing export" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-54 · [I] Sensitive data leaves a trust boundary on "Billing export" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Internet" / "Hosting VPC (internal network)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-55 · [I] Sensitive data moved by file share or physical transfer — **HIGH**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-56 · [D] "Billing export" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-57 · [D] Availability of "Billing export" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Internet, Hosting VPC (internal network)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Application log store (Data store)

_Aggregated application and access logs._

#### T-32 · [I] Sensitive data stored unencrypted in Application log store — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Application log store are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-30 · [T] Modification of Application log store would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Application log store are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-31 · [R] No access log for Application log store — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Application log store are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-33 · [I] Backups of Application log store are a second copy of the sensitive data — **MEDIUM**

_Information disclosure — violates Confidentiality_

Backups and snapshots of Application log store carry the same sensitive contents but usually live somewhere with looser access control, longer retention and less monitoring than the primary store.

**Recommended mitigations:**
- Encrypt backups with their own keys and restrict who can restore them.
- Apply the same classification and retention rules to backups as to production data.
- Audit restore operations - a restore is an easy way to exfiltrate a whole database.

#### T-34 · [D] Resource exhaustion against Application log store — **LOW**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Application log store unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### PHI (Asset)

#### T-36 · [D] Availability of the asset PHI — **HIGH**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

#### T-37 · [T] Integrity of the asset PHI — **MEDIUM**

_Tampering — violates Integrity_

If PHI can be altered without detection, decisions made from it are wrong in a way nobody notices. Corruption of a valuable record is often more damaging, and much harder to spot, than its disclosure.

**Recommended mitigations:**
- Establish an authoritative source and reconcile copies against it.
- Keep a tamper-evident history of changes with attribution.

#### T-35 · [I] Confidentiality of the asset PHI — **MEDIUM**

_Information disclosure — violates Confidentiality_

PHI is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

### Billing SaaS (Entity)

_Third-party billing provider._

#### T-05 · [S] Shared secret identifies Billing SaaS — **MEDIUM**

_Spoofing — violates Authentication_

Identity rests on a bearer secret. Anyone who obtains the key from source control, a log, a config file or a backup becomes Billing SaaS, and the theft leaves no trace.

**Recommended mitigations:**
- Move to short-lived tokens or mutual TLS so a leaked value expires quickly.
- Store keys in a secret manager, scope them narrowly, and support rotation without downtime.
- Scan repositories and logs for leaked keys.

#### T-06 · [R] Actions by Billing SaaS are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Billing SaaS did. Billing SaaS can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### SQL queries (Data flow)

_Reads and writes patient records._

#### T-49 · [D] Availability of "SQL queries" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Application logs (Data flow)

_Request and error logs shipped to the log store._

#### T-50 · [D] Availability of "Application logs" as a dependency — **INFO**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

## 5. Coverage gaps

All security categories are answered.

## Appendix A · STRIDE reference

| Letter | Threat | Property violated | Definition | Applies to |
| --- | --- | --- | --- | --- |
| S | Spoofing | Authentication | Pretending to be something or someone else - a user, a process, a machine or a service. | Entity, Process |
| T | Tampering | Integrity | Modifying data or code without authorisation, in memory, on disk or on the wire. | Process, Data store, Data flow, Asset |
| R | Repudiation | Non-repudiation | Claiming not to have performed an action, when the system cannot prove otherwise. | Entity, Process, Data store |
| I | Information disclosure | Confidentiality | Exposing information to people who are not authorised to see it. | Process, Data store, Data flow, Asset |
| D | Denial of service | Availability | Absorbing or destroying the resources needed to provide the service. | Process, Data store, Data flow, Asset |
| E | Elevation of privilege | Authorisation | Doing something you are not permitted to do, or gaining capabilities you were never granted. | Process |

