# Connected infusion pump (worked example)

STRIDE threat model report — generated 2026-08-11 17:15

- **System:** Large-volume infusion pump with hospital connectivity and a vendor cloud service
- **Author:** Teaching example
- **Date:** 2026-08-11
- **Scope / assumptions:** In scope: the pump controller and its dose-limit interlock, the alarm path to the nurse call system, the hospital gateway, the drug library service and the vendor telemetry cloud. Out of scope: the EHR itself, hospital network infrastructure, and physical security of the ward.
- **Intended use:** Continuous and bolus intravenous delivery of medication to adult and paediatric inpatients, programmed at the bedside or by auto-programming from the EHR, under the supervision of clinical staff.
- **Safety risk management file:** Infusion Pump Risk Management File (ISO 14971) (RMF-IP-2200 rev C)
- **Methodology:** STRIDE per element
- **Severity scale:** Built-in qualitative scale (1 of 165 threats scored with CVSS v4.0)

## 1. Summary

| Metric | Value |
| --- | --- |
| Elements analysed | 22 |
| Data flows | 11 |
| Trust boundaries | 3 |
| Assets | 4 |
| Threats identified | 165 |
| Threats affecting patient safety | 56 |
| Safety-relevant elements | 21 |

| Safety impact | What a compromise does to the patient | Threats |
| --- | --- | --- |
| Device control — Controls or actuates therapy / diagnosis | Unintended, altered or withheld therapy delivered to the patient. | 18 |
| Alarms — Generates, carries or displays alarms | A real alarm is missed or suppressed, or false alarms drive alarm fatigue and unnecessary intervention. | 18 |
| Safety stop — Implements a safety stop, interlock or limit | The protective function does not engage, or engages when it should not, removing the last barrier before harm. | 14 |
| Clinical data — Produces clinical data used for decisions | A clinical decision is made on wrong, stale or missing data. | 4 |
| Care delivery — Needed for timely care delivery | Care is delayed or cannot be delivered. | 2 |

| Severity | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- |
| Threats | 59 | 66 | 34 | 6 | 0 |

| STRIDE | Property | Threats |
| --- | --- | --- |
| S — Spoofing | Authentication | 15 |
| T — Tampering | Integrity | 49 |
| R — Repudiation | Non-repudiation | 15 |
| I — Information disclosure | Confidentiality | 22 |
| D — Denial of service | Availability | 48 |
| E — Elevation of privilege | Authorisation | 16 |

## 2. Diagram inventory

### 2.1 Trust boundaries

| Boundary | Kind | Description |
| --- | --- | --- |
| Pump enclosure (device) | Machine / process boundary | The physical device: firmware, actuator and local user interface. |
| Hospital network | Network segment | The clinical network the pump joins over Wi-Fi. |
| Vendor cloud | Third-party or vendor | Manufacturer-operated telemetry and fleet management service. |

### 2.2 Elements

| Element | Type | Description | Classification | Safety impact | Severity of harm | In boundary | Asset |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Pump controller | Process | Firmware that computes and drives the infusion rate. | Restricted (PII / PHI / PCI) | Device control | Catastrophic — patient death | Pump enclosure (device) | yes |
| Dose limit interlock | Process | Independent hard-limit check before actuation. | Internal | Safety stop | Catastrophic — patient death | Pump enclosure (device) | yes |
| Alarm manager | Process | Detects alarm conditions and annunciates locally and remotely. | Confidential | Alarms | Critical — permanent impairment or life-threatening injury | Pump enclosure (device) |  |
| Drug library (on device) | Data store | Dose limits and concentrations per medication. | Internal | Safety stop | Catastrophic — patient death | Pump enclosure (device) | yes |
| Nurse (bedside) | Entity | Programmes the infusion at the pump and responds to alarms. | Restricted (PII / PHI / PCI) | Device control; Care delivery | Serious — injury needing professional intervention | Hospital network |  |
| Biomed / service tech | Entity | Services the pump and updates the drug library. | Internal | Safety stop | Catastrophic — patient death | Hospital network |  |
| Hospital gateway | Process | Bridges pumps to hospital systems and the vendor cloud. | Restricted (PII / PHI / PCI) | Device control; Alarms; Care delivery | Critical — permanent impairment or life-threatening injury | Hospital network |  |
| Nurse call system | Process | Escalates device alarms to staff handsets. | Confidential | Alarms; Care delivery | Critical — permanent impairment or life-threatening injury | Hospital network |  |
| Vendor fleet service | Process | Telemetry, drug library distribution and firmware updates. | Restricted (PII / PHI / PCI) | Safety stop; Device control | Catastrophic — patient death | Vendor cloud |  |
| Telemetry & event store | Data store | Infusion events, alarms and device logs. | Restricted (PII / PHI / PCI) | Clinical data | Minor — temporary injury, no professional intervention | Vendor cloud |  |
| Patient | Asset | — | Restricted (PII / PHI / PCI) | Device control; Care delivery | Catastrophic — patient death | Vendor cloud | yes |

### 2.3 Data flows

| Flow | Source | Destination | Protocol | Encryption | Crosses boundary |
| --- | --- | --- | --- | --- | --- |
| Programme infusion | Nurse (bedside) | Pump controller | Other | None (cleartext) | Pump enclosure (device), Hospital network |
| Auto-programming order | Hospital gateway | Pump controller | HTTP (cleartext) | None (cleartext) | Pump enclosure (device), Hospital network |
| Requested rate check | Pump controller | Dose limit interlock (bi) | Other | None (cleartext) | no |
| Dose limits | Drug library (on device) | Dose limit interlock | Other | None (cleartext) | no |
| Alarm conditions | Pump controller | Alarm manager | Other | None (cleartext) | no |
| Remote alarm escalation | Alarm manager | Nurse call system | HTTP (cleartext) | None (cleartext) | Pump enclosure (device), Hospital network |
| Drug library update | Biomed / service tech | Drug library (on device) | SMB / NFS file share | None (cleartext) | Pump enclosure (device), Hospital network |
| Drug library & firmware distribution | Vendor fleet service | Hospital gateway | HTTPS / TLS | TLS (server authenticated) | Hospital network, Vendor cloud |
| Device telemetry | Hospital gateway | Vendor fleet service | HTTPS / TLS | TLS (server authenticated) | Hospital network, Vendor cloud |
| Store events | Vendor fleet service | Telemetry & event store | HTTPS / TLS | TLS (server authenticated) | no |
| Bedside annunciation | Alarm manager | Nurse (bedside) | Physical / manual transfer | None (cleartext) | Pump enclosure (device), Hospital network |

## 3. STRIDE coverage matrix

| Element | Type | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Pump controller | Process | 2 | 3 | 2 | 1 | 2 | 5 |
| Dose limit interlock | Process | 3 | 2 | 1 | o | 2 | 2 |
| Alarm manager | Process | 3 | 2 | 2 | 1 | 2 | 1 |
| Drug library (on device) | Data store | · | 3 | 1 | 1 | 1 | · |
| Nurse (bedside) | Entity | 1 | · | 1 | · | · | · |
| Biomed / service tech | Entity | 1 | · | 1 | · | · | · |
| Hospital gateway | Process | 3 | 4 | 3 | 1 | 4 | 5 |
| Nurse call system | Process | 1 | 2 | 1 | o | 3 | 1 |
| Vendor fleet service | Process | 1 | 4 | 1 | 2 | 1 | 2 |
| Telemetry & event store | Data store | · | 2 | 2 | 1 | 3 | · |
| Patient | Asset | · | 1 | · | 1 | 1 | · |
| Programme infusion | Data flow | · | 3 | · | 2 | 3 | · |
| Auto-programming order | Data flow | · | 3 | · | 2 | 3 | · |
| Requested rate check | Data flow | · | 2 | · | 1 | 2 | · |
| Dose limits | Data flow | · | 2 | · | 1 | 2 | · |
| Alarm conditions | Data flow | · | 2 | · | 1 | 2 | · |
| Remote alarm escalation | Data flow | · | 3 | · | 2 | 3 | · |
| Drug library update | Data flow | · | 3 | · | 1 | 3 | · |
| Drug library & firmware distribution | Data flow | · | 3 | · | o | 4 | · |
| Device telemetry | Data flow | · | 2 | · | 1 | 3 | · |
| Store events | Data flow | · | o | · | o | 1 | · |
| Bedside annunciation | Data flow | · | 3 | · | 3 | 3 | · |

## 4. Threats and recommended mitigations

### Pump controller (Process)

_Firmware that computes and drives the infusion rate._

#### T-10 · [T] Therapy parameters handled by Pump controller can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

**CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H/S:P/AU:Y` — Scored with the clinical engineering team; S:P set because the subsequent system impact is the patient.

Dose, rate, duration, energy or programme values passing through Pump controller can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-002 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-12 · [D] Loss of Pump controller removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Pump controller responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-004 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-09 · [S] Therapy commands to Pump controller are not proven to come from a legitimate source — **CRITICAL**

_Spoofing — violates Authentication_

An attacker who can reach Pump controller issues therapy or actuation commands that the device accepts as clinical instructions, because nothing distinguishes them from the real controller or clinician.

> **Patient safety — SEC-HAZ-001 · Controls or actuates therapy / diagnosis**  
> **Harm:** Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Authenticate every command source cryptographically (mutual TLS, signed commands); network position is not identity.
- Bind commands to a session, a patient context and a monotonic sequence number so replayed or injected commands are rejected.
- Require confirmation at the device for changes that increase delivered therapy.

#### T-11 · [E] Therapy control functions in Pump controller are reachable without a clinical authorisation decision — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A caller who is authenticated for some other purpose — a service account, a read-only integration, a patient-facing feature — can invoke the functions that change therapy, because authorisation does not separate clinical control from everything else.

> **Patient safety — SEC-HAZ-003 · Controls or actuates therapy / diagnosis**  
> **Harm:** Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Separate therapy-control operations behind their own authorisation, deny by default, and require a clinical role.
- Require step-up authentication or a second person for high-consequence changes.
- Log every therapy-control call with the authenticated identity and the resulting parameter change.

#### T-08 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Pump controller executes it, and it executes as a privileged account.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-13 · [R] Therapy changes at Pump controller cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

> **Patient safety — SEC-HAZ-005 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-01 · [T] Untrusted input reaches Pump controller without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Pump controller is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-04 · [I] Weak authorisation over sensitive data in Pump controller — **HIGH**

_Information disclosure — violates Confidentiality_

Pump controller handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-07 · [E] Coarse authorisation in Pump controller — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-159 · [S] Unauthenticated inbound flow "Auto-programming order" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Auto-programming order" from Hospital gateway carry no proof of who sent them. Pump controller therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Auto-programming order

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-05 · [D] Pump controller has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Pump controller has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-160 · [E] Privilege crosses a trust boundary into Pump controller — **HIGH**

_Elevation of privilege — violates Authorisation_

"Auto-programming order" enters Pump controller across the trust boundary "Pump enclosure (device)" / "Hospital network" without an authorisation decision of its own. Whatever the caller can request, Pump controller will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Auto-programming order

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-02 · [T] Integrity of the code and configuration of Pump controller — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Pump controller runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-03 · [R] Pump controller keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Pump controller cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-06 · [E] Pump controller holds a broadly privileged service account — **HIGH**

_Elevation of privilege — violates Authorisation_

Compromising Pump controller yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

### Vendor fleet service (Process)

_Telemetry, drug library distribution and firmware updates._

#### T-75 · [T] Safety limits or interlock configuration at Vendor fleet service can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Vendor fleet service can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-029 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-77 · [T] Therapy parameters handled by Vendor fleet service can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Vendor fleet service can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-031 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-76 · [D] The safety stop in Vendor fleet service may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Vendor fleet service. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

> **Patient safety — SEC-HAZ-030 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-74 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Vendor fleet service executes it, and it executes as a privileged account.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-78 · [R] Therapy changes at Vendor fleet service cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

> **Patient safety — SEC-HAZ-032 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-69 · [T] Untrusted input reaches Vendor fleet service without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Vendor fleet service is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-68 · [S] Clients cannot verify they are talking to the real Vendor fleet service — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Vendor fleet service. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-70 · [T] Integrity of the code and configuration of Vendor fleet service — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Vendor fleet service runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-72 · [I] Regulated data may be copied into logs by Vendor fleet service — **HIGH**

_Information disclosure — violates Confidentiality_

Vendor fleet service handles regulated data and logs heavily. Logs are usually held longer, replicated further and read by more people than the primary store, so they quietly become a second, less protected copy of the sensitive data.

**Recommended mitigations:**
- Redact or tokenise identifiers and payloads before they are written to logs.
- Apply the same classification, access control and retention to logs as to the primary store.
- Review log sinks (aggregators, crash reporters, APM vendors) as part of the data flow.

#### T-73 · [E] Vendor fleet service holds a broadly privileged service account — **HIGH**

_Elevation of privilege — violates Authorisation_

Compromising Vendor fleet service yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

#### T-71 · [I] Leakage through errors, responses and telemetry from Vendor fleet service — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Vendor fleet service - versions, paths, schema, and whether a given account exists.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Dose limit interlock (Process)

_Independent hard-limit check before actuation._

#### T-21 · [D] The safety stop in Dose limit interlock may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Dose limit interlock. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

> **Patient safety — SEC-HAZ-008 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> **Hazardous situation (as modelled):** This is the last barrier between a wrong programmed dose and the patient. If its limits are widened, or it does not get to run, nothing else stops an unsafe infusion.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-011, RC-012

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-19 · [T] Safety limits or interlock configuration at Dose limit interlock can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Dose limit interlock can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-006 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** This is the last barrier between a wrong programmed dose and the patient. If its limits are widened, or it does not get to run, nothing else stops an unsafe infusion.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-011, RC-012

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-20 · [E] The safety stop in Dose limit interlock can be overridden without proper authority — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Override, service, maintenance or "clinical justification" paths that disable the interlock are reachable by a caller who should not have them — a normal user, a service tool, or anything that has learned the shared override credential.

> **Patient safety — SEC-HAZ-007 · Implements a safety stop, interlock or limit**  
> **Harm:** The protective stop is bypassed and the patient is exposed to exactly the hazard it was implemented to control.  
> **Hazardous situation (as modelled):** This is the last barrier between a wrong programmed dose and the patient. If its limits are widened, or it does not get to run, nothing else stops an unsafe infusion.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-011, RC-012

**Recommended mitigations:**
- Require a distinct, strongly authenticated role for any override, with per-use authorisation rather than a mode that stays on.
- Make overrides time-boxed and self-expiring, and annunciate continuously while one is active.
- Log every override with identity, reason and duration, and review them as a safety signal.
- Remove service backdoors and default maintenance credentials from production devices.

#### T-14 · [S] Dose limit interlock accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Dose limit interlock is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-15 · [T] Untrusted input reaches Dose limit interlock without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Dose limit interlock is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-18 · [E] No effective authorisation model in Dose limit interlock — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-161 · [S] Unauthenticated inbound flow "Requested rate check" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Requested rate check" from Pump controller carry no proof of who sent them. Dose limit interlock therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Requested rate check

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-162 · [S] Unauthenticated inbound flow "Dose limits" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Dose limits" from Drug library (on device) carry no proof of who sent them. Dose limit interlock therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Dose limits

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-17 · [D] Dose limit interlock has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Dose limit interlock has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-16 · [R] Dose limit interlock keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Dose limit interlock cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

### Programme infusion (Data flow)

_Rate, dose and duration entered at the bedside._

#### T-97 · [D] Loss of Programme infusion removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Programme infusion responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-036 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-002

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-96 · [T] Therapy parameters handled by Programme infusion can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Programme infusion can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-035 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-002

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-90 · [T] Traffic on "Programme infusion" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-92 · [I] Data on "Programme infusion" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-94 · [D] "Programme infusion" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-91 · [T] No end-to-end integrity on "Programme infusion" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-93 · [I] Sensitive data leaves a trust boundary on "Programme infusion" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-95 · [D] Availability of "Programme infusion" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Auto-programming order (Data flow)

_Pharmacy order pushed to the pump from the EHR._

#### T-105 · [D] Loss of Auto-programming order removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Auto-programming order responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-038 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-004

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-104 · [T] Therapy parameters handled by Auto-programming order can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Auto-programming order can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-037 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-004

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-98 · [T] Traffic on "Auto-programming order" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-100 · [I] Data on "Auto-programming order" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-102 · [D] "Auto-programming order" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-99 · [T] No end-to-end integrity on "Auto-programming order" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-101 · [I] Sensitive data leaves a trust boundary on "Auto-programming order" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-103 · [D] Availability of "Auto-programming order" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Drug library (on device) (Data store)

_Dose limits and concentrations per medication._

#### T-37 · [T] Safety limits or interlock configuration at Drug library (on device) can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Drug library (on device) can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-013 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** The limits the interlock enforces. Tampering here silently widens what the pump will accept as a legitimate dose.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-012

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-33 · [T] Unrestricted write access to Drug library (on device) — **HIGH**

_Tampering — violates Integrity_

Write access to Drug library (on device) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-35 · [I] Weak access control on Drug library (on device) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Drug library (on device) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-32 · [T] Modification of Drug library (on device) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Drug library (on device) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-34 · [R] No access log for Drug library (on device) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Drug library (on device) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-36 · [D] Resource exhaustion against Drug library (on device) — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Drug library (on device) unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Drug library & firmware distribution (Data flow)

_Fleet-wide updates pushed to the hospital._

#### T-139 · [T] Safety limits or interlock configuration at Drug library & firmware distribution can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Drug library & firmware distribution can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-049 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-141 · [T] Therapy parameters handled by Drug library & firmware distribution can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Drug library & firmware distribution can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-051 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-140 · [D] The safety stop in Drug library & firmware distribution may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Drug library & firmware distribution. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

> **Patient safety — SEC-HAZ-050 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-142 · [D] Loss of Drug library & firmware distribution removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Drug library & firmware distribution responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-052 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-136 · [T] No end-to-end integrity on "Drug library & firmware distribution" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-137 · [D] "Drug library & firmware distribution" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-138 · [D] Availability of "Drug library & firmware distribution" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Alarm manager (Process)

_Detects alarm conditions and annunciates locally and remotely._

#### T-29 · [D] Alarm delivery through Alarm manager can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Alarm manager, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-010 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-30 · [S] Alarms carried by Alarm manager cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Alarm manager can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-011 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-28 · [T] Alarm conditions or thresholds at Alarm manager can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Alarm manager. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-009 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-31 · [R] Alarm history at Alarm manager is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Alarm manager.

> **Patient safety — SEC-HAZ-012 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-22 · [S] Alarm manager accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Alarm manager is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-163 · [S] Unauthenticated inbound flow "Alarm conditions" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Alarm conditions" from Pump controller carry no proof of who sent them. Alarm manager therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Alarm conditions

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-23 · [T] Untrusted input reaches Alarm manager without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Alarm manager is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-25 · [I] Weak authorisation over sensitive data in Alarm manager — **HIGH**

_Information disclosure — violates Confidentiality_

Alarm manager handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-27 · [E] No effective authorisation model in Alarm manager — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-26 · [D] Alarm manager has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Alarm manager has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-24 · [R] Alarm manager keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Alarm manager cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

### Hospital gateway (Process)

_Bridges pumps to hospital systems and the vendor cloud._

#### T-54 · [D] Loss of Hospital gateway removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Hospital gateway responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-017 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-57 · [D] Alarm delivery through Hospital gateway can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Hospital gateway, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-020 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-51 · [S] Therapy commands to Hospital gateway are not proven to come from a legitimate source — **CRITICAL**

_Spoofing — violates Authentication_

An attacker who can reach Hospital gateway issues therapy or actuation commands that the device accepts as clinical instructions, because nothing distinguishes them from the real controller or clinician.

> **Patient safety — SEC-HAZ-014 · Controls or actuates therapy / diagnosis**  
> **Harm:** Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Authenticate every command source cryptographically (mutual TLS, signed commands); network position is not identity.
- Bind commands to a session, a patient context and a monotonic sequence number so replayed or injected commands are rejected.
- Require confirmation at the device for changes that increase delivered therapy.

#### T-58 · [S] Alarms carried by Hospital gateway cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Hospital gateway can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-021 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-52 · [T] Therapy parameters handled by Hospital gateway can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Hospital gateway can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-015 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-56 · [T] Alarm conditions or thresholds at Hospital gateway can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Hospital gateway. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-019 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-50 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Hospital gateway executes it, and it executes as a privileged account.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-53 · [E] Therapy control functions in Hospital gateway are reachable without a clinical authorisation decision — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A caller who is authenticated for some other purpose — a service account, a read-only integration, a patient-facing feature — can invoke the functions that change therapy, because authorisation does not separate clinical control from everything else.

> **Patient safety — SEC-HAZ-016 · Controls or actuates therapy / diagnosis**  
> **Harm:** Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Separate therapy-control operations behind their own authorisation, deny by default, and require a clinical role.
- Require step-up authentication or a second person for high-consequence changes.
- Log every therapy-control call with the authenticated identity and the resulting parameter change.

#### T-60 · [D] Loss of Hospital gateway delays or prevents care — **CRITICAL**

_Denial of service — violates Availability_

Hospital gateway is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

> **Patient safety — SEC-HAZ-023 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-55 · [R] Therapy changes at Hospital gateway cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

> **Patient safety — SEC-HAZ-018 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-59 · [R] Alarm history at Hospital gateway is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Hospital gateway.

> **Patient safety — SEC-HAZ-022 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-42 · [S] Hospital gateway accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Hospital gateway is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-43 · [T] Untrusted input reaches Hospital gateway without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Hospital gateway is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-46 · [I] Weak authorisation over sensitive data in Hospital gateway — **HIGH**

_Information disclosure — violates Confidentiality_

Hospital gateway handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-48 · [E] No effective authorisation model in Hospital gateway — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-165 · [E] Privilege crosses a trust boundary into Hospital gateway — **HIGH**

_Elevation of privilege — violates Authorisation_

"Drug library & firmware distribution" enters Hospital gateway across the trust boundary "Hospital network" / "Vendor cloud" without an authorisation decision of its own. Whatever the caller can request, Hospital gateway will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Drug library & firmware distribution

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-47 · [D] Hospital gateway has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Hospital gateway has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-44 · [T] Integrity of the code and configuration of Hospital gateway — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Hospital gateway runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-45 · [R] Hospital gateway keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Hospital gateway cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-49 · [E] Hospital gateway holds a broadly privileged service account — **MEDIUM**

_Elevation of privilege — violates Authorisation_

Compromising Hospital gateway yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

### Nurse call system (Process)

_Escalates device alarms to staff handsets._

#### T-64 · [D] Alarm delivery through Nurse call system can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Nurse call system, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-025 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-65 · [S] Alarms carried by Nurse call system cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Nurse call system can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-026 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-63 · [T] Alarm conditions or thresholds at Nurse call system can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Nurse call system. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-024 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-67 · [D] Loss of Nurse call system delays or prevents care — **CRITICAL**

_Denial of service — violates Availability_

Nurse call system is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

> **Patient safety — SEC-HAZ-028 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-66 · [R] Alarm history at Nurse call system is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Nurse call system.

> **Patient safety — SEC-HAZ-027 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-61 · [T] Untrusted input reaches Nurse call system without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Nurse call system is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-164 · [E] Privilege crosses a trust boundary into Nurse call system — **HIGH**

_Elevation of privilege — violates Authorisation_

"Remote alarm escalation" enters Nurse call system across the trust boundary "Pump enclosure (device)" / "Hospital network" without an authorisation decision of its own. Whatever the caller can request, Nurse call system will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Remote alarm escalation

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-62 · [D] Nurse call system has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Nurse call system has, taking it down for everyone.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### Requested rate check (Data flow)

_Every programmed rate is checked against the hard limits._

#### T-110 · [D] The safety stop in Requested rate check may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Requested rate check. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

> **Patient safety — SEC-HAZ-040 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-011

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-109 · [T] Safety limits or interlock configuration at Requested rate check can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Requested rate check can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-039 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-011

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-106 · [T] Traffic on "Requested rate check" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-107 · [I] Data on "Requested rate check" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-108 · [D] Availability of "Requested rate check" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Dose limits (Data flow)

_Limits the interlock enforces._

#### T-115 · [D] The safety stop in Dose limits may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Dose limits. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

> **Patient safety — SEC-HAZ-042 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-012

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-114 · [T] Safety limits or interlock configuration at Dose limits can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Dose limits can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-041 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-012

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-111 · [T] Traffic on "Dose limits" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-112 · [I] Data on "Dose limits" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-113 · [D] Availability of "Dose limits" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Alarm conditions (Data flow)

_Occlusion, air-in-line, battery and completion events._

#### T-120 · [D] Alarm delivery through Alarm conditions can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Alarm conditions, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-044 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-119 · [T] Alarm conditions or thresholds at Alarm conditions can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Alarm conditions. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-043 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-116 · [T] Traffic on "Alarm conditions" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-117 · [I] Data on "Alarm conditions" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-118 · [D] Availability of "Alarm conditions" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Remote alarm escalation (Data flow)

_Alarms forwarded to staff handsets._

#### T-128 · [D] Alarm delivery through Remote alarm escalation can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Remote alarm escalation, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-046 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007, RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-127 · [T] Alarm conditions or thresholds at Remote alarm escalation can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Remote alarm escalation. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-045 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007, RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-121 · [T] Traffic on "Remote alarm escalation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-123 · [I] Data on "Remote alarm escalation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-125 · [D] "Remote alarm escalation" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-122 · [T] No end-to-end integrity on "Remote alarm escalation" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-124 · [I] Sensitive data leaves a trust boundary on "Remote alarm escalation" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-126 · [D] Availability of "Remote alarm escalation" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside annunciation (Data flow)

_Audible and visual alarm at the pump._

#### T-158 · [D] Alarm delivery through Bedside annunciation can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside annunciation, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-056 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-157 · [T] Alarm conditions or thresholds at Bedside annunciation can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside annunciation. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-055 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-150 · [T] Traffic on "Bedside annunciation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-152 · [I] Data on "Bedside annunciation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-155 · [D] "Bedside annunciation" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-151 · [T] No end-to-end integrity on "Bedside annunciation" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-153 · [I] Sensitive data leaves a trust boundary on "Bedside annunciation" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-154 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-156 · [D] Availability of "Bedside annunciation" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Drug library update (Data flow)

_Service tooling writes new dose limits to the pump._

#### T-134 · [T] Safety limits or interlock configuration at Drug library update can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Drug library update can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

> **Patient safety — SEC-HAZ-047 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: HAZ-009

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-135 · [D] The safety stop in Drug library update may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Drug library update. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

> **Patient safety — SEC-HAZ-048 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: HAZ-009

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-129 · [T] Traffic on "Drug library update" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-131 · [I] Data on "Drug library update" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-130 · [T] No end-to-end integrity on "Drug library update" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-132 · [D] "Drug library update" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-133 · [D] Availability of "Drug library update" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Device telemetry (Data flow)

_Infusion and alarm events sent to the vendor._

#### T-147 · [T] Clinical data at Device telemetry can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Device telemetry, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-053 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: HAZ-013

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-148 · [D] Clinical data from Device telemetry may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Device telemetry unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-054 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: HAZ-013

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-143 · [T] No end-to-end integrity on "Device telemetry" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-144 · [I] Sensitive data leaves a trust boundary on "Device telemetry" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Hospital network" / "Vendor cloud". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-145 · [D] "Device telemetry" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-146 · [D] Availability of "Device telemetry" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Telemetry & event store (Data store)

_Infusion events, alarms and device logs._

#### T-85 · [T] Clinical data at Telemetry & event store can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Telemetry & event store, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-033 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class A — no injury possible · Safety file: HAZ-013

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-86 · [D] Clinical data from Telemetry & event store may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Telemetry & event store unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-034 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class A — no injury possible · Safety file: HAZ-013

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-81 · [R] Regulated records in Telemetry & event store without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Telemetry & event store holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-83 · [D] Loss of Telemetry & event store may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Telemetry & event store - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-79 · [T] Modification of Telemetry & event store would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Telemetry & event store are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-80 · [R] No access log for Telemetry & event store — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Telemetry & event store are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-82 · [I] Backups of Telemetry & event store are a second copy of the sensitive data — **MEDIUM**

_Information disclosure — violates Confidentiality_

Backups and snapshots of Telemetry & event store carry the same sensitive contents but usually live somewhere with looser access control, longer retention and less monitoring than the primary store.

**Recommended mitigations:**
- Encrypt backups with their own keys and restrict who can restore them.
- Apply the same classification and retention rules to backups as to production data.
- Audit restore operations - a restore is an easy way to exfiltrate a whole database.

#### T-84 · [D] Resource exhaustion against Telemetry & event store — **LOW**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Telemetry & event store unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Nurse (bedside) (Entity)

_Programmes the infusion at the pump and responds to alarms._

#### T-38 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate Nurse (bedside). Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-39 · [R] Actions by Nurse (bedside) are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Nurse (bedside) did. Nurse (bedside) can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### Patient (Asset)

#### T-88 · [D] Availability of the asset Patient — **HIGH**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

#### T-89 · [T] Integrity of the asset Patient — **HIGH**

_Tampering — violates Integrity_

If Patient can be altered without detection, decisions made from it are wrong in a way nobody notices. Corruption of a valuable record is often more damaging, and much harder to spot, than its disclosure.

**Recommended mitigations:**
- Establish an authoritative source and reconcile copies against it.
- Keep a tamper-evident history of changes with attribution.

#### T-87 · [I] Confidentiality of the asset Patient — **HIGH**

_Information disclosure — violates Confidentiality_

Patient is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

### Biomed / service tech (Entity)

_Services the pump and updates the drug library._

#### T-40 · [S] Shared secret identifies Biomed / service tech — **MEDIUM**

_Spoofing — violates Authentication_

Identity rests on a bearer secret. Anyone who obtains the key from source control, a log, a config file or a backup becomes Biomed / service tech, and the theft leaves no trace.

**Recommended mitigations:**
- Move to short-lived tokens or mutual TLS so a leaked value expires quickly.
- Store keys in a secret manager, scope them narrowly, and support rotation without downtime.
- Scan repositories and logs for leaked keys.

#### T-41 · [R] Actions by Biomed / service tech are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Biomed / service tech did. Biomed / service tech can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### Store events (Data flow)

_Telemetry written to the event store._

#### T-149 · [D] Availability of "Store events" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

## 5. Patient safety traceability

Each row is a security threat with a credible path to patient harm. Carry the hazard reference into the safety risk management file (Infusion Pump Risk Management File (ISO 14971), RMF-IP-2200 rev C) so the security control and the safety risk control are the same decision.

| Hazard ref | Threat | Element | STRIDE | Safety impact | Hazardous situation -> harm | Severity of harm | Severity | Safety file ref |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-HAZ-001 | T-09 | Pump controller | S | Device control | Therapy commands to Pump controller are not proven to come from a legitimate source -> Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-002 | T-10 | Pump controller | T | Device control | Therapy parameters handled by Pump controller can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-003 | T-11 | Pump controller | E | Device control | Therapy control functions in Pump controller are reachable without a clinical authorisation decision -> Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-004 | T-12 | Pump controller | D | Device control | Loss of Pump controller removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-005 | T-13 | Pump controller | R | Device control | Therapy changes at Pump controller cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-006 | T-19 | Dose limit interlock | T | Safety stop | Safety limits or interlock configuration at Dose limit interlock can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-011, RC-012 |
| SEC-HAZ-007 | T-20 | Dose limit interlock | E | Safety stop | The safety stop in Dose limit interlock can be overridden without proper authority -> The protective stop is bypassed and the patient is exposed to exactly the hazard it was implemented to control. | Catastrophic — patient death | CRITICAL | RC-011, RC-012 |
| SEC-HAZ-008 | T-21 | Dose limit interlock | D | Safety stop | The safety stop in Dose limit interlock may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | RC-011, RC-012 |
| SEC-HAZ-009 | T-28 | Alarm manager | T | Alarms | Alarm conditions or thresholds at Alarm manager can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-010 | T-29 | Alarm manager | D | Alarms | Alarm delivery through Alarm manager can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-011 | T-30 | Alarm manager | S | Alarms | Alarms carried by Alarm manager cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-012 | T-31 | Alarm manager | R | Alarms | Alarm history at Alarm manager is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-013 | T-37 | Drug library (on device) | T | Safety stop | Safety limits or interlock configuration at Drug library (on device) can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-012 |
| SEC-HAZ-014 | T-51 | Hospital gateway | S | Device control | Therapy commands to Hospital gateway are not proven to come from a legitimate source -> Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-015 | T-52 | Hospital gateway | T | Device control | Therapy parameters handled by Hospital gateway can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-016 | T-53 | Hospital gateway | E | Device control | Therapy control functions in Hospital gateway are reachable without a clinical authorisation decision -> Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-017 | T-54 | Hospital gateway | D | Device control | Loss of Hospital gateway removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-018 | T-55 | Hospital gateway | R | Device control | Therapy changes at Hospital gateway cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-019 | T-56 | Hospital gateway | T | Alarms | Alarm conditions or thresholds at Hospital gateway can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-020 | T-57 | Hospital gateway | D | Alarms | Alarm delivery through Hospital gateway can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-021 | T-58 | Hospital gateway | S | Alarms | Alarms carried by Hospital gateway cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-022 | T-59 | Hospital gateway | R | Alarms | Alarm history at Hospital gateway is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-023 | T-60 | Hospital gateway | D | Care delivery | Loss of Hospital gateway delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-024 | T-63 | Nurse call system | T | Alarms | Alarm conditions or thresholds at Nurse call system can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-025 | T-64 | Nurse call system | D | Alarms | Alarm delivery through Nurse call system can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-026 | T-65 | Nurse call system | S | Alarms | Alarms carried by Nurse call system cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-027 | T-66 | Nurse call system | R | Alarms | Alarm history at Nurse call system is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-028 | T-67 | Nurse call system | D | Care delivery | Loss of Nurse call system delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-029 | T-75 | Vendor fleet service | T | Safety stop | Safety limits or interlock configuration at Vendor fleet service can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-030 | T-76 | Vendor fleet service | D | Safety stop | The safety stop in Vendor fleet service may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-031 | T-77 | Vendor fleet service | T | Device control | Therapy parameters handled by Vendor fleet service can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-032 | T-78 | Vendor fleet service | R | Device control | Therapy changes at Vendor fleet service cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-033 | T-85 | Telemetry & event store | T | Clinical data | Clinical data at Telemetry & event store can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-034 | T-86 | Telemetry & event store | D | Clinical data | Clinical data from Telemetry & event store may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-035 | T-96 | Programme infusion | T | Device control | Therapy parameters handled by Programme infusion can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-002 |
| SEC-HAZ-036 | T-97 | Programme infusion | D | Device control | Loss of Programme infusion removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-002 |
| SEC-HAZ-037 | T-104 | Auto-programming order | T | Device control | Therapy parameters handled by Auto-programming order can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-004 |
| SEC-HAZ-038 | T-105 | Auto-programming order | D | Device control | Loss of Auto-programming order removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-004 |
| SEC-HAZ-039 | T-109 | Requested rate check | T | Safety stop | Safety limits or interlock configuration at Requested rate check can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-011 |
| SEC-HAZ-040 | T-110 | Requested rate check | D | Safety stop | The safety stop in Requested rate check may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | RC-011 |
| SEC-HAZ-041 | T-114 | Dose limits | T | Safety stop | Safety limits or interlock configuration at Dose limits can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-012 |
| SEC-HAZ-042 | T-115 | Dose limits | D | Safety stop | The safety stop in Dose limits may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | RC-012 |
| SEC-HAZ-043 | T-119 | Alarm conditions | T | Alarms | Alarm conditions or thresholds at Alarm conditions can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-044 | T-120 | Alarm conditions | D | Alarms | Alarm delivery through Alarm conditions can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-045 | T-127 | Remote alarm escalation | T | Alarms | Alarm conditions or thresholds at Remote alarm escalation can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-046 | T-128 | Remote alarm escalation | D | Alarms | Alarm delivery through Remote alarm escalation can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-047 | T-134 | Drug library update | T | Safety stop | Safety limits or interlock configuration at Drug library update can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-009 |
| SEC-HAZ-048 | T-135 | Drug library update | D | Safety stop | The safety stop in Drug library update may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-009 |
| SEC-HAZ-049 | T-139 | Drug library & firmware distribution | T | Safety stop | Safety limits or interlock configuration at Drug library & firmware distribution can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-050 | T-140 | Drug library & firmware distribution | D | Safety stop | The safety stop in Drug library & firmware distribution may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-051 | T-141 | Drug library & firmware distribution | T | Device control | Therapy parameters handled by Drug library & firmware distribution can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-052 | T-142 | Drug library & firmware distribution | D | Device control | Loss of Drug library & firmware distribution removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-053 | T-147 | Device telemetry | T | Clinical data | Clinical data at Device telemetry can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-054 | T-148 | Device telemetry | D | Clinical data | Clinical data from Device telemetry may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-055 | T-157 | Bedside annunciation | T | Alarms | Alarm conditions or thresholds at Bedside annunciation can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | RC-021 |
| SEC-HAZ-056 | T-158 | Bedside annunciation | D | Alarms | Alarm delivery through Bedside annunciation can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | RC-021 |

### 5.1 Safety-relevant elements with no threat raised

Record these in the safety file as justified residual risks.

| Element | Safety functions | Severity of harm | Controls in place | Safety file ref |
| --- | --- | --- | --- | --- |
| Nurse (bedside) | Device control; Care delivery | Serious — injury needing professional intervention | none recorded | HAZ-002 |
| Biomed / service tech | Safety stop | Catastrophic — patient death | none recorded | HAZ-009 |
| Patient | Device control; Care delivery | Catastrophic — patient death | none recorded | RMF-IP-2200 |

### 5.2 Breaks in the safety trace

| Element | Type | What is missing |
| --- | --- | --- |
| Store events | Data flow | Patient safety impact has not been assessed for this element. |

## 6. Coverage gaps

| Element | Type | Unanswered categories |
| --- | --- | --- |
| Telemetry & event store | Data store | Hazardous situation |
| Programme infusion | Data flow | Hazardous situation |
| Auto-programming order | Data flow | Hazardous situation |
| Requested rate check | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Dose limits | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Alarm conditions | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Remote alarm escalation | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Drug library update | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Drug library & firmware distribution | Data flow | Hazardous situation |
| Device telemetry | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Store events | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Bedside annunciation | Data flow | Software safety class (IEC 62304), Hazardous situation |

## Appendix A · STRIDE reference

| Letter | Threat | Property violated | Definition | Applies to |
| --- | --- | --- | --- | --- |
| S | Spoofing | Authentication | Pretending to be something or someone else - a user, a process, a machine or a service. | Entity, Process |
| T | Tampering | Integrity | Modifying data or code without authorisation, in memory, on disk or on the wire. | Process, Data store, Data flow, Asset |
| R | Repudiation | Non-repudiation | Claiming not to have performed an action, when the system cannot prove otherwise. | Entity, Process, Data store |
| I | Information disclosure | Confidentiality | Exposing information to people who are not authorised to see it. | Process, Data store, Data flow, Asset |
| D | Denial of service | Availability | Absorbing or destroying the resources needed to provide the service. | Process, Data store, Data flow, Asset |
| E | Elevation of privilege | Authorisation | Doing something you are not permitted to do, or gaining capabilities you were never granted. | Process |

## Appendix B · How severity was rated

Severity scale in force: **Built-in qualitative scale** — Rule base rating adjusted by the diagram context.

| Level | Score from |
| --- | --- |
| Critical | 5.5 |
| High | 4 |
| Medium | 3 |
| Low | 2 |
| Info | 0 |

| Factor | Points |
| --- | --- |
| Base rating: Info | 1 |
| Base rating: Low | 2 |
| Base rating: Medium | 3 |
| Base rating: High | 4 |
| Base rating: Critical | 6 |
| Aggravating: patientSafety | +0.5 |
| Aggravating: sensitiveData | +0.5 |
| Aggravating: externalExposure | +0.5 |
| Aggravating: markedAsset | +0.5 |
| Aggravating: safetyCriticalDoS | +0.5 |
| Mitigating: publicData | -0.5 |
| Mitigating: lowAvailabilityNeed | -0.5 |

CVSS v4.0 assessments override the modelled rating where present. Vectors are validated against the CVSS v4.0 specification; scores are entered from the NVD calculator (https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator).

