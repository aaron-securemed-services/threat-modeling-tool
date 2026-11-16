# Connected infusion pump (worked example)

STRIDE threat model report — generated 2026-11-16 23:50

- **System:** Large-volume infusion pump with hospital connectivity and a vendor cloud service
- **Author:** Teaching example
- **Date:** 2026-08-11
- **Intended use:** Continuous and bolus intravenous delivery of medication to adult and paediatric inpatients, programmed at the bedside or by auto-programming from the EHR, under the supervision of clinical staff.
- **Environment of use:** Acute-care wards and intensive care. The pump joins the hospital's clinical Wi-Fi alongside other vendors' devices and general IT. The hospital runs that network, not the manufacturer, and segmentation cannot be relied on. Pumps move between wards and are within reach of patients and visitors.
- **Scope:** In scope: the pump controller and its dose-limit interlock, the alarm path to the nurse call system, the hospital gateway, the drug library service and the vendor telemetry cloud. Out of scope: the EHR itself, hospital network infrastructure, and physical security of the ward.
- **Assumptions:** Networks are assumed hostile: an adversary can alter, drop and replay traffic. The hospital network is hostile. Clinical staff follow the programming workflow but cannot detect a value altered in transit. The EHR and the nurse call system belong to other manufacturers and are treated as untrusted peers. A visitor can reach the pump's ports unobserved for minutes at a time.
- **Safety risk management file:** Infusion Pump Risk Management File (ISO 14971) (RMF-IP-2200 rev C)
- **Methodology:** STRIDE per element. Rationale: STRIDE per element on a data flow diagram. The pump's cybersecurity risks arise at its interfaces, and a per-element sweep gives a coverage argument a reviewer can follow and repeat. Each safety-relevant function is also analysed for the hazard a compromise creates, so the result feeds the ISO 14971 file. STRIDE does not rank attacker effort, so exploitability is added per threat with CVSS v4.0.
- **Severity scale:** Built-in qualitative scale (1 of 203 threats scored with CVSS v4.0)
- **Risk acceptance:** Residual risk up to Medium is acceptable. Scored before mitigation by the model, and after mitigation by the security and safety leads together. Residual Medium or below is acceptable. High needs sign-off against clinical benefit. Critical is not acceptable. Every threat with a path to patient harm is carried into RMF-IP-2200 by its SEC-HAZ reference.

## 1. Summary

| Metric | Value |
| --- | --- |
| Elements analysed | 23 |
| Data flows | 12 |
| Trust boundaries | 3 |
| Assets | 4 |
| Threats identified | 203 |
| Threats affecting patient safety | 60 |
| Safety-relevant elements | 22 |
| Threats with a recorded decision and residual risk | 5 |
| Threats still open | 198 |

| Safety impact | What a compromise does to the patient | Threats |
| --- | --- | --- |
| Device control — Controls or actuates therapy / diagnosis | Unintended, altered or withheld therapy delivered to the patient. | 20 |
| Alarms — Generates, carries or displays alarms | A real alarm is missed or suppressed, or false alarms drive alarm fatigue and unnecessary intervention. | 18 |
| Safety stop — Implements a safety stop, interlock or limit | The protective function does not engage, or engages when it should not, removing the last barrier before harm. | 16 |
| Clinical data — Produces clinical data used for decisions | A clinical decision is made on wrong, stale or missing data. | 4 |
| Care delivery — Needed for timely care delivery | Care is delayed or cannot be delivered. | 2 |

| Severity | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- |
| Threats | 70 | 89 | 39 | 5 | 0 |

| STRIDE | Property | Threats |
| --- | --- | --- |
| S — Spoofing | Authentication | 20 |
| T — Tampering | Integrity | 65 |
| R — Repudiation | Non-repudiation | 15 |
| I — Information disclosure | Confidentiality | 33 |
| D — Denial of service | Availability | 52 |
| E — Elevation of privilege | Authorisation | 18 |

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
| Firmware and library push | Hospital gateway | Pump controller | HTTP (cleartext) | None (cleartext) | Pump enclosure (device), Hospital network |
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
| Pump controller | Process | 3 | 4 | 2 | 3 | 2 | 6 |
| Dose limit interlock | Process | 4 | 4 | 1 | 1 | 2 | 2 |
| Alarm manager | Process | 4 | 4 | 2 | 3 | 2 | 1 |
| Drug library (on device) | Data store | · | 3 | 1 | 1 | 1 | · |
| Nurse (bedside) | Entity | 1 | · | 1 | · | · | · |
| Biomed / service tech | Entity | 1 | · | 1 | · | · | · |
| Hospital gateway | Process | 4 | 6 | 3 | 3 | 4 | 6 |
| Nurse call system | Process | 2 | 3 | 1 | 1 | 3 | 1 |
| Vendor fleet service | Process | 1 | 4 | 1 | 3 | 1 | 2 |
| Telemetry & event store | Data store | · | 2 | 2 | 2 | 3 | · |
| Patient | Asset | · | 1 | · | 1 | 1 | · |
| Programme infusion | Data flow | · | 3 | · | 2 | 3 | · |
| Auto-programming order | Data flow | · | 4 | · | 2 | 3 | · |
| Firmware and library push | Data flow | · | 5 | · | 1 | 4 | · |
| Requested rate check | Data flow | · | 2 | · | 1 | 2 | · |
| Dose limits | Data flow | · | 2 | · | 1 | 2 | · |
| Alarm conditions | Data flow | · | 2 | · | 1 | 2 | · |
| Remote alarm escalation | Data flow | · | 3 | · | 2 | 3 | · |
| Drug library update | Data flow | · | 4 | · | 1 | 3 | · |
| Drug library & firmware distribution | Data flow | · | 4 | · | o | 4 | · |
| Device telemetry | Data flow | · | 2 | · | 1 | 3 | · |
| Store events | Data flow | · | o | · | o | 1 | · |
| Bedside annunciation | Data flow | · | 3 | · | 3 | 3 | · |

## 4. Threats and recommended mitigations

### Pump controller (Process)

_Firmware that computes and drives the infusion rate._

#### T-14 · [T] Therapy parameters handled by Pump controller can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

**CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H/S:P/AU:Y` — Scored with the clinical engineering team; S:P set because the subsequent system impact is the patient.

Dose, rate, duration, energy or programme values passing through Pump controller can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-002 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-16 · [D] Loss of Pump controller removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Pump controller responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-004 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-13 · [S] Therapy commands to Pump controller are not proven to come from a legitimate source — **CRITICAL**

_Spoofing — violates Authentication_

An attacker who can reach Pump controller issues therapy or actuation commands that the device accepts as clinical instructions, because nothing distinguishes them from the real controller or clinician.

_Authenticity, which includes integrity · Authentication_

> **Patient safety — SEC-HAZ-001 · Controls or actuates therapy / diagnosis**  
> **Harm:** Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Authenticate every command source cryptographically (mutual TLS, signed commands); network position is not identity.
- Bind commands to a session, a patient context and a monotonic sequence number so replayed or injected commands are rejected.
- Require confirmation at the device for changes that increase delivered therapy.

**Risk treatment:** Mitigated by design — residual **MEDIUM** — Control: SR-021 therapy commands signed by the gateway and verified at the pump; SR-022 confirmation at the pump for any rate increase — Rationale: A spoofed command is rejected at the pump. What remains is a compromised gateway signing key. — Evidence: TC-SEC-041; PT-2026-02 §5.1

#### T-15 · [E] Therapy control functions in Pump controller are reachable without a clinical authorisation decision — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A caller who is authenticated for some other purpose — a service account, a read-only integration, a patient-facing feature — can invoke the functions that change therapy, because authorisation does not separate clinical control from everything else.

_Authorization · Authorization_

> **Patient safety — SEC-HAZ-003 · Controls or actuates therapy / diagnosis**  
> **Harm:** Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Separate therapy-control operations behind their own authorisation, deny by default, and require a clinical role.
- Require step-up authentication or a second person for high-consequence changes.
- Log every therapy-control call with the authenticated identity and the resulting parameter change.

#### T-11 · [T] Updates to Pump controller are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Pump controller as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-10 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Pump controller executes it, and it executes as a privileged account.

_Authorization · Code, data and execution integrity_

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-17 · [R] Therapy changes at Pump controller cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-005 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** Over-infusion of a high-alert medication. The controller drives the actuator directly, so any altered rate or programme becomes delivered therapy within one pump cycle.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-001, HAZ-004, RC-011

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-02 · [T] Untrusted input reaches Pump controller without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Pump controller is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-05 · [I] Weak authorisation over sensitive data in Pump controller — **HIGH**

_Information disclosure — violates Confidentiality_

Pump controller handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-12 · [I] A secret held by Pump controller is the same on every device — **HIGH**

_Information disclosure — violates Confidentiality_

The credential or key Pump controller relies on is hardcoded, left at its default, or shared across the product line. Extracting it once - from one device, a firmware image or a manual - yields access to every device that carries it.

_Confidentiality · Cryptography · Lifecycle: Manufacturing, Deployment_

**Recommended mitigations:**
- Provision a unique credential or key pair per device at manufacture; never derive keys from serial numbers or other discoverable identifiers.
- Remove hardcoded and default passwords; force a change at commissioning where a password has to exist.
- Use public-key schemes so that nothing extracted from one device authenticates as another.

#### T-09 · [E] Coarse authorisation in Pump controller — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

_Authorization · Authorization_

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-196 · [S] Unauthenticated inbound flow "Auto-programming order" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Auto-programming order" from Hospital gateway carry no proof of who sent them. Pump controller therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Auto-programming order

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-07 · [D] Pump controller has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Pump controller has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-197 · [E] Privilege crosses a trust boundary into Pump controller — **HIGH**

_Elevation of privilege — violates Authorisation_

"Auto-programming order" enters Pump controller across the trust boundary "Pump enclosure (device)" / "Hospital network" without an authorisation decision of its own. Whatever the caller can request, Pump controller will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: Auto-programming order

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-01 · [S] Clients cannot verify they are talking to the real Pump controller — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Pump controller. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-03 · [T] Integrity of the code and configuration of Pump controller — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Pump controller runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-04 · [R] Pump controller keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Pump controller cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-08 · [E] Pump controller holds a broadly privileged service account — **HIGH**

_Elevation of privilege — violates Authorisation_

Compromising Pump controller yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

_Authorization · Authorization_

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

#### T-198 · [E] Privilege crosses a trust boundary into Pump controller — **HIGH**

_Elevation of privilege — violates Authorisation_

"Firmware and library push" enters Pump controller across the trust boundary "Pump enclosure (device)" / "Hospital network" without an authorisation decision of its own. Whatever the caller can request, Pump controller will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: Firmware and library push

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-06 · [I] Leakage through errors, responses and telemetry from Pump controller — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Pump controller - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Vendor fleet service (Process)

_Telemetry, drug library distribution and firmware updates._

#### T-98 · [T] Safety limits or interlock configuration at Vendor fleet service can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Vendor fleet service can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-029 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-100 · [T] Therapy parameters handled by Vendor fleet service can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Vendor fleet service can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-031 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-99 · [D] The safety stop in Vendor fleet service may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Vendor fleet service. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-030 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-96 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Vendor fleet service executes it, and it executes as a privileged account.

_Authorization · Code, data and execution integrity · Multi-patient_

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-101 · [R] Therapy changes at Vendor fleet service cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

> **Patient safety — SEC-HAZ-032 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide safety event, not a single-device one.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-91 · [T] Untrusted input reaches Vendor fleet service without strict validation — **CRITICAL**

_Tampering — violates Integrity_

Input crossing into Vendor fleet service is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-90 · [S] Clients cannot verify they are talking to the real Vendor fleet service — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Vendor fleet service. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-92 · [T] Integrity of the code and configuration of Vendor fleet service — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Vendor fleet service runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain · Multi-patient_

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-94 · [I] Regulated data may be copied into logs by Vendor fleet service — **HIGH**

_Information disclosure — violates Confidentiality_

Vendor fleet service handles regulated data and logs heavily. Logs are usually held longer, replicated further and read by more people than the primary store, so they quietly become a second, less protected copy of the sensitive data.

_Confidentiality · Confidentiality · Multi-patient_

**Recommended mitigations:**
- Redact or tokenise identifiers and payloads before they are written to logs.
- Apply the same classification, access control and retention to logs as to the primary store.
- Review log sinks (aggregators, crash reporters, APM vendors) as part of the data flow.

#### T-95 · [E] Vendor fleet service holds a broadly privileged service account — **HIGH**

_Elevation of privilege — violates Authorisation_

Compromising Vendor fleet service yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

_Authorization · Authorization · Multi-patient_

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

#### T-93 · [I] Leakage through errors, responses and telemetry from Vendor fleet service — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Vendor fleet service - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment · Multi-patient_

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

#### T-97 · [I] Keys held by Vendor fleet service can be read out of storage — **MEDIUM**

_Information disclosure — violates Confidentiality_

The keys are unique to the device but live in ordinary storage. Anyone with the device in their hands, a filesystem image or code execution in Vendor fleet service can copy them and impersonate this device from elsewhere.

_Confidentiality · Cryptography · Lifecycle: Manufacturing · Multi-patient_

**Recommended mitigations:**
- Hold keys in a secure element, TPM or hardware-backed keystore so they can be used but not exported.
- Limit what a single device key can do, and be able to revoke it.

### Auto-programming order (Data flow)

_Pharmacy order pushed to the pump from the EHR._

#### T-130 · [D] Loss of Auto-programming order removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Auto-programming order responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-038 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-004

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-129 · [T] Therapy parameters handled by Auto-programming order can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Auto-programming order can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-037 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-004

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-122 · [T] Traffic on "Auto-programming order" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-128 · [T] Commands on "Auto-programming order" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-124 · [I] Data on "Auto-programming order" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-126 · [D] "Auto-programming order" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-123 · [T] No end-to-end integrity on "Auto-programming order" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-125 · [I] Sensitive data leaves a trust boundary on "Auto-programming order" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-127 · [D] Availability of "Auto-programming order" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Drug library & firmware distribution (Data flow)

_Fleet-wide updates pushed to the hospital._

#### T-176 · [T] Safety limits or interlock configuration at Drug library & firmware distribution can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Drug library & firmware distribution can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-053 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-178 · [T] Therapy parameters handled by Drug library & firmware distribution can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Drug library & firmware distribution can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-055 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-177 · [D] The safety stop in Drug library & firmware distribution may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Drug library & firmware distribution. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-054 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-179 · [D] Loss of Drug library & firmware distribution removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Drug library & firmware distribution responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-056 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-175 · [T] Code delivered over "Drug library & firmware distribution" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-172 · [T] No end-to-end integrity on "Drug library & firmware distribution" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-173 · [D] "Drug library & firmware distribution" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-174 · [D] Availability of "Drug library & firmware distribution" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Dose limit interlock (Process)

_Independent hard-limit check before actuation._

#### T-29 · [D] The safety stop in Dose limit interlock may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Dose limit interlock. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-008 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> **Hazardous situation (as modelled):** This is the last barrier between a wrong programmed dose and the patient. If its limits are widened, or it does not get to run, nothing else stops an unsafe infusion.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-011, RC-012

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-27 · [T] Safety limits or interlock configuration at Dose limit interlock can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Dose limit interlock can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-006 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** This is the last barrier between a wrong programmed dose and the patient. If its limits are widened, or it does not get to run, nothing else stops an unsafe infusion.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-011, RC-012

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

**Risk treatment:** Mitigated by design — residual **HIGH** (above the acceptance threshold) — Control: SR-030 absolute hard limit in firmware that no drug library entry can widen — Rationale: Library tampering is bounded by the firmware limit, but soft limits can still be widened until the signed drug library ships in release 2.1. — **no verification evidence referenced**

#### T-28 · [E] The safety stop in Dose limit interlock can be overridden without proper authority — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Override, service, maintenance or "clinical justification" paths that disable the interlock are reachable by a caller who should not have them — a normal user, a service tool, or anything that has learned the shared override credential.

_Authorization · Authorization_

> **Patient safety — SEC-HAZ-007 · Implements a safety stop, interlock or limit**  
> **Harm:** The protective stop is bypassed and the patient is exposed to exactly the hazard it was implemented to control.  
> **Hazardous situation (as modelled):** This is the last barrier between a wrong programmed dose and the patient. If its limits are widened, or it does not get to run, nothing else stops an unsafe infusion.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-011, RC-012

**Recommended mitigations:**
- Require a distinct, strongly authenticated role for any override, with per-use authorisation rather than a mode that stays on.
- Make overrides time-boxed and self-expiring, and annunciate continuously while one is active.
- Log every override with identity, reason and duration, and review them as a safety signal.
- Remove service backdoors and default maintenance credentials from production devices.

#### T-26 · [T] Updates to Dose limit interlock are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Dose limit interlock as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-18 · [S] Dose limit interlock accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Dose limit interlock is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-20 · [T] Untrusted input reaches Dose limit interlock without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Dose limit interlock is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-25 · [E] No effective authorisation model in Dose limit interlock — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-199 · [S] Unauthenticated inbound flow "Requested rate check" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Requested rate check" from Pump controller carry no proof of who sent them. Dose limit interlock therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Requested rate check

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-200 · [S] Unauthenticated inbound flow "Dose limits" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Dose limits" from Drug library (on device) carry no proof of who sent them. Dose limit interlock therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Dose limits

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-24 · [D] Dose limit interlock has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Dose limit interlock has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-19 · [S] Clients cannot verify they are talking to the real Dose limit interlock — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Dose limit interlock. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-21 · [T] Integrity of the code and configuration of Dose limit interlock — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Dose limit interlock runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-22 · [R] Dose limit interlock keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Dose limit interlock cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-23 · [I] Leakage through errors, responses and telemetry from Dose limit interlock — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Dose limit interlock - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Hospital gateway (Process)

_Bridges pumps to hospital systems and the vendor cloud._

#### T-73 · [D] Loss of Hospital gateway removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Hospital gateway responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-017 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-76 · [D] Alarm delivery through Hospital gateway can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Hospital gateway, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-020 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-70 · [S] Therapy commands to Hospital gateway are not proven to come from a legitimate source — **CRITICAL**

_Spoofing — violates Authentication_

An attacker who can reach Hospital gateway issues therapy or actuation commands that the device accepts as clinical instructions, because nothing distinguishes them from the real controller or clinician.

_Authenticity, which includes integrity · Authentication · Multi-patient_

> **Patient safety — SEC-HAZ-014 · Controls or actuates therapy / diagnosis**  
> **Harm:** Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Authenticate every command source cryptographically (mutual TLS, signed commands); network position is not identity.
- Bind commands to a session, a patient context and a monotonic sequence number so replayed or injected commands are rejected.
- Require confirmation at the device for changes that increase delivered therapy.

#### T-77 · [S] Alarms carried by Hospital gateway cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Hospital gateway can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication · Multi-patient_

> **Patient safety — SEC-HAZ-021 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-71 · [T] Therapy parameters handled by Hospital gateway can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Hospital gateway can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-015 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-75 · [T] Alarm conditions or thresholds at Hospital gateway can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Hospital gateway. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-019 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-65 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Hospital gateway executes it, and it executes as a privileged account.

_Authorization · Code, data and execution integrity · Multi-patient_

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-72 · [E] Therapy control functions in Hospital gateway are reachable without a clinical authorisation decision — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A caller who is authenticated for some other purpose — a service account, a read-only integration, a patient-facing feature — can invoke the functions that change therapy, because authorisation does not separate clinical control from everything else.

_Authorization · Authorization · Multi-patient_

> **Patient safety — SEC-HAZ-016 · Controls or actuates therapy / diagnosis**  
> **Harm:** Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Separate therapy-control operations behind their own authorisation, deny by default, and require a clinical role.
- Require step-up authentication or a second person for high-consequence changes.
- Log every therapy-control call with the authenticated identity and the resulting parameter change.

#### T-79 · [D] Loss of Hospital gateway delays or prevents care — **CRITICAL**

_Denial of service — violates Availability_

Hospital gateway is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-023 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-74 · [R] Therapy changes at Hospital gateway cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

> **Patient safety — SEC-HAZ-018 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-78 · [R] Alarm history at Hospital gateway is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Hospital gateway.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

> **Patient safety — SEC-HAZ-022 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** Carries auto-programming orders towards the pump and alarms away from it. A compromise here reaches every pump on the ward at once.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-004, HAZ-007

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-55 · [S] Hospital gateway accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Hospital gateway is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-57 · [T] Untrusted input reaches Hospital gateway without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Hospital gateway is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-60 · [I] Weak authorisation over sensitive data in Hospital gateway — **HIGH**

_Information disclosure — violates Confidentiality_

Hospital gateway handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization · Multi-patient_

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-63 · [E] No effective authorisation model in Hospital gateway — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization · Multi-patient_

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-68 · [E] Hospital gateway runs software that no longer receives security fixes — **HIGH**

_Elevation of privilege — violates Authorisation_

Vulnerabilities in the software behind Hospital gateway will keep being published and will never be patched upstream. Each one is a ready-made way into the device for anyone who reads the advisory.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain, Maintenance and update · Multi-patient_

**Recommended mitigations:**
- Plan the replacement or in-house maintenance of the component before its support ends, not after.
- Keep the design modular enough that a third-party component can be swapped.
- Until then, reduce what can reach it, and tell users what they need to know to manage the risk.

**Risk treatment:** Transferred to the user (disclosed in labeling) — residual **HIGH** (above the acceptance threshold) — Rationale: The gateway OS image is past end of support. Hospitals are told to isolate it on its own VLAN (IFU §9.3) until the 3.0 image ships.

#### T-203 · [E] Privilege crosses a trust boundary into Hospital gateway — **HIGH**

_Elevation of privilege — violates Authorisation_

"Drug library & firmware distribution" enters Hospital gateway across the trust boundary "Hospital network" / "Vendor cloud" without an authorisation decision of its own. Whatever the caller can request, Hospital gateway will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation · Multi-patient_

Via data flow: Drug library & firmware distribution

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-62 · [D] Hospital gateway has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Hospital gateway has, taking it down for everyone.

_Availability · Resiliency and recovery · Multi-patient_

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-56 · [S] Clients cannot verify they are talking to the real Hospital gateway — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Hospital gateway. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-58 · [T] Integrity of the code and configuration of Hospital gateway — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Hospital gateway runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain · Multi-patient_

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-66 · [T] Hospital gateway can be rolled back to a vulnerable release — **HIGH**

_Tampering — violates Integrity_

An older image of Hospital gateway is still validly signed. An attacker who can present it reinstates every vulnerability that later releases fixed, without breaking any signature check.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update · Multi-patient_

**Recommended mitigations:**
- Enforce a monotonic version counter held where the update itself cannot rewrite it.
- Allow a downgrade only through separately signed downgrade metadata, and log it.
- Make the installed version visible to the operator and in the audit trail.

#### T-67 · [T] Third-party software in Hospital gateway is not traced to an SBOM — **HIGH**

_Tampering — violates Integrity_

Hospital gateway is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain · Multi-patient_

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-59 · [R] Hospital gateway keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Hospital gateway cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-64 · [E] Hospital gateway holds a broadly privileged service account — **HIGH**

_Elevation of privilege — violates Authorisation_

Compromising Hospital gateway yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.

_Authorization · Authorization · Multi-patient_

**Recommended mitigations:**
- Give the component its own identity scoped to exactly the resources and verbs it uses.
- Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.
- Review the account's permissions on a schedule and alert on privilege changes.

#### T-61 · [I] Leakage through errors, responses and telemetry from Hospital gateway — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Hospital gateway - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment · Multi-patient_

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

#### T-69 · [I] Keys held by Hospital gateway can be read out of storage — **MEDIUM**

_Information disclosure — violates Confidentiality_

The keys are unique to the device but live in ordinary storage. Anyone with the device in their hands, a filesystem image or code execution in Hospital gateway can copy them and impersonate this device from elsewhere.

_Confidentiality · Cryptography · Lifecycle: Manufacturing · Multi-patient_

**Recommended mitigations:**
- Hold keys in a secure element, TPM or hardware-backed keystore so they can be used but not exported.
- Limit what a single device key can do, and be able to revoke it.

### Nurse call system (Process)

_Escalates device alarms to staff handsets._

#### T-86 · [D] Alarm delivery through Nurse call system can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Nurse call system, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-025 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-87 · [S] Alarms carried by Nurse call system cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Nurse call system can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication · Multi-patient_

> **Patient safety — SEC-HAZ-026 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-85 · [T] Alarm conditions or thresholds at Nurse call system can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Nurse call system. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-024 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-89 · [D] Loss of Nurse call system delays or prevents care — **CRITICAL**

_Denial of service — violates Availability_

Nurse call system is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-028 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-88 · [R] Alarm history at Nurse call system is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Nurse call system.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

> **Patient safety — SEC-HAZ-027 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is the only remaining barrier.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: HAZ-007, RC-021

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-81 · [T] Untrusted input reaches Nurse call system without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Nurse call system is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-202 · [E] Privilege crosses a trust boundary into Nurse call system — **HIGH**

_Elevation of privilege — violates Authorisation_

"Remote alarm escalation" enters Nurse call system across the trust boundary "Pump enclosure (device)" / "Hospital network" without an authorisation decision of its own. Whatever the caller can request, Nurse call system will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation · Multi-patient_

Via data flow: Remote alarm escalation

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-84 · [D] Nurse call system has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Nurse call system has, taking it down for everyone.

_Availability · Resiliency and recovery · Multi-patient_

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-80 · [S] Clients cannot verify they are talking to the real Nurse call system — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Nurse call system. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-82 · [T] Integrity of the code and configuration of Nurse call system — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Nurse call system runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain · Multi-patient_

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-83 · [I] Leakage through errors, responses and telemetry from Nurse call system — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Nurse call system - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment · Multi-patient_

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Programme infusion (Data flow)

_Rate, dose and duration entered at the bedside._

#### T-121 · [D] Loss of Programme infusion removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Programme infusion responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-036 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-002

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-120 · [T] Therapy parameters handled by Programme infusion can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Programme infusion can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-035 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-002

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-114 · [T] Traffic on "Programme infusion" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-116 · [I] Data on "Programme infusion" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-118 · [D] "Programme infusion" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-115 · [T] No end-to-end integrity on "Programme infusion" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-117 · [I] Sensitive data leaves a trust boundary on "Programme infusion" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-119 · [D] Availability of "Programme infusion" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Firmware and library push (Data flow)

_Firmware images and drug libraries relayed from the vendor to each pump._

#### T-138 · [D] Loss of Firmware and library push removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Firmware and library push responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-040 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> **Hazardous situation (as modelled):** Whatever arrives here becomes the software that drives the pump and the limits that constrain it.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-140 · [D] The safety stop in Firmware and library push may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Firmware and library push. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-042 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> **Hazardous situation (as modelled):** Whatever arrives here becomes the software that drives the pump and the limits that constrain it.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-137 · [T] Therapy parameters handled by Firmware and library push can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Firmware and library push can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-039 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** Whatever arrives here becomes the software that drives the pump and the limits that constrain it.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-139 · [T] Safety limits or interlock configuration at Firmware and library push can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Firmware and library push can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-041 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** Whatever arrives here becomes the software that drives the pump and the limits that constrain it.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-011

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-136 · [T] Code delivered over "Firmware and library push" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-131 · [T] Traffic on "Firmware and library push" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-133 · [I] Data on "Firmware and library push" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-134 · [D] "Firmware and library push" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-132 · [T] No end-to-end integrity on "Firmware and library push" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-135 · [D] Availability of "Firmware and library push" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Drug library (on device) (Data store)

_Dose limits and concentrations per medication._

#### T-50 · [T] Safety limits or interlock configuration at Drug library (on device) can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Drug library (on device) can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-013 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> **Hazardous situation (as modelled):** The limits the interlock enforces. Tampering here silently widens what the pump will accept as a legitimate dose.  
> Severity of harm: Catastrophic — patient death · Software safety class: Class C — death or serious injury possible · Safety file: RC-012

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-46 · [T] Unrestricted write access to Drug library (on device) — **HIGH**

_Tampering — violates Integrity_

Write access to Drug library (on device) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

_Authorization · Authorization_

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-48 · [I] Weak access control on Drug library (on device) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Drug library (on device) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

_Confidentiality · Authentication_

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-45 · [T] Modification of Drug library (on device) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Drug library (on device) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-47 · [R] No access log for Drug library (on device) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Drug library (on device) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-49 · [D] Resource exhaustion against Drug library (on device) — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Drug library (on device) unavailable without any need to break into it.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Alarm manager (Process)

_Detects alarm conditions and annunciates locally and remotely._

#### T-42 · [D] Alarm delivery through Alarm manager can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Alarm manager, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-010 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

**Risk treatment:** Mitigated by compensating control — residual **MEDIUM** — Control: Audible and visual annunciation at the pump does not depend on the network path — Rationale: Remote escalation can still be blocked; the bedside alarm cannot. — Evidence: TC-ALM-112

#### T-43 · [S] Alarms carried by Alarm manager cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Alarm manager can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication_

> **Patient safety — SEC-HAZ-011 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-39 · [T] Updates to Alarm manager are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Alarm manager as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-41 · [T] Alarm conditions or thresholds at Alarm manager can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Alarm manager. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-009 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-44 · [R] Alarm history at Alarm manager is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Alarm manager.

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-012 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration goes unnoticed; injected false alarms cause alarm fatigue on the ward.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: HAZ-007

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-30 · [S] Alarm manager accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Alarm manager is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-201 · [S] Unauthenticated inbound flow "Alarm conditions" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Alarm conditions" from Pump controller carry no proof of who sent them. Alarm manager therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Alarm conditions

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-32 · [T] Untrusted input reaches Alarm manager without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Alarm manager is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-35 · [I] Weak authorisation over sensitive data in Alarm manager — **HIGH**

_Information disclosure — violates Confidentiality_

Alarm manager handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-40 · [I] A secret held by Alarm manager is the same on every device — **HIGH**

_Information disclosure — violates Confidentiality_

The credential or key Alarm manager relies on is hardcoded, left at its default, or shared across the product line. Extracting it once - from one device, a firmware image or a manual - yields access to every device that carries it.

_Confidentiality · Cryptography · Lifecycle: Manufacturing, Deployment_

**Recommended mitigations:**
- Provision a unique credential or key pair per device at manufacture; never derive keys from serial numbers or other discoverable identifiers.
- Remove hardcoded and default passwords; force a change at commissioning where a password has to exist.
- Use public-key schemes so that nothing extracted from one device authenticates as another.

#### T-38 · [E] No effective authorisation model in Alarm manager — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-37 · [D] Alarm manager has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Alarm manager has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-31 · [S] Clients cannot verify they are talking to the real Alarm manager — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Alarm manager. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-33 · [T] Integrity of the code and configuration of Alarm manager — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Alarm manager runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-34 · [R] Alarm manager keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Alarm manager cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-36 · [I] Leakage through errors, responses and telemetry from Alarm manager — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Alarm manager - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Requested rate check (Data flow)

_Every programmed rate is checked against the hard limits._

#### T-145 · [D] The safety stop in Requested rate check may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Requested rate check. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-044 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-011

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-144 · [T] Safety limits or interlock configuration at Requested rate check can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Requested rate check can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-043 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-011

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-141 · [T] Traffic on "Requested rate check" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-142 · [I] Data on "Requested rate check" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-143 · [D] Availability of "Requested rate check" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Dose limits (Data flow)

_Limits the interlock enforces._

#### T-150 · [D] The safety stop in Dose limits may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Dose limits. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-046 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-012

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-149 · [T] Safety limits or interlock configuration at Dose limits can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Dose limits can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-045 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: RC-012

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-146 · [T] Traffic on "Dose limits" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-147 · [I] Data on "Dose limits" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-148 · [D] Availability of "Dose limits" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Alarm conditions (Data flow)

_Occlusion, air-in-line, battery and completion events._

#### T-155 · [D] Alarm delivery through Alarm conditions can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Alarm conditions, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-048 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-154 · [T] Alarm conditions or thresholds at Alarm conditions can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Alarm conditions. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-047 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-151 · [T] Traffic on "Alarm conditions" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-152 · [I] Data on "Alarm conditions" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-153 · [D] Availability of "Alarm conditions" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Remote alarm escalation (Data flow)

_Alarms forwarded to staff handsets._

#### T-163 · [D] Alarm delivery through Remote alarm escalation can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Remote alarm escalation, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-050 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007, RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-162 · [T] Alarm conditions or thresholds at Remote alarm escalation can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Remote alarm escalation. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-049 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: HAZ-007, RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-156 · [T] Traffic on "Remote alarm escalation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-158 · [I] Data on "Remote alarm escalation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-160 · [D] "Remote alarm escalation" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-157 · [T] No end-to-end integrity on "Remote alarm escalation" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-159 · [I] Sensitive data leaves a trust boundary on "Remote alarm escalation" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-161 · [D] Availability of "Remote alarm escalation" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside annunciation (Data flow)

_Audible and visual alarm at the pump._

#### T-195 · [D] Alarm delivery through Bedside annunciation can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside annunciation, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-060 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-194 · [T] Alarm conditions or thresholds at Bedside annunciation can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside annunciation. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-059 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: RC-021

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-187 · [T] Traffic on "Bedside annunciation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-189 · [I] Data on "Bedside annunciation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-192 · [D] "Bedside annunciation" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-188 · [T] No end-to-end integrity on "Bedside annunciation" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-190 · [I] Sensitive data leaves a trust boundary on "Bedside annunciation" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Pump enclosure (device)" / "Hospital network". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-191 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

_Confidentiality · Confidentiality_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-193 · [D] Availability of "Bedside annunciation" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Drug library update (Data flow)

_Service tooling writes new dose limits to the pump._

#### T-170 · [T] Safety limits or interlock configuration at Drug library update can be modified — **CRITICAL**

_Tampering — violates Integrity_

The hard limits, dose caps, drug library, interlock rules or fail-safe configuration held or carried by Drug library update can be changed by an attacker. The protective function still appears present but no longer constrains anything meaningful.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-051 · Implements a safety stop, interlock or limit**  
> **Harm:** The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: HAZ-009

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Hold safety limits in signed, integrity-checked configuration verified at load and periodically at run time.
- Enforce an absolute hard limit in firmware or hardware that no configuration or network message can widen.
- Treat a change to a safety limit as a controlled change: authenticated, authorised, logged, and visible to the clinician.
- Alarm when the running limits differ from the approved set.

#### T-171 · [D] The safety stop in Drug library update may not run when it is needed — **CRITICAL**

_Denial of service — violates Availability_

Resource exhaustion, flooding or a hung dependency starves the watchdog, monitor or interlock logic in Drug library update. The protective function is not removed — it simply does not get to execute in time, or cannot reach the actuator to stop it.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-052 · Implements a safety stop, interlock or limit**  
> **Harm:** The device continues in an unsafe state because the mechanism that should have stopped it never ran.  
> Severity of harm: Catastrophic — patient death · Software safety class: not set · Safety file: HAZ-009

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Run the safety monitor independently of the application: separate task, separate watchdog, ideally separate processor.
- Give it a guaranteed execution budget that untrusted work cannot consume, and a hardware watchdog behind it.
- Design the failure direction deliberately: on loss of the monitor, the device goes to the safe state rather than continuing.
- Test the interlock under load and under attack conditions, not only on an idle bench.

#### T-169 · [T] Code delivered over "Drug library update" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-164 · [T] Traffic on "Drug library update" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-166 · [I] Data on "Drug library update" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-165 · [T] No end-to-end integrity on "Drug library update" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-167 · [D] "Drug library update" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-168 · [D] Availability of "Drug library update" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Pump enclosure (device), Hospital network

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Device telemetry (Data flow)

_Infusion and alarm events sent to the vendor._

#### T-184 · [T] Clinical data at Device telemetry can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Device telemetry, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-057 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: HAZ-013

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-185 · [D] Clinical data from Device telemetry may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Device telemetry unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-058 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: HAZ-013

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-180 · [T] No end-to-end integrity on "Device telemetry" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-181 · [I] Sensitive data leaves a trust boundary on "Device telemetry" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Hospital network" / "Vendor cloud". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-182 · [D] "Device telemetry" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-183 · [D] Availability of "Device telemetry" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Hospital network, Vendor cloud

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Telemetry & event store (Data store)

_Infusion events, alarms and device logs._

#### T-109 · [T] Clinical data at Telemetry & event store can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Telemetry & event store, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

> **Patient safety — SEC-HAZ-033 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class A — no injury possible · Safety file: HAZ-013

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-110 · [D] Clinical data from Telemetry & event store may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Telemetry & event store unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery · Multi-patient_

> **Patient safety — SEC-HAZ-034 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class A — no injury possible · Safety file: HAZ-013

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-104 · [R] Regulated records in Telemetry & event store without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Telemetry & event store holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-106 · [D] Loss of Telemetry & event store may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Telemetry & event store - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

_Availability · Resiliency and recovery · Multi-patient_

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-102 · [T] Modification of Telemetry & event store would go unnoticed — **HIGH**

_Tampering — violates Integrity_

Nothing proves that the contents of Telemetry & event store are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-103 · [R] No access log for Telemetry & event store — **HIGH**

_Repudiation — violates Non-repudiation_

Reads and writes against Telemetry & event store are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-105 · [I] Backups of Telemetry & event store are a second copy of the sensitive data — **HIGH**

_Information disclosure — violates Confidentiality_

Backups and snapshots of Telemetry & event store carry the same sensitive contents but usually live somewhere with looser access control, longer retention and less monitoring than the primary store.

_Confidentiality · Confidentiality · Multi-patient_

**Recommended mitigations:**
- Encrypt backups with their own keys and restrict who can restore them.
- Apply the same classification and retention rules to backups as to production data.
- Audit restore operations - a restore is an easy way to exfiltrate a whole database.

#### T-108 · [I] Sensitive data in Telemetry & event store outlives the device's time in service — **MEDIUM**

_Information disclosure — violates Confidentiality_

When the device is returned, repaired, resold or thrown away, Telemetry & event store still holds patient data and credentials. Whoever handles it next has the device in their hands and all the time they need.

_Confidentiality · Confidentiality · Lifecycle: Decommission · Multi-patient_

**Recommended mitigations:**
- Provide a sanitisation function that erases data and credentials, and say how to use it in the labeling.
- Encrypt with a key that can be destroyed, so erasure does not depend on overwriting every block.
- Revoke the device's identity and credentials on the server side when it leaves service.

#### T-107 · [D] Resource exhaustion against Telemetry & event store — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Telemetry & event store unavailable without any need to break into it.

_Availability · Resiliency and recovery · Multi-patient_

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Nurse (bedside) (Entity)

_Programmes the infusion at the pump and responds to alarms._

#### T-51 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate Nurse (bedside). Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-52 · [R] Actions by Nurse (bedside) are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Nurse (bedside) did. Nurse (bedside) can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

**Risk treatment:** Accepted — residual **LOW** — Rationale: Programming at the bedside is attributed through the ward's medication administration record rather than by the pump.

### Patient (Asset)

#### T-112 · [D] Availability of the asset Patient — **HIGH**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

#### T-113 · [T] Integrity of the asset Patient — **HIGH**

_Tampering — violates Integrity_

If Patient can be altered without detection, decisions made from it are wrong in a way nobody notices. Corruption of a valuable record is often more damaging, and much harder to spot, than its disclosure.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Establish an authoritative source and reconcile copies against it.
- Keep a tamper-evident history of changes with attribution.

#### T-111 · [I] Confidentiality of the asset Patient — **HIGH**

_Information disclosure — violates Confidentiality_

Patient is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

_Confidentiality · Confidentiality_

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

### Biomed / service tech (Entity)

_Services the pump and updates the drug library._

#### T-53 · [S] Shared secret identifies Biomed / service tech — **MEDIUM**

_Spoofing — violates Authentication_

Identity rests on a bearer secret. Anyone who obtains the key from source control, a log, a config file or a backup becomes Biomed / service tech, and the theft leaves no trace.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Recommended mitigations:**
- Move to short-lived tokens or mutual TLS so a leaked value expires quickly.
- Store keys in a secret manager, scope them narrowly, and support rotation without downtime.
- Scan repositories and logs for leaked keys.

#### T-54 · [R] Actions by Biomed / service tech are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Biomed / service tech did. Biomed / service tech can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### Store events (Data flow)

_Telemetry written to the event store._

#### T-186 · [D] Availability of "Store events" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery · Multi-patient_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

## 5. Patient safety traceability

Each row is a security threat with a credible path to patient harm. Carry the hazard reference into the safety risk management file (Infusion Pump Risk Management File (ISO 14971), RMF-IP-2200 rev C) so the security control and the safety risk control are the same decision.

| Hazard ref | Threat | Element | STRIDE | Safety impact | Hazardous situation -> harm | Severity of harm | Severity | Safety file ref |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-HAZ-001 | T-13 | Pump controller | S | Device control | Therapy commands to Pump controller are not proven to come from a legitimate source -> Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-002 | T-14 | Pump controller | T | Device control | Therapy parameters handled by Pump controller can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-003 | T-15 | Pump controller | E | Device control | Therapy control functions in Pump controller are reachable without a clinical authorisation decision -> Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-004 | T-16 | Pump controller | D | Device control | Loss of Pump controller removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-005 | T-17 | Pump controller | R | Device control | Therapy changes at Pump controller cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Catastrophic — patient death | CRITICAL | HAZ-001, HAZ-004, RC-011 |
| SEC-HAZ-006 | T-27 | Dose limit interlock | T | Safety stop | Safety limits or interlock configuration at Dose limit interlock can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-011, RC-012 |
| SEC-HAZ-007 | T-28 | Dose limit interlock | E | Safety stop | The safety stop in Dose limit interlock can be overridden without proper authority -> The protective stop is bypassed and the patient is exposed to exactly the hazard it was implemented to control. | Catastrophic — patient death | CRITICAL | RC-011, RC-012 |
| SEC-HAZ-008 | T-29 | Dose limit interlock | D | Safety stop | The safety stop in Dose limit interlock may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | RC-011, RC-012 |
| SEC-HAZ-009 | T-41 | Alarm manager | T | Alarms | Alarm conditions or thresholds at Alarm manager can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-010 | T-42 | Alarm manager | D | Alarms | Alarm delivery through Alarm manager can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-011 | T-43 | Alarm manager | S | Alarms | Alarms carried by Alarm manager cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-012 | T-44 | Alarm manager | R | Alarms | Alarm history at Alarm manager is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-013 | T-50 | Drug library (on device) | T | Safety stop | Safety limits or interlock configuration at Drug library (on device) can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-012 |
| SEC-HAZ-014 | T-70 | Hospital gateway | S | Device control | Therapy commands to Hospital gateway are not proven to come from a legitimate source -> Unintended therapy is delivered to the patient — wrong dose, wrong rate, wrong energy, or delivery to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-015 | T-71 | Hospital gateway | T | Device control | Therapy parameters handled by Hospital gateway can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-016 | T-72 | Hospital gateway | E | Device control | Therapy control functions in Hospital gateway are reachable without a clinical authorisation decision -> Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-017 | T-73 | Hospital gateway | D | Device control | Loss of Hospital gateway removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-018 | T-74 | Hospital gateway | R | Device control | Therapy changes at Hospital gateway cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-019 | T-75 | Hospital gateway | T | Alarms | Alarm conditions or thresholds at Hospital gateway can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-020 | T-76 | Hospital gateway | D | Alarms | Alarm delivery through Hospital gateway can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-021 | T-77 | Hospital gateway | S | Alarms | Alarms carried by Hospital gateway cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-022 | T-78 | Hospital gateway | R | Alarms | Alarm history at Hospital gateway is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-023 | T-79 | Hospital gateway | D | Care delivery | Loss of Hospital gateway delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-004, HAZ-007 |
| SEC-HAZ-024 | T-85 | Nurse call system | T | Alarms | Alarm conditions or thresholds at Nurse call system can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-025 | T-86 | Nurse call system | D | Alarms | Alarm delivery through Nurse call system can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-026 | T-87 | Nurse call system | S | Alarms | Alarms carried by Nurse call system cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-027 | T-88 | Nurse call system | R | Alarms | Alarm history at Nurse call system is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-028 | T-89 | Nurse call system | D | Care delivery | Loss of Nurse call system delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-029 | T-98 | Vendor fleet service | T | Safety stop | Safety limits or interlock configuration at Vendor fleet service can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-030 | T-99 | Vendor fleet service | D | Safety stop | The safety stop in Vendor fleet service may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-031 | T-100 | Vendor fleet service | T | Device control | Therapy parameters handled by Vendor fleet service can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-032 | T-101 | Vendor fleet service | R | Device control | Therapy changes at Vendor fleet service cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-033 | T-109 | Telemetry & event store | T | Clinical data | Clinical data at Telemetry & event store can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-034 | T-110 | Telemetry & event store | D | Clinical data | Clinical data from Telemetry & event store may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-035 | T-120 | Programme infusion | T | Device control | Therapy parameters handled by Programme infusion can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-002 |
| SEC-HAZ-036 | T-121 | Programme infusion | D | Device control | Loss of Programme infusion removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-002 |
| SEC-HAZ-037 | T-129 | Auto-programming order | T | Device control | Therapy parameters handled by Auto-programming order can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-004 |
| SEC-HAZ-038 | T-130 | Auto-programming order | D | Device control | Loss of Auto-programming order removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-004 |
| SEC-HAZ-039 | T-137 | Firmware and library push | T | Device control | Therapy parameters handled by Firmware and library push can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-040 | T-138 | Firmware and library push | D | Device control | Loss of Firmware and library push removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-041 | T-139 | Firmware and library push | T | Safety stop | Safety limits or interlock configuration at Firmware and library push can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-042 | T-140 | Firmware and library push | D | Safety stop | The safety stop in Firmware and library push may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-043 | T-144 | Requested rate check | T | Safety stop | Safety limits or interlock configuration at Requested rate check can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-011 |
| SEC-HAZ-044 | T-145 | Requested rate check | D | Safety stop | The safety stop in Requested rate check may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | RC-011 |
| SEC-HAZ-045 | T-149 | Dose limits | T | Safety stop | Safety limits or interlock configuration at Dose limits can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | RC-012 |
| SEC-HAZ-046 | T-150 | Dose limits | D | Safety stop | The safety stop in Dose limits may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | RC-012 |
| SEC-HAZ-047 | T-154 | Alarm conditions | T | Alarms | Alarm conditions or thresholds at Alarm conditions can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-048 | T-155 | Alarm conditions | D | Alarms | Alarm delivery through Alarm conditions can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007 |
| SEC-HAZ-049 | T-162 | Remote alarm escalation | T | Alarms | Alarm conditions or thresholds at Remote alarm escalation can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-050 | T-163 | Remote alarm escalation | D | Alarms | Alarm delivery through Remote alarm escalation can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | HAZ-007, RC-021 |
| SEC-HAZ-051 | T-170 | Drug library update | T | Safety stop | Safety limits or interlock configuration at Drug library update can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-009 |
| SEC-HAZ-052 | T-171 | Drug library update | D | Safety stop | The safety stop in Drug library update may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-009 |
| SEC-HAZ-053 | T-176 | Drug library & firmware distribution | T | Safety stop | Safety limits or interlock configuration at Drug library & firmware distribution can be modified -> The last barrier before harm is removed: a dose or energy that the interlock existed to prevent is delivered, and nothing intervenes. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-054 | T-177 | Drug library & firmware distribution | D | Safety stop | The safety stop in Drug library & firmware distribution may not run when it is needed -> The device continues in an unsafe state because the mechanism that should have stopped it never ran. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-055 | T-178 | Drug library & firmware distribution | T | Device control | Therapy parameters handled by Drug library & firmware distribution can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-056 | T-179 | Drug library & firmware distribution | D | Device control | Loss of Drug library & firmware distribution removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Catastrophic — patient death | CRITICAL | HAZ-011 |
| SEC-HAZ-057 | T-184 | Device telemetry | T | Clinical data | Clinical data at Device telemetry can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-058 | T-185 | Device telemetry | D | Clinical data | Clinical data from Device telemetry may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | HAZ-013 |
| SEC-HAZ-059 | T-194 | Bedside annunciation | T | Alarms | Alarm conditions or thresholds at Bedside annunciation can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | RC-021 |
| SEC-HAZ-060 | T-195 | Bedside annunciation | D | Alarms | Alarm delivery through Bedside annunciation can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | RC-021 |

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
| Nurse call system | Process | Update mechanism, Keys and credentials held |
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

## 7. Security architecture views

The four views FDA asks for (section V.B.2). The diagram is the picture for all of them; these tables are the text.

### 7.1 Global system view

| Path | From -> to | Carries | Protocol | Interface | Authentication | Encryption | Integrity | Replay protection |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Programme infusion | Nurse (bedside) -> Pump controller | Commands | Other (Front-panel keypad and touchscreen) | In use for the intended use | Username + password | None (cleartext) | None | Not applicable — not a replayable channel |
| Auto-programming order | Hospital gateway -> Pump controller | Commands | HTTP (cleartext) (HTTP/1.1, tcp/8080, JSON order) | In use for the intended use | None / anonymous | None (cleartext) | None | None |
| Firmware and library push | Hospital gateway -> Pump controller | Code | HTTP (cleartext) (HTTP/1.1, tcp/8080, image pulled on notification) | In use for the intended use | Shared secret or API key | None (cleartext) | None | None |
| Requested rate check | Pump controller <-> Dose limit interlock | Data | Other (In-process call) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Dose limits | Drug library (on device) -> Dose limit interlock | Data | Other (File read at start-up and on change) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Alarm conditions | Pump controller -> Alarm manager | Data | Other (In-process message queue) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Remote alarm escalation | Alarm manager -> Nurse call system | Data | HTTP (cleartext) (HTTP/1.1, tcp/8081) | In use for the intended use | Shared secret or API key | None (cleartext) | None | None |
| Drug library update | Biomed / service tech -> Drug library (on device) | Code | SMB / NFS file share (SMB 2, tcp/445) | Service / maintenance only | Shared secret or API key | None (cleartext) | None | None |
| Drug library & firmware distribution | Vendor fleet service -> Hospital gateway | Code | HTTPS / TLS (TLS 1.2, tcp/443) | In use for the intended use | Shared secret or API key | TLS (server authenticated) | Transport (TLS) only | Timestamp or sequence number |
| Device telemetry | Hospital gateway -> Vendor fleet service | Data | HTTPS / TLS (TLS 1.2, tcp/443) | In use for the intended use | Shared secret or API key | TLS (server authenticated) | Transport (TLS) only | Timestamp or sequence number |
| Store events | Vendor fleet service -> Telemetry & event store | Data | HTTPS / TLS (TLS 1.2, tcp/443) | In use for the intended use | Session token / JWT | TLS (server authenticated) | Transport (TLS) only | Timestamp or sequence number |
| Bedside annunciation | Alarm manager -> Nurse (bedside) | Data | Physical / manual transfer (Audible and visual alarm at the pump) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |

### 7.2 Multi-patient harm view

| Element | Type | Safety impact | Severity of harm | Threats | Controls in place |
| --- | --- | --- | --- | --- | --- |
| Biomed / service tech | Entity | Safety stop | Catastrophic — patient death | 2 | none recorded |
| Hospital gateway | Process | Device control; Alarms; Care delivery | Critical — permanent impairment or life-threatening injury | 26 | none recorded |
| Nurse call system | Process | Alarms; Care delivery | Critical — permanent impairment or life-threatening injury | 11 | none recorded |
| Vendor fleet service | Process | Safety stop; Device control | Catastrophic — patient death | 12 | none recorded |
| Telemetry & event store | Data store | Clinical data | Minor — temporary injury, no professional intervention | 9 | none recorded |
| Auto-programming order | Data flow | Device control | Catastrophic — patient death | 9 | none recorded |
| Firmware and library push | Data flow | Device control; Safety stop | Catastrophic — patient death | 10 | none recorded |
| Drug library & firmware distribution | Data flow | Safety stop; Device control | Catastrophic — patient death | 8 | none recorded |
| Device telemetry | Data flow | Clinical data | Minor — temporary injury, no professional intervention | 6 | none recorded |
| Store events | Data flow | — | not set | 1 | none recorded |

### 7.3 Updatability and patchability view

| Code-carrying path | From -> to | Protocol | Authentication | Integrity of the code | Crosses |
| --- | --- | --- | --- | --- | --- |
| Firmware and library push | Hospital gateway -> Pump controller | HTTP (cleartext) | Shared secret or API key | None | Pump enclosure (device), Hospital network |
| Drug library update | Biomed / service tech -> Drug library (on device) | SMB / NFS file share | Shared secret or API key | None | Pump enclosure (device), Hospital network |
| Drug library & firmware distribution | Vendor fleet service -> Hospital gateway | HTTPS / TLS | Shared secret or API key | Transport (TLS) only | Hospital network, Vendor cloud |

| Software | Origin | Support status | Update mechanism | SBOM reference |
| --- | --- | --- | --- | --- |
| Pump controller | Mixed — includes third-party components | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | SBOM-IP-2200 §1 (pump firmware) |
| Dose limit interlock | Proprietary (manufacturer-developed) | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | SBOM-IP-2200 §1 (pump firmware) |
| Alarm manager | Proprietary (manufacturer-developed) | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | SBOM-IP-2200 §1 (pump firmware) |
| Hospital gateway | Mixed — includes third-party components | No longer maintained (end of support) | Signed updates, no rollback protection | **missing** |
| Nurse call system | Commercial off-the-shelf | Actively maintained | not set | Not part of the device (hospital system) |
| Vendor fleet service | Mixed — includes third-party components | Actively maintained | Signed updates with rollback protection | SBOM-FLEET-12 |

### 7.4 Security use case views

| Use case | Elements and paths involved | Safety impact | Threats | Open |
| --- | --- | --- | --- | --- |
| Programming | Pump controller, Nurse (bedside), Hospital gateway, Programme infusion, Auto-programming order | Device control; Care delivery; Alarms | 65 | 62 |
| Delivering therapy | Pump controller, Dose limit interlock, Drug library (on device), Patient, Requested rate check, Dose limits | Device control; Safety stop; Care delivery | 53 | 51 |
| Software update | Pump controller, Biomed / service tech, Hospital gateway, Vendor fleet service, Firmware and library push, Drug library & firmware distribution | Device control; Safety stop; Alarms; Care delivery | 78 | 76 |
| Drug library update | Dose limit interlock, Drug library (on device), Biomed / service tech, Vendor fleet service, Firmware and library push, Drug library update, Drug library & firmware distribution | Safety stop; Device control | 60 | 59 |
| Alarming | Alarm manager, Nurse (bedside), Hospital gateway, Nurse call system, Alarm conditions, Remote alarm escalation, Bedside annunciation | Alarms; Device control; Care delivery | 77 | 74 |
| Telemetry | Hospital gateway, Vendor fleet service, Telemetry & event store, Device telemetry, Store events | Device control; Alarms; Care delivery; Safety stop; Clinical data | 54 | 53 |

## 8. Cybersecurity risk assessment

Pre-mitigation risk is the severity the model computed (or the CVSS v4.0 band where one was entered). Security risk is rated on exploitability and impact, not on a probability of occurrence.

**Acceptance criteria:** residual risk up to Medium is acceptable. Scored before mitigation by the model, and after mitigation by the security and safety leads together. Residual Medium or below is acceptable. High needs sign-off against clinical benefit. Critical is not acceptable. Every threat with a path to patient harm is carried into RMF-IP-2200 by its SEC-HAZ reference.

| Decision | Threats |
| --- | --- |
| Open — no decision recorded | 198 |
| Mitigated by design | 2 |
| Mitigated by compensating control | 1 |
| Transferred to the user (disclosed in labeling) | 1 |
| Accepted | 1 |

**Residual risk above the acceptance threshold:** T-27, T-68.

**Mitigated, but no verification evidence referenced:** T-27.

| Threat | Element | Risk | Pre-mitigation | Decision | Control / rationale | Residual | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-14 | Pump controller | [T] Therapy parameters handled by Pump controller can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-98 | Vendor fleet service | [T] Safety limits or interlock configuration at Vendor fleet service can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-100 | Vendor fleet service | [T] Therapy parameters handled by Vendor fleet service can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-16 | Pump controller | [D] Loss of Pump controller removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-99 | Vendor fleet service | [D] The safety stop in Vendor fleet service may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-130 | Auto-programming order | [D] Loss of Auto-programming order removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-13 | Pump controller | [S] Therapy commands to Pump controller are not proven to come from a legitimate source | CRITICAL | Mitigated by design | SR-021 therapy commands signed by the gateway and verified at the pump; SR-022 confirmation at the pump for any rate increase — A spoofed command is rejected at the pump. What remains is a compromised gateway signing key. | MEDIUM | TC-SEC-041; PT-2026-02 §5.1 |
| T-129 | Auto-programming order | [T] Therapy parameters handled by Auto-programming order can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-176 | Drug library & firmware distribution | [T] Safety limits or interlock configuration at Drug library & firmware distribution can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-178 | Drug library & firmware distribution | [T] Therapy parameters handled by Drug library & firmware distribution can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-29 | Dose limit interlock | [D] The safety stop in Dose limit interlock may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-73 | Hospital gateway | [D] Loss of Hospital gateway removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-76 | Hospital gateway | [D] Alarm delivery through Hospital gateway can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-86 | Nurse call system | [D] Alarm delivery through Nurse call system can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-121 | Programme infusion | [D] Loss of Programme infusion removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-138 | Firmware and library push | [D] Loss of Firmware and library push removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-140 | Firmware and library push | [D] The safety stop in Firmware and library push may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-177 | Drug library & firmware distribution | [D] The safety stop in Drug library & firmware distribution may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-179 | Drug library & firmware distribution | [D] Loss of Drug library & firmware distribution removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-15 | Pump controller | [E] Therapy control functions in Pump controller are reachable without a clinical authorisation decision | CRITICAL | Open |  | as pre-mitigation |  |
| T-96 | Vendor fleet service | [E] Injection into a privileged process | CRITICAL | Open |  | as pre-mitigation |  |
| T-70 | Hospital gateway | [S] Therapy commands to Hospital gateway are not proven to come from a legitimate source | CRITICAL | Open |  | as pre-mitigation |  |
| T-77 | Hospital gateway | [S] Alarms carried by Hospital gateway cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-87 | Nurse call system | [S] Alarms carried by Nurse call system cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-11 | Pump controller | [T] Updates to Pump controller are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-27 | Dose limit interlock | [T] Safety limits or interlock configuration at Dose limit interlock can be modified | CRITICAL | Mitigated by design | SR-030 absolute hard limit in firmware that no drug library entry can widen — Library tampering is bounded by the firmware limit, but soft limits can still be widened until the signed drug library ships in release 2.1. | HIGH (above threshold) | **missing** |
| T-50 | Drug library (on device) | [T] Safety limits or interlock configuration at Drug library (on device) can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-71 | Hospital gateway | [T] Therapy parameters handled by Hospital gateway can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-75 | Hospital gateway | [T] Alarm conditions or thresholds at Hospital gateway can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-85 | Nurse call system | [T] Alarm conditions or thresholds at Nurse call system can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-120 | Programme infusion | [T] Therapy parameters handled by Programme infusion can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-137 | Firmware and library push | [T] Therapy parameters handled by Firmware and library push can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-139 | Firmware and library push | [T] Safety limits or interlock configuration at Firmware and library push can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-175 | Drug library & firmware distribution | [T] Code delivered over "Drug library & firmware distribution" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-101 | Vendor fleet service | [R] Therapy changes at Vendor fleet service cannot be reconstructed afterwards | CRITICAL | Open |  | as pre-mitigation |  |
| T-42 | Alarm manager | [D] Alarm delivery through Alarm manager can be blocked, delayed or flooded | CRITICAL | Mitigated by compensating control | Audible and visual annunciation at the pump does not depend on the network path — Remote escalation can still be blocked; the bedside alarm cannot. | MEDIUM | TC-ALM-112 |
| T-145 | Requested rate check | [D] The safety stop in Requested rate check may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-150 | Dose limits | [D] The safety stop in Dose limits may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-155 | Alarm conditions | [D] Alarm delivery through Alarm conditions can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-163 | Remote alarm escalation | [D] Alarm delivery through Remote alarm escalation can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-195 | Bedside annunciation | [D] Alarm delivery through Bedside annunciation can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-10 | Pump controller | [E] Injection into a privileged process | CRITICAL | Open |  | as pre-mitigation |  |
| T-28 | Dose limit interlock | [E] The safety stop in Dose limit interlock can be overridden without proper authority | CRITICAL | Open |  | as pre-mitigation |  |
| T-65 | Hospital gateway | [E] Injection into a privileged process | CRITICAL | Open |  | as pre-mitigation |  |
| T-72 | Hospital gateway | [E] Therapy control functions in Hospital gateway are reachable without a clinical authorisation decision | CRITICAL | Open |  | as pre-mitigation |  |
| T-43 | Alarm manager | [S] Alarms carried by Alarm manager cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-26 | Dose limit interlock | [T] Updates to Dose limit interlock are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-39 | Alarm manager | [T] Updates to Alarm manager are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-41 | Alarm manager | [T] Alarm conditions or thresholds at Alarm manager can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-136 | Firmware and library push | [T] Code delivered over "Firmware and library push" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-144 | Requested rate check | [T] Safety limits or interlock configuration at Requested rate check can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-149 | Dose limits | [T] Safety limits or interlock configuration at Dose limits can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-154 | Alarm conditions | [T] Alarm conditions or thresholds at Alarm conditions can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-162 | Remote alarm escalation | [T] Alarm conditions or thresholds at Remote alarm escalation can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-170 | Drug library update | [T] Safety limits or interlock configuration at Drug library update can be modified | CRITICAL | Open |  | as pre-mitigation |  |
| T-184 | Device telemetry | [T] Clinical data at Device telemetry can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-194 | Bedside annunciation | [T] Alarm conditions or thresholds at Bedside annunciation can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-17 | Pump controller | [R] Therapy changes at Pump controller cannot be reconstructed afterwards | CRITICAL | Open |  | as pre-mitigation |  |
| T-79 | Hospital gateway | [D] Loss of Hospital gateway delays or prevents care | CRITICAL | Open |  | as pre-mitigation |  |
| T-89 | Nurse call system | [D] Loss of Nurse call system delays or prevents care | CRITICAL | Open |  | as pre-mitigation |  |
| T-171 | Drug library update | [D] The safety stop in Drug library update may not run when it is needed | CRITICAL | Open |  | as pre-mitigation |  |
| T-185 | Device telemetry | [D] Clinical data from Device telemetry may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-109 | Telemetry & event store | [T] Clinical data at Telemetry & event store can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-169 | Drug library update | [T] Code delivered over "Drug library update" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-74 | Hospital gateway | [R] Therapy changes at Hospital gateway cannot be reconstructed afterwards | CRITICAL | Open |  | as pre-mitigation |  |
| T-78 | Hospital gateway | [R] Alarm history at Hospital gateway is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-88 | Nurse call system | [R] Alarm history at Nurse call system is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-110 | Telemetry & event store | [D] Clinical data from Telemetry & event store may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-91 | Vendor fleet service | [T] Untrusted input reaches Vendor fleet service without strict validation | CRITICAL | Open |  | as pre-mitigation |  |
| T-44 | Alarm manager | [R] Alarm history at Alarm manager is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-55 | Hospital gateway | [S] Hospital gateway accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-02 | Pump controller | [T] Untrusted input reaches Pump controller without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-57 | Hospital gateway | [T] Untrusted input reaches Hospital gateway without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-81 | Nurse call system | [T] Untrusted input reaches Nurse call system without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-122 | Auto-programming order | [T] Traffic on "Auto-programming order" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-128 | Auto-programming order | [T] Commands on "Auto-programming order" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-104 | Telemetry & event store | [R] Regulated records in Telemetry & event store without a full audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-05 | Pump controller | [I] Weak authorisation over sensitive data in Pump controller | HIGH | Open |  | as pre-mitigation |  |
| T-12 | Pump controller | [I] A secret held by Pump controller is the same on every device | HIGH | Open |  | as pre-mitigation |  |
| T-60 | Hospital gateway | [I] Weak authorisation over sensitive data in Hospital gateway | HIGH | Open |  | as pre-mitigation |  |
| T-124 | Auto-programming order | [I] Data on "Auto-programming order" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-106 | Telemetry & event store | [D] Loss of Telemetry & event store may be unrecoverable | HIGH | Open |  | as pre-mitigation |  |
| T-09 | Pump controller | [E] Coarse authorisation in Pump controller | HIGH | Open |  | as pre-mitigation |  |
| T-63 | Hospital gateway | [E] No effective authorisation model in Hospital gateway | HIGH | Open |  | as pre-mitigation |  |
| T-68 | Hospital gateway | [E] Hospital gateway runs software that no longer receives security fixes | HIGH | Transferred to the user (disclosed in labeling) | The gateway OS image is past end of support. Hospitals are told to isolate it on its own VLAN (IFU §9.3) until the 3.0 image ships. | HIGH (above threshold) |  |
| T-202 | Nurse call system | [E] Privilege crosses a trust boundary into Nurse call system | HIGH | Open |  | as pre-mitigation |  |
| T-203 | Hospital gateway | [E] Privilege crosses a trust boundary into Hospital gateway | HIGH | Open |  | as pre-mitigation |  |
| T-18 | Dose limit interlock | [S] Dose limit interlock accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-30 | Alarm manager | [S] Alarm manager accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-51 | Nurse (bedside) | [S] Single-factor credentials for a high-value identity | HIGH | Open |  | as pre-mitigation |  |
| T-90 | Vendor fleet service | [S] Clients cannot verify they are talking to the real Vendor fleet service | HIGH | Open |  | as pre-mitigation |  |
| T-196 | Pump controller | [S] Unauthenticated inbound flow "Auto-programming order" | HIGH | Open |  | as pre-mitigation |  |
| T-201 | Alarm manager | [S] Unauthenticated inbound flow "Alarm conditions" | HIGH | Open |  | as pre-mitigation |  |
| T-20 | Dose limit interlock | [T] Untrusted input reaches Dose limit interlock without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-32 | Alarm manager | [T] Untrusted input reaches Alarm manager without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-46 | Drug library (on device) | [T] Unrestricted write access to Drug library (on device) | HIGH | Open |  | as pre-mitigation |  |
| T-92 | Vendor fleet service | [T] Integrity of the code and configuration of Vendor fleet service | HIGH | Open |  | as pre-mitigation |  |
| T-114 | Programme infusion | [T] Traffic on "Programme infusion" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-131 | Firmware and library push | [T] Traffic on "Firmware and library push" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-151 | Alarm conditions | [T] Traffic on "Alarm conditions" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-156 | Remote alarm escalation | [T] Traffic on "Remote alarm escalation" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-180 | Device telemetry | [T] No end-to-end integrity on "Device telemetry" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-187 | Bedside annunciation | [T] Traffic on "Bedside annunciation" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-35 | Alarm manager | [I] Weak authorisation over sensitive data in Alarm manager | HIGH | Open |  | as pre-mitigation |  |
| T-40 | Alarm manager | [I] A secret held by Alarm manager is the same on every device | HIGH | Open |  | as pre-mitigation |  |
| T-48 | Drug library (on device) | [I] Weak access control on Drug library (on device) | HIGH | Open |  | as pre-mitigation |  |
| T-94 | Vendor fleet service | [I] Regulated data may be copied into logs by Vendor fleet service | HIGH | Open |  | as pre-mitigation |  |
| T-116 | Programme infusion | [I] Data on "Programme infusion" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-133 | Firmware and library push | [I] Data on "Firmware and library push" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-152 | Alarm conditions | [I] Data on "Alarm conditions" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-158 | Remote alarm escalation | [I] Data on "Remote alarm escalation" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-181 | Device telemetry | [I] Sensitive data leaves a trust boundary on "Device telemetry" | HIGH | Open |  | as pre-mitigation |  |
| T-189 | Bedside annunciation | [I] Data on "Bedside annunciation" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-07 | Pump controller | [D] Pump controller has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-62 | Hospital gateway | [D] Hospital gateway has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-84 | Nurse call system | [D] Nurse call system has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-112 | Patient | [D] Availability of the asset Patient | HIGH | Open |  | as pre-mitigation |  |
| T-126 | Auto-programming order | [D] "Auto-programming order" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-182 | Device telemetry | [D] "Device telemetry" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-25 | Dose limit interlock | [E] No effective authorisation model in Dose limit interlock | HIGH | Open |  | as pre-mitigation |  |
| T-38 | Alarm manager | [E] No effective authorisation model in Alarm manager | HIGH | Open |  | as pre-mitigation |  |
| T-95 | Vendor fleet service | [E] Vendor fleet service holds a broadly privileged service account | HIGH | Open |  | as pre-mitigation |  |
| T-197 | Pump controller | [E] Privilege crosses a trust boundary into Pump controller | HIGH | Open |  | as pre-mitigation |  |
| T-01 | Pump controller | [S] Clients cannot verify they are talking to the real Pump controller | HIGH | Open |  | as pre-mitigation |  |
| T-56 | Hospital gateway | [S] Clients cannot verify they are talking to the real Hospital gateway | HIGH | Open |  | as pre-mitigation |  |
| T-80 | Nurse call system | [S] Clients cannot verify they are talking to the real Nurse call system | HIGH | Open |  | as pre-mitigation |  |
| T-199 | Dose limit interlock | [S] Unauthenticated inbound flow "Requested rate check" | HIGH | Open |  | as pre-mitigation |  |
| T-200 | Dose limit interlock | [S] Unauthenticated inbound flow "Dose limits" | HIGH | Open |  | as pre-mitigation |  |
| T-03 | Pump controller | [T] Integrity of the code and configuration of Pump controller | HIGH | Open |  | as pre-mitigation |  |
| T-58 | Hospital gateway | [T] Integrity of the code and configuration of Hospital gateway | HIGH | Open |  | as pre-mitigation |  |
| T-66 | Hospital gateway | [T] Hospital gateway can be rolled back to a vulnerable release | HIGH | Open |  | as pre-mitigation |  |
| T-67 | Hospital gateway | [T] Third-party software in Hospital gateway is not traced to an SBOM | HIGH | Open |  | as pre-mitigation |  |
| T-82 | Nurse call system | [T] Integrity of the code and configuration of Nurse call system | HIGH | Open |  | as pre-mitigation |  |
| T-102 | Telemetry & event store | [T] Modification of Telemetry & event store would go unnoticed | HIGH | Open |  | as pre-mitigation |  |
| T-113 | Patient | [T] Integrity of the asset Patient | HIGH | Open |  | as pre-mitigation |  |
| T-123 | Auto-programming order | [T] No end-to-end integrity on "Auto-programming order" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-141 | Requested rate check | [T] Traffic on "Requested rate check" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-146 | Dose limits | [T] Traffic on "Dose limits" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-164 | Drug library update | [T] Traffic on "Drug library update" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-172 | Drug library & firmware distribution | [T] No end-to-end integrity on "Drug library & firmware distribution" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-04 | Pump controller | [R] Pump controller keeps no security audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-59 | Hospital gateway | [R] Hospital gateway keeps no security audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-103 | Telemetry & event store | [R] No access log for Telemetry & event store | HIGH | Open |  | as pre-mitigation |  |
| T-105 | Telemetry & event store | [I] Backups of Telemetry & event store are a second copy of the sensitive data | HIGH | Open |  | as pre-mitigation |  |
| T-111 | Patient | [I] Confidentiality of the asset Patient | HIGH | Open |  | as pre-mitigation |  |
| T-125 | Auto-programming order | [I] Sensitive data leaves a trust boundary on "Auto-programming order" | HIGH | Open |  | as pre-mitigation |  |
| T-142 | Requested rate check | [I] Data on "Requested rate check" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-147 | Dose limits | [I] Data on "Dose limits" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-166 | Drug library update | [I] Data on "Drug library update" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-24 | Dose limit interlock | [D] Dose limit interlock has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-37 | Alarm manager | [D] Alarm manager has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-118 | Programme infusion | [D] "Programme infusion" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-134 | Firmware and library push | [D] "Firmware and library push" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-160 | Remote alarm escalation | [D] "Remote alarm escalation" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-173 | Drug library & firmware distribution | [D] "Drug library & firmware distribution" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-192 | Bedside annunciation | [D] "Bedside annunciation" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-08 | Pump controller | [E] Pump controller holds a broadly privileged service account | HIGH | Open |  | as pre-mitigation |  |
| T-64 | Hospital gateway | [E] Hospital gateway holds a broadly privileged service account | HIGH | Open |  | as pre-mitigation |  |
| T-198 | Pump controller | [E] Privilege crosses a trust boundary into Pump controller | HIGH | Open |  | as pre-mitigation |  |
| T-19 | Dose limit interlock | [S] Clients cannot verify they are talking to the real Dose limit interlock | MEDIUM | Open |  | as pre-mitigation |  |
| T-31 | Alarm manager | [S] Clients cannot verify they are talking to the real Alarm manager | MEDIUM | Open |  | as pre-mitigation |  |
| T-53 | Biomed / service tech | [S] Shared secret identifies Biomed / service tech | MEDIUM | Open |  | as pre-mitigation |  |
| T-21 | Dose limit interlock | [T] Integrity of the code and configuration of Dose limit interlock | MEDIUM | Open |  | as pre-mitigation |  |
| T-33 | Alarm manager | [T] Integrity of the code and configuration of Alarm manager | MEDIUM | Open |  | as pre-mitigation |  |
| T-45 | Drug library (on device) | [T] Modification of Drug library (on device) would go unnoticed | MEDIUM | Open |  | as pre-mitigation |  |
| T-115 | Programme infusion | [T] No end-to-end integrity on "Programme infusion" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-132 | Firmware and library push | [T] No end-to-end integrity on "Firmware and library push" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-157 | Remote alarm escalation | [T] No end-to-end integrity on "Remote alarm escalation" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-188 | Bedside annunciation | [T] No end-to-end integrity on "Bedside annunciation" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-22 | Dose limit interlock | [R] Dose limit interlock keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-34 | Alarm manager | [R] Alarm manager keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-47 | Drug library (on device) | [R] No access log for Drug library (on device) | MEDIUM | Open |  | as pre-mitigation |  |
| T-52 | Nurse (bedside) | [R] Actions by Nurse (bedside) are not attributable | MEDIUM | Accepted | Programming at the bedside is attributed through the ward's medication administration record rather than by the pump. | LOW |  |
| T-54 | Biomed / service tech | [R] Actions by Biomed / service tech are not attributable | MEDIUM | Open |  | as pre-mitigation |  |
| T-93 | Vendor fleet service | [I] Leakage through errors, responses and telemetry from Vendor fleet service | MEDIUM | Open |  | as pre-mitigation |  |
| T-97 | Vendor fleet service | [I] Keys held by Vendor fleet service can be read out of storage | MEDIUM | Open |  | as pre-mitigation |  |
| T-117 | Programme infusion | [I] Sensitive data leaves a trust boundary on "Programme infusion" | MEDIUM | Open |  | as pre-mitigation |  |
| T-159 | Remote alarm escalation | [I] Sensitive data leaves a trust boundary on "Remote alarm escalation" | MEDIUM | Open |  | as pre-mitigation |  |
| T-190 | Bedside annunciation | [I] Sensitive data leaves a trust boundary on "Bedside annunciation" | MEDIUM | Open |  | as pre-mitigation |  |
| T-191 | Bedside annunciation | [I] Sensitive data moved by file share or physical transfer | MEDIUM | Open |  | as pre-mitigation |  |
| T-127 | Auto-programming order | [D] Availability of "Auto-programming order" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-183 | Device telemetry | [D] Availability of "Device telemetry" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-165 | Drug library update | [T] No end-to-end integrity on "Drug library update" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-06 | Pump controller | [I] Leakage through errors, responses and telemetry from Pump controller | MEDIUM | Open |  | as pre-mitigation |  |
| T-61 | Hospital gateway | [I] Leakage through errors, responses and telemetry from Hospital gateway | MEDIUM | Open |  | as pre-mitigation |  |
| T-69 | Hospital gateway | [I] Keys held by Hospital gateway can be read out of storage | MEDIUM | Open |  | as pre-mitigation |  |
| T-83 | Nurse call system | [I] Leakage through errors, responses and telemetry from Nurse call system | MEDIUM | Open |  | as pre-mitigation |  |
| T-108 | Telemetry & event store | [I] Sensitive data in Telemetry & event store outlives the device's time in service | MEDIUM | Open |  | as pre-mitigation |  |
| T-49 | Drug library (on device) | [D] Resource exhaustion against Drug library (on device) | MEDIUM | Open |  | as pre-mitigation |  |
| T-107 | Telemetry & event store | [D] Resource exhaustion against Telemetry & event store | MEDIUM | Open |  | as pre-mitigation |  |
| T-119 | Programme infusion | [D] Availability of "Programme infusion" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-135 | Firmware and library push | [D] Availability of "Firmware and library push" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-153 | Alarm conditions | [D] Availability of "Alarm conditions" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-161 | Remote alarm escalation | [D] Availability of "Remote alarm escalation" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-167 | Drug library update | [D] "Drug library update" can be flooded | MEDIUM | Open |  | as pre-mitigation |  |
| T-174 | Drug library & firmware distribution | [D] Availability of "Drug library & firmware distribution" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-186 | Store events | [D] Availability of "Store events" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-193 | Bedside annunciation | [D] Availability of "Bedside annunciation" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-23 | Dose limit interlock | [I] Leakage through errors, responses and telemetry from Dose limit interlock | LOW | Open |  | as pre-mitigation |  |
| T-36 | Alarm manager | [I] Leakage through errors, responses and telemetry from Alarm manager | LOW | Open |  | as pre-mitigation |  |
| T-143 | Requested rate check | [D] Availability of "Requested rate check" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-148 | Dose limits | [D] Availability of "Dose limits" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-168 | Drug library update | [D] Availability of "Drug library update" as a dependency | LOW | Open |  | as pre-mitigation |  |

## 9. FDA premarket alignment

How this threat model lines up with FDA's "Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions" (February 2026). A reading aid for assembling a submission, not a finding of compliance.

### 9.1 Security objectives (section IV.B)

| Objective | Threats | Open |
| --- | --- | --- |
| Authenticity, which includes integrity | 91 | 88 |
| Authorization | 21 | 21 |
| Availability | 52 | 51 |
| Confidentiality | 30 | 30 |
| Secure and timely updatability and patchability | 9 | 8 |

### 9.2 Security control categories (section V.B.1, Appendix 1)

| Control category | Guidance | Threats | Open |
| --- | --- | --- | --- |
| Authentication | Appendix 1.A | 30 | 29 |
| Authorization | Appendix 1.B | 18 | 18 |
| Cryptography | Appendix 1.C | 22 | 22 |
| Code, data and execution integrity | Appendix 1.D | 41 | 40 |
| Confidentiality | Appendix 1.E | 16 | 16 |
| Event detection and logging | Appendix 1.F | 15 | 14 |
| Resiliency and recovery | Appendix 1.G | 52 | 51 |
| Firmware and software updates | Appendix 1.H | 9 | 8 |

### 9.3 Lifecycle coverage (section V.A.1)

| Stage | Threats | Considerations recorded |
| --- | --- | --- |
| Supply chain | 8 | Pump firmware builds on a commercial RTOS and an open-source TLS library. The hospital gateway ships on a commercial OS image. One SBOM per release (SBOM-IP-2200). |
| Manufacturing | 4 | Every pump leaves the factory with the same service password and the same gateway key. |
| Deployment | 8 | Commissioned by hospital biomed onto the clinical Wi-Fi. Nothing forces the service password to change. |
| Interoperation | 21 | EHR auto-programming through the hospital gateway, and nurse call integration. Both are other manufacturers' systems. |
| Maintenance and update | 8 | Firmware and drug libraries come from the vendor fleet service through the hospital gateway, or are installed locally by a service technician from a file share. |
| Decommission | 1 | none recorded |

### 9.4 What this model states

| Expected of the threat model | Guidance | Status | Detail |
| --- | --- | --- | --- |
| Intended use | IV.B | Stated | Stated. |
| Environment of use | IV.B | Stated | Stated. |
| Assumptions about the system and its environment | V.A.1 | Stated | Stated. |
| Network assumed hostile | V.A.1 | Stated | Analysed on the assumption that an adversary can alter, drop and replay traffic. |
| Rationale for the threat modeling methodology | V.A.1 | Stated | Stated. |
| Trust boundaries and security context | V.B | Stated | 3 drawn. |
| Lifecycle risks beyond the design | V.A.1 | Stated | 6 of 6 lifecycle stages have a recorded consideration or a threat raised. |
| Risk acceptance criteria | V.A.2 | Stated | Residual risk up to "Medium" is acceptable. |
| Pre- and post-mitigation risk for every threat | V.A.2 | Partial | 5 of 203 threats have a recorded decision and residual risk; 198 are open. |
| Controls traced to test evidence | V.C | Partial | 1 mitigated threat has no verification evidence referenced. |
| Security risks traced into the safety risk assessment | V.A.2 | Missing | 1 break in the safety trace (section 5.2). |
| Multi-patient harm view | V.B.2(b) | Stated | 10 elements can affect multiple devices or patients at once. |
| Updatability and patchability view | V.B.2(c) | Stated | 3 code-carrying paths modelled. |
| Security use case views | V.B.2(d) | Stated | 6 use cases defined. |
| Software traced to the SBOM | V.A.4, Appendix 2 | Partial | 5 of 6 processes reference an SBOM entry. |

### 9.5 What sits outside the threat model

| Document | Guidance | What it holds |
| --- | --- | --- |
| Software bill of materials | V.A.4, VII.C.3 | A machine-readable SBOM with each component's level of support and end-of-support date. The SBOM references in section 7.3 point into it. |
| Vulnerability assessment | V.A.4 | Known vulnerabilities in the device and its components, including the CISA Known Exploited Vulnerabilities catalogue, each with a safety and security risk assessment. |
| Unresolved anomalies | V.A.5 | Software anomalies present at submission, assessed for whether a threat could trigger them deliberately. |
| Cybersecurity testing | V.C | Security requirement, threat mitigation, vulnerability and penetration test reports. The evidence references in section 8 point into them. |
| Measures and metrics | V.A.6 | Share of vulnerabilities patched, time from identification to patch, and time from patch to deployment in the field. |
| Labeling | VI.A | What users need to configure, operate, update and decommission the device securely, including any risk transferred to them. |
| Cybersecurity management plan | VI.B, VII.C.1 | How vulnerabilities will be monitored, disclosed and patched after release. |

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
| Aggravating: multiPatientHarm | +0.5 |
| Mitigating: publicData | -0.5 |
| Mitigating: lowAvailabilityNeed | -0.5 |

CVSS v4.0 assessments override the modelled rating where present. Vectors are validated against the CVSS v4.0 specification; scores are entered from the NVD calculator (https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator).
