# CGM lab — GlucoSense CGM-3000 (worked example)

STRIDE threat model report — generated 2026-08-29 22:40

- **System:** Continuous glucose monitoring appliance: a wearable BLE sensor, an MQTT telemetry backbone, an HL7 clinical interface, and a web + bedside-kiosk console, all on one Raspberry Pi with its USB ports, Bluetooth radio and touchscreen live at the bedside.
- **Author:** SecureMED teaching example (CGM-LAB-INT)
- **Date:** 2026-08-29
- **Scope / assumptions:** In scope: the appliance's web/kiosk console, HL7 listener, MQTT broker and telemetry, BLE advertiser, on-device config and user store, the host privilege model, and the Pi's physical interfaces — USB host ports, the on-board Bluetooth controller and the bedside touchscreen panel. Out of scope: the physical sensor hardware and adhesive, the upstream hospital EHR/LIS itself, the lab network fabric, and any real patient.
- **Intended use:** A continuous glucose monitor tracks a patient's interstitial glucose every few minutes and streams it to a display and to the clinical record. Patients and clinicians rely on it for two things: hypo/hyper ALARMS that warn of a dangerous low or high, and the glucose trend used to decide insulin dosing (including automated-delivery loops). A missed low-glucose alarm or a falsely reassuring reading can lead to severe, un-treated hypoglycaemia — seizure, coma or death. This lab is a deliberately vulnerable simulation (GlucoSense CGM-3000) that teaches students to find and fix the flaws that would let an attacker read, forge or suppress that safety-critical data.
- **Safety risk management file:** CGM-3000 Risk Management File (ISO 14971) (RMF-CGM-3000 rev A)
- **Methodology:** STRIDE per element
- **Severity scale:** Built-in qualitative scale (2 of 324 threats scored with CVSS v4.0)

## 1. Summary

| Metric | Value |
| --- | --- |
| Elements analysed | 45 |
| Data flows | 24 |
| Trust boundaries | 4 |
| Assets | 4 |
| Threats identified | 324 |
| Threats affecting patient safety | 80 |
| Safety-relevant elements | 22 |

| Safety impact | What a compromise does to the patient | Threats |
| --- | --- | --- |
| Device control — Controls or actuates therapy / diagnosis | Unintended, altered or withheld therapy delivered to the patient. | 6 |
| Alarms — Generates, carries or displays alarms | A real alarm is missed or suppressed, or false alarms drive alarm fatigue and unnecessary intervention. | 36 |
| Clinical data — Produces clinical data used for decisions | A clinical decision is made on wrong, stale or missing data. | 34 |
| Care delivery — Needed for timely care delivery | Care is delayed or cannot be delivered. | 4 |

| Severity | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- |
| Threats | 77 | 169 | 62 | 16 | 0 |

| STRIDE | Property | Threats |
| --- | --- | --- |
| S — Spoofing | Authentication | 26 |
| T — Tampering | Integrity | 90 |
| R — Repudiation | Non-repudiation | 30 |
| I — Information disclosure | Confidentiality | 63 |
| D — Denial of service | Availability | 93 |
| E — Elevation of privilege | Authorisation | 22 |

## 2. Diagram inventory

### 2.1 Trust boundaries

| Boundary | Kind | Description |
| --- | --- | --- |
| Untrusted lab network + BLE RF | Internet / DMZ perimeter | Any peer on the isolated lab LAN, and the radio space around the appliance. No control is applied here. |
| GlucoSense CGM-3000 appliance (Raspberry Pi 5) | Physical / facility | The device under test. All lab services bind 0.0.0.0 with no host firewall, and its physical interfaces — USB ports, Bluetooth radio and touch panel — are live at the bedside. |
| Host OS / root (SSH) | Privilege level | The Linux host the services run on. Root is the crown jewel (SEC-HAZ-009). |
| Unattended bedside (physical access) | Physical / facility | The patient bay itself. Anyone who can walk up to the appliance can touch its screen, plug into its ports and stand inside Bluetooth range, usually unobserved. |

### 2.2 Elements

| Element | Type | Description | Classification | Safety impact | Severity of harm | In boundary | Asset |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Unauthenticated network client | Entity | Any device on the lab LAN, and the student's Kali box. Anonymous until it defeats a control. | Restricted (PII / PHI / PCI) | — | not set | Untrusted lab network + BLE RF |  |
| Clinician / caregiver | Entity | Reads glucose and hypo/hyper alarms on the console and bedside kiosk, and acts on them. | Restricted (PII / PHI / PCI) | Clinical data; Alarms | Serious — injury needing professional intervention | Untrusted lab network + BLE RF |  |
| Hospital LIS / EHR interface | Entity | Upstream clinical system that queries the CGM over HL7 v2 (MLLP) for glucose results. | Restricted (PII / PHI / PCI) | — | not set | Untrusted lab network + BLE RF |  |
| Web admin console (Flask) | Process | Login, /admin maintenance token, /admin/export diagnostic download, and /kiosk/unlock. TCP 8080. Surfaces 1-4 and 8. | Restricted (PII / PHI / PCI) | Clinical data | Serious — injury needing professional intervention | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| HL7 MLLP listener | Process | Answers a well-formed QRY^Q01 for a known MRN with an ORU^R01 (PHI). Serial in MSH-3; flag in NTE. TCP 2575. Surface 5. | Restricted (PII / PHI / PCI) | Clinical data | Minor — temporary injury, no professional intervention | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| MQTT broker (mosquitto) | Process | Telemetry backbone. glucose/# carries readings + alarm state; cgm/service/# holds a retained capture flag. TCP 1883. Surface 6. | Restricted (PII / PHI / PCI) | Device control; Alarms; Clinical data | Critical — permanent impairment or life-threatening injury | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| BLE advertiser (runs as root) | Process | Non-connectable LE broadcast, company id 0xFFFF, carrying XOR-obfuscated manufacturer data. Surface 7. | Restricted (PII / PHI / PCI) | Clinical data | Minor — temporary injury, no professional intervention | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Bedside kiosk (Chromium / matchbox on DSI panel) | Process | Full-screen bedside display of glucose + alarms; unlock via POST /kiosk/unlock. Owns tty1. Surface 8. | Restricted (PII / PHI / PCI) | Alarms; Clinical data; Care delivery | Serious — injury needing professional intervention | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Host shell (biomed via SSH) | Process | SSH foothold + local privilege escalation to root. Surface 9. | Restricted (PII / PHI / PCI) | — | not set | Host OS / root (SSH) |  |
| User store (cgm.db, SQLite) | Data store | Seeded username/role/password rows queried by the login. Surface 1. | Restricted (PII / PHI / PCI) | — | not set | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Device config (cgm.conf) | Data store | Holds the MQTT credentials, the device serial (BLE key) and a maintenance token. World-readable, one dir above the report root. Surface 3. | Restricted (PII / PHI / PCI) | — | not set | GlucoSense CGM-3000 appliance (Raspberry Pi 5) | yes |
| Glucose telemetry (MQTT glucose/#, retained) | Data store | Per-patient readings and alarm state. A forged retained message persists to later subscribers. | Restricted (PII / PHI / PCI) | Clinical data; Alarms | Critical — permanent impairment or life-threatening injury | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Root filesystem / sudoers (/etc/sudoers.d, /root) | Data store | The NOPASSWD sudoers drop-in and /root/flag.txt (mode 600). Surface 9. | Confidential | — | not set | Host OS / root (SSH) |  |
| CGM sensor + BLE gateway | Entity | The wearable sensor front end that publishes legitimate glucose readings and alarm state onto glucose/#. | Restricted (PII / PHI / PCI) | Clinical data; Alarms | Critical — permanent impairment or life-threatening injury | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Patient glucose data / PHI | Asset | Per-patient readings, MRNs and demographics across HL7, MQTT and BLE. | Restricted (PII / PHI / PCI) | — | not set | GlucoSense CGM-3000 appliance (Raspberry Pi 5) | yes |
| Hypo / hyper alarm path | Asset | The end-to-end path that turns a real low or high into an alarm the clinician sees and acts on. | Restricted (PII / PHI / PCI) | Alarms; Device control | Critical — permanent impairment or life-threatening injury | GlucoSense CGM-3000 appliance (Raspberry Pi 5) | yes |
| Device & broker credentials | Asset | MQTT creds, Flask session secret, device serial, biomed SSH password. | Restricted (PII / PHI / PCI) | — | not set | GlucoSense CGM-3000 appliance (Raspberry Pi 5) | yes |
| Visitor at the bedside | Entity | A visitor, a patient, a cleaner or a contractor: unauthenticated, unsupervised, and alone with the device for minutes at a time. | Restricted (PII / PHI / PCI) | — | not set | Unattended bedside (physical access) |  |
| USB host ports (udev auto-mount) | Process | The Pi's four USB-A ports, live and unblanked at the bedside. udev auto-mounts any removable volume and the kernel binds any device that enumerates as a keyboard. Physical surface — not one of the numbered lab surfaces. | Restricted (PII / PHI / PCI) | Alarms; Care delivery | Critical — permanent impairment or life-threatening injury | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Bluetooth stack (BlueZ / bluetoothd, root) | Process | The Pi's on-board controller and the BlueZ daemon: discoverable and pairable in the lab image, and the same radio the BLE advertiser broadcasts on. Physical / RF surface — not one of the numbered lab surfaces. | Restricted (PII / PHI / PCI) | Clinical data; Alarms | Critical — permanent impairment or life-threatening injury | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |
| Touchscreen HMI (DSI panel + libinput) | Process | The 7-inch bedside touch panel: the only thing the clinician actually looks at, and the input device for the kiosk session on tty1. Physical surface — not one of the numbered lab surfaces. | Restricted (PII / PHI / PCI) | Alarms; Clinical data; Care delivery | Serious — injury needing professional intervention | GlucoSense CGM-3000 appliance (Raspberry Pi 5) |  |

### 2.3 Data flows

| Flow | Source | Destination | Protocol | Encryption | Crosses boundary |
| --- | --- | --- | --- | --- | --- |
| HTTP attack surface | Unauthenticated network client | Web admin console (Flask) (bi) | HTTP (cleartext) | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Console session | Clinician / caregiver | Web admin console (Flask) (bi) | HTTP (cleartext) | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Bedside interaction | Clinician / caregiver | Bedside kiosk (Chromium / matchbox on DSI panel) (bi) | HTTP (cleartext) | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| HL7 v2 query / result (MLLP) | Hospital LIS / EHR interface | HL7 MLLP listener (bi) | Other | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Login query | Web admin console (Flask) | User store (cgm.db, SQLite) (bi) | SQL / database protocol | None (cleartext) | no |
| Diagnostic export / config read | Web admin console (Flask) | Device config (cgm.conf) (bi) | Other | None (cleartext) | no |
| Console telemetry | Web admin console (Flask) | MQTT broker (mosquitto) (bi) | AMQP / Kafka / queue | None (cleartext) | no |
| Legitimate glucose publish | CGM sensor + BLE gateway | MQTT broker (mosquitto) | AMQP / Kafka / queue | None (cleartext) | no |
| Retained telemetry | MQTT broker (mosquitto) | Glucose telemetry (MQTT glucose/#, retained) (bi) | AMQP / Kafka / queue | None (cleartext) | no |
| Forged-reading injection | Unauthenticated network client | MQTT broker (mosquitto) (bi) | AMQP / Kafka / queue | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Bedside display feed | MQTT broker (mosquitto) | Bedside kiosk (Chromium / matchbox on DSI panel) | AMQP / Kafka / queue | None (cleartext) | no |
| BLE advertisement (RF) | BLE advertiser (runs as root) | Unauthenticated network client | Other | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Rogue HL7 query | Unauthenticated network client | HL7 MLLP listener (bi) | Other | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| SSH foothold | Unauthenticated network client | Host shell (biomed via SSH) (bi) | SFTP / SSH | TLS (server authenticated) | Untrusted lab network + BLE RF, Host OS / root (SSH) |
| Privilege escalation | Host shell (biomed via SSH) | Root filesystem / sudoers (/etc/sudoers.d, /root) (bi) | Other | None (cleartext) | no |
| USB port access | Visitor at the bedside | USB host ports (udev auto-mount) (bi) | Physical / manual transfer | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Bluetooth pairing / GATT access | Visitor at the bedside | Bluetooth stack (BlueZ / bluetoothd, root) (bi) | Other | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Unattended panel use | Visitor at the bedside | Touchscreen HMI (DSI panel + libinput) (bi) | Physical / manual transfer | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Touch input / rendered display | Touchscreen HMI (DSI panel + libinput) | Bedside kiosk (Chromium / matchbox on DSI panel) (bi) | Other | None (cleartext) | no |
| Bedside annunciation | Touchscreen HMI (DSI panel + libinput) | Clinician / caregiver | Physical / manual transfer | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Paired HID input | Bluetooth stack (BlueZ / bluetoothd, root) | Bedside kiosk (Chromium / matchbox on DSI panel) | Other | None (cleartext) | no |
| Removable-media config copy | USB host ports (udev auto-mount) | Device config (cgm.conf) (bi) | Physical / manual transfer | None (cleartext) | no |
| Auto-mount + udev rule execution | USB host ports (udev auto-mount) | Root filesystem / sudoers (/etc/sudoers.d, /root) | Physical / manual transfer | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH) |
| HCI advertising control | BLE advertiser (runs as root) | Bluetooth stack (BlueZ / bluetoothd, root) | Other | None (cleartext) | no |

## 3. STRIDE coverage matrix

| Element | Type | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Unauthenticated network client | Entity | 1 | · | 2 | · | · | · |
| Clinician / caregiver | Entity | 1 | · | 1 | · | · | · |
| Hospital LIS / EHR interface | Entity | 1 | · | 1 | · | · | · |
| Web admin console (Flask) | Process | 1 | 3 | 1 | 2 | 2 | 1 |
| HL7 MLLP listener | Process | 3 | 2 | 1 | 1 | 2 | 3 |
| MQTT broker (mosquitto) | Process | o | 4 | 3 | 1 | 4 | 2 |
| BLE advertiser (runs as root) | Process | 1 | 3 | 1 | 1 | 2 | 3 |
| Bedside kiosk (Chromium / matchbox on DSI panel) | Process | 5 | 3 | 2 | 1 | 4 | 2 |
| Host shell (biomed via SSH) | Process | 1 | 2 | 1 | 2 | 1 | 1 |
| User store (cgm.db, SQLite) | Data store | · | 2 | 2 | 2 | 2 | · |
| Device config (cgm.conf) | Data store | · | 2 | 2 | 2 | 2 | · |
| Glucose telemetry (MQTT glucose/#, retained) | Data store | · | 3 | 3 | 1 | 4 | · |
| Root filesystem / sudoers (/etc/sudoers.d, /root) | Data store | · | 2 | 1 | 2 | 2 | · |
| CGM sensor + BLE gateway | Entity | 1 | · | 1 | · | · | · |
| Patient glucose data / PHI | Asset | · | 1 | · | 1 | 1 | · |
| Hypo / hyper alarm path | Asset | · | o | · | 1 | 1 | · |
| Device & broker credentials | Asset | · | o | · | 2 | 1 | · |
| Visitor at the bedside | Entity | 1 | · | 2 | · | · | · |
| USB host ports (udev auto-mount) | Process | 3 | 3 | 2 | 1 | 3 | 4 |
| Bluetooth stack (BlueZ / bluetoothd, root) | Process | 4 | 4 | 2 | 1 | 3 | 4 |
| Touchscreen HMI (DSI panel + libinput) | Process | 3 | 3 | 2 | 1 | 4 | 2 |
| HTTP attack surface | Data flow | · | 2 | · | 2 | 2 | · |
| Console session | Data flow | · | 3 | · | 2 | 3 | · |
| Bedside interaction | Data flow | · | 4 | · | 2 | 4 | · |
| HL7 v2 query / result (MLLP) | Data flow | · | 3 | · | 2 | 3 | · |
| Login query | Data flow | · | 1 | · | 1 | 1 | · |
| Diagnostic export / config read | Data flow | · | 1 | · | 1 | 1 | · |
| Console telemetry | Data flow | · | 1 | · | 1 | 1 | · |
| Legitimate glucose publish | Data flow | · | 3 | · | 1 | 3 | · |
| Retained telemetry | Data flow | · | 1 | · | 1 | 1 | · |
| Forged-reading injection | Data flow | · | 5 | · | 2 | 5 | · |
| Bedside display feed | Data flow | · | 3 | · | 1 | 3 | · |
| BLE advertisement (RF) | Data flow | · | 3 | · | 2 | 3 | · |
| Rogue HL7 query | Data flow | · | 2 | · | 2 | 2 | · |
| SSH foothold | Data flow | · | 1 | · | 1 | 2 | · |
| Privilege escalation | Data flow | · | 1 | · | 1 | 1 | · |
| USB port access | Data flow | · | 2 | · | 3 | 2 | · |
| Bluetooth pairing / GATT access | Data flow | · | 2 | · | 2 | 2 | · |
| Unattended panel use | Data flow | · | 2 | · | 3 | 2 | · |
| Touch input / rendered display | Data flow | · | 3 | · | 1 | 3 | · |
| Bedside annunciation | Data flow | · | 4 | · | 3 | 4 | · |
| Paired HID input | Data flow | · | 2 | · | 1 | 3 | · |
| Removable-media config copy | Data flow | · | 1 | · | 2 | 1 | · |
| Auto-mount + udev rule execution | Data flow | · | 2 | · | 3 | 2 | · |
| HCI advertising control | Data flow | · | 1 | · | 1 | 1 | · |

## 4. Threats and recommended mitigations

### Web admin console (Flask) (Process)

_Login, /admin maintenance token, /admin/export diagnostic download, and /kiosk/unlock. TCP 8080. Surfaces 1-4 and 8._

#### T-09 · [T] Untrusted input reaches Web admin console (Flask) without strict validation — **CRITICAL**

_Tampering — violates Integrity_

**CVSS v4.0:** 9.2 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` — SQL injection in the login gives an unauthenticated admin session and, via the export traversal, read of on-device secrets. Network, no auth, no interaction. Scored in the CVSS v4.0 calculator as a teaching illustration.

Input crossing into Web admin console (Flask) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-16 · [T] Clinical data at Web admin console (Flask) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Web admin console (Flask), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-001 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** The console is where a clinician reads glucose trends and acknowledges alarms; a compromise that alters what it shows biases a dosing decision.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-002, RC-021

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-17 · [D] Clinical data from Web admin console (Flask) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Web admin console (Flask) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-002 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** The console is where a clinician reads glucose trends and acknowledges alarms; a compromise that alters what it shows biases a dosing decision.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-002, RC-021

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-12 · [I] Weak authorisation over sensitive data in Web admin console (Flask) — **HIGH**

_Information disclosure — violates Confidentiality_

Web admin console (Flask) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-15 · [E] Coarse authorisation in Web admin console (Flask) — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-08 · [S] Clients cannot verify they are talking to the real Web admin console (Flask) — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Web admin console (Flask). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-10 · [T] Integrity of the code and configuration of Web admin console (Flask) — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Web admin console (Flask) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-11 · [R] Web admin console (Flask) keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Web admin console (Flask) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-14 · [D] Web admin console (Flask) has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Web admin console (Flask) has, taking it down for everyone.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-13 · [I] Leakage through errors, responses and telemetry from Web admin console (Flask) — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Web admin console (Flask) - versions, paths, schema, and whether a given account exists.

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### MQTT broker (mosquitto) (Process)

_Telemetry backbone. glucose/# carries readings + alarm state; cgm/service/# holds a retained capture flag. TCP 1883. Surface 6._

#### T-35 · [T] Alarm conditions or thresholds at MQTT broker (mosquitto) can be tampered with — **HIGH**

_Tampering — violates Integrity_

**CVSS v4.0:** 8.7 (High) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:H` — With a leaked broker credential, forging a retained 'in range' reading on glucose/# suppresses a genuine hypoglycaemia alarm (integrity + safety impact). Adjacent network, low privilege. Illustrative CVSS v4.0 score.

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through MQTT broker (mosquitto). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-009 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-33 · [D] Loss of MQTT broker (mosquitto) removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops MQTT broker (mosquitto) responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-007 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-36 · [D] Alarm delivery through MQTT broker (mosquitto) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts MQTT broker (mosquitto), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-010 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-39 · [D] Clinical data from MQTT broker (mosquitto) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes MQTT broker (mosquitto) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-013 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-31 · [T] Therapy parameters handled by MQTT broker (mosquitto) can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through MQTT broker (mosquitto) can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-005 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-38 · [T] Clinical data at MQTT broker (mosquitto) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through MQTT broker (mosquitto), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-012 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-32 · [E] Therapy control functions in MQTT broker (mosquitto) are reachable without a clinical authorisation decision — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A caller who is authenticated for some other purpose — a service account, a read-only integration, a patient-facing feature — can invoke the functions that change therapy, because authorisation does not separate clinical control from everything else.

> **Patient safety — SEC-HAZ-006 · Controls or actuates therapy / diagnosis**  
> **Harm:** Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Separate therapy-control operations behind their own authorisation, deny by default, and require a clinical role.
- Require step-up authentication or a second person for high-consequence changes.
- Log every therapy-control call with the authenticated identity and the resulting parameter change.

#### T-34 · [R] Therapy changes at MQTT broker (mosquitto) cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

> **Patient safety — SEC-HAZ-008 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-37 · [R] Alarm history at MQTT broker (mosquitto) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at MQTT broker (mosquitto).

> **Patient safety — SEC-HAZ-011 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-26 · [T] Untrusted input reaches MQTT broker (mosquitto) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into MQTT broker (mosquitto) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-28 · [I] Weak authorisation over sensitive data in MQTT broker (mosquitto) — **HIGH**

_Information disclosure — violates Confidentiality_

MQTT broker (mosquitto) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-30 · [E] Coarse authorisation in MQTT broker (mosquitto) — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-29 · [D] MQTT broker (mosquitto) has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads MQTT broker (mosquitto) has, taking it down for everyone.

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-27 · [R] MQTT broker (mosquitto) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through MQTT broker (mosquitto) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

### Forged-reading injection (Data flow)

_With the leaked cred: WRITE glucose/# (forge 'IN_RANGE') and READ cgm/service/# (flag). READ glucose/# denied._

#### T-219 · [D] Loss of Forged-reading injection removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Forged-reading injection responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

> **Patient safety — SEC-HAZ-059 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-221 · [D] Alarm delivery through Forged-reading injection can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Forged-reading injection, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-061 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-223 · [D] Clinical data from Forged-reading injection may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Forged-reading injection unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-063 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-218 · [T] Therapy parameters handled by Forged-reading injection can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Forged-reading injection can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

> **Patient safety — SEC-HAZ-058 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-220 · [T] Alarm conditions or thresholds at Forged-reading injection can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Forged-reading injection. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-060 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-222 · [T] Clinical data at Forged-reading injection can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Forged-reading injection, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-062 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-212 · [T] Traffic on "Forged-reading injection" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-214 · [I] Data on "Forged-reading injection" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-216 · [D] "Forged-reading injection" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-213 · [T] No end-to-end integrity on "Forged-reading injection" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-215 · [I] Sensitive data leaves a trust boundary on "Forged-reading injection" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-217 · [D] Availability of "Forged-reading injection" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside annunciation (Data flow)

_What the clinician actually sees and hears at the bedside: current glucose, trend, and the hypo / hyper alarm._

#### T-287 · [D] Alarm delivery through Bedside annunciation can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside annunciation, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-075 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-289 · [D] Clinical data from Bedside annunciation may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside annunciation unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-077 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-286 · [T] Alarm conditions or thresholds at Bedside annunciation can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside annunciation. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-074 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-288 · [T] Clinical data at Bedside annunciation can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside annunciation, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-076 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-279 · [T] Traffic on "Bedside annunciation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-281 · [I] Data on "Bedside annunciation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-284 · [D] "Bedside annunciation" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-280 · [T] No end-to-end integrity on "Bedside annunciation" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-282 · [I] Sensitive data leaves a trust boundary on "Bedside annunciation" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-283 · [I] Sensitive data moved by file share or physical transfer — **HIGH**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-285 · [D] Availability of "Bedside annunciation" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Glucose telemetry (MQTT glucose/#, retained) (Data store)

_Per-patient readings and alarm state. A forged retained message persists to later subscribers._

#### T-95 · [D] Clinical data from Glucose telemetry (MQTT glucose/#, retained) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Glucose telemetry (MQTT glucose/#, retained) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-024 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-97 · [D] Alarm delivery through Glucose telemetry (MQTT glucose/#, retained) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Glucose telemetry (MQTT glucose/#, retained), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-026 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-94 · [T] Clinical data at Glucose telemetry (MQTT glucose/#, retained) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Glucose telemetry (MQTT glucose/#, retained), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-023 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-96 · [T] Alarm conditions or thresholds at Glucose telemetry (MQTT glucose/#, retained) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Glucose telemetry (MQTT glucose/#, retained). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-025 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-98 · [R] Alarm history at Glucose telemetry (MQTT glucose/#, retained) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Glucose telemetry (MQTT glucose/#, retained).

> **Patient safety — SEC-HAZ-027 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-92 · [D] Loss of Glucose telemetry (MQTT glucose/#, retained) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Glucose telemetry (MQTT glucose/#, retained) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-90 · [R] Regulated records in Glucose telemetry (MQTT glucose/#, retained) without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Glucose telemetry (MQTT glucose/#, retained) holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-91 · [I] Sensitive data stored unencrypted in Glucose telemetry (MQTT glucose/#, retained) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Glucose telemetry (MQTT glucose/#, retained) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-88 · [T] Modification of Glucose telemetry (MQTT glucose/#, retained) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Glucose telemetry (MQTT glucose/#, retained) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-89 · [R] No access log for Glucose telemetry (MQTT glucose/#, retained) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Glucose telemetry (MQTT glucose/#, retained) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-93 · [D] Resource exhaustion against Glucose telemetry (MQTT glucose/#, retained) — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Glucose telemetry (MQTT glucose/#, retained) unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Legitimate glucose publish (Data flow)

_Real readings + alarm state onto glucose/<patient>._

#### T-206 · [D] Clinical data from Legitimate glucose publish may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Legitimate glucose publish unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-055 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-208 · [D] Alarm delivery through Legitimate glucose publish can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Legitimate glucose publish, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-057 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-205 · [T] Clinical data at Legitimate glucose publish can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Legitimate glucose publish, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-054 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-207 · [T] Alarm conditions or thresholds at Legitimate glucose publish can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Legitimate glucose publish. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-056 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-202 · [T] Traffic on "Legitimate glucose publish" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-203 · [I] Data on "Legitimate glucose publish" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-204 · [D] Availability of "Legitimate glucose publish" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### USB host ports (udev auto-mount) (Process)

_The Pi's four USB-A ports, live and unblanked at the bedside. udev auto-mounts any removable volume and the kernel binds any device that enumerates as a keyboard. Physical surface — not one of the numbered lab surfaces._

#### T-130 · [S] Alarms carried by USB host ports (udev auto-mount) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach USB host ports (udev auto-mount) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-030 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-128 · [T] Alarm conditions or thresholds at USB host ports (udev auto-mount) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through USB host ports (udev auto-mount). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-028 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-129 · [D] Alarm delivery through USB host ports (udev auto-mount) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts USB host ports (udev auto-mount), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-029 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-127 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, USB host ports (udev auto-mount) executes it, and it executes as a privileged account.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-131 · [R] Alarm history at USB host ports (udev auto-mount) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at USB host ports (udev auto-mount).

> **Patient safety — SEC-HAZ-031 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-132 · [D] Loss of USB host ports (udev auto-mount) delays or prevents care — **CRITICAL**

_Denial of service — violates Availability_

USB host ports (udev auto-mount) is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

> **Patient safety — SEC-HAZ-032 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-119 · [S] USB host ports (udev auto-mount) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach USB host ports (udev auto-mount) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-316 · [S] Unauthenticated inbound flow "USB port access" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "USB port access" from Visitor at the bedside carry no proof of who sent them. USB host ports (udev auto-mount) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: USB port access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-120 · [T] Untrusted input reaches USB host ports (udev auto-mount) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into USB host ports (udev auto-mount) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-123 · [I] Weak authorisation over sensitive data in USB host ports (udev auto-mount) — **HIGH**

_Information disclosure — violates Confidentiality_

USB host ports (udev auto-mount) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-125 · [E] USB host ports (udev auto-mount) runs with administrative privilege — **HIGH**

_Elevation of privilege — violates Authorisation_

Any code-execution or file-write bug in USB host ports (udev auto-mount) immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Run as a dedicated unprivileged account with only the permissions the workload needs.
- Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.
- Separate administrative functions into their own component with its own identity.

#### T-126 · [E] No effective authorisation model in USB host ports (udev auto-mount) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-317 · [E] Privilege crosses a trust boundary into USB host ports (udev auto-mount) — **HIGH**

_Elevation of privilege — violates Authorisation_

"USB port access" enters USB host ports (udev auto-mount) across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)" without an authorisation decision of its own. Whatever the caller can request, USB host ports (udev auto-mount) will perform - so the trust of the far side becomes the trust of this side.

Via data flow: USB port access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-121 · [T] Integrity of the code and configuration of USB host ports (udev auto-mount) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that USB host ports (udev auto-mount) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-122 · [R] USB host ports (udev auto-mount) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through USB host ports (udev auto-mount) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-124 · [D] USB host ports (udev auto-mount) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads USB host ports (udev auto-mount) has, taking it down for everyone.

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### Bluetooth stack (BlueZ / bluetoothd, root) (Process)

_The Pi's on-board controller and the BlueZ daemon: discoverable and pairable in the lab image, and the same radio the BLE advertiser broadcasts on. Physical / RF surface — not one of the numbered lab surfaces._

#### T-146 · [S] Alarms carried by Bluetooth stack (BlueZ / bluetoothd, root) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Bluetooth stack (BlueZ / bluetoothd, root) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-037 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-142 · [T] Clinical data at Bluetooth stack (BlueZ / bluetoothd, root) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bluetooth stack (BlueZ / bluetoothd, root), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-033 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-144 · [T] Alarm conditions or thresholds at Bluetooth stack (BlueZ / bluetoothd, root) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bluetooth stack (BlueZ / bluetoothd, root). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-035 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-143 · [D] Clinical data from Bluetooth stack (BlueZ / bluetoothd, root) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bluetooth stack (BlueZ / bluetoothd, root) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-034 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-145 · [D] Alarm delivery through Bluetooth stack (BlueZ / bluetoothd, root) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bluetooth stack (BlueZ / bluetoothd, root), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-036 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-141 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Bluetooth stack (BlueZ / bluetoothd, root) executes it, and it executes as a privileged account.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-147 · [R] Alarm history at Bluetooth stack (BlueZ / bluetoothd, root) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Bluetooth stack (BlueZ / bluetoothd, root).

> **Patient safety — SEC-HAZ-038 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-133 · [S] Bluetooth stack (BlueZ / bluetoothd, root) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Bluetooth stack (BlueZ / bluetoothd, root) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-318 · [S] Unauthenticated inbound flow "Bluetooth pairing / GATT access" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Bluetooth pairing / GATT access" from Visitor at the bedside carry no proof of who sent them. Bluetooth stack (BlueZ / bluetoothd, root) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Bluetooth pairing / GATT access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-324 · [S] Unauthenticated inbound flow "HCI advertising control" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "HCI advertising control" from BLE advertiser (runs as root) carry no proof of who sent them. Bluetooth stack (BlueZ / bluetoothd, root) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: HCI advertising control

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-134 · [T] Untrusted input reaches Bluetooth stack (BlueZ / bluetoothd, root) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Bluetooth stack (BlueZ / bluetoothd, root) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-137 · [I] Weak authorisation over sensitive data in Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Information disclosure — violates Confidentiality_

Bluetooth stack (BlueZ / bluetoothd, root) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-139 · [E] Bluetooth stack (BlueZ / bluetoothd, root) runs with administrative privilege — **HIGH**

_Elevation of privilege — violates Authorisation_

Any code-execution or file-write bug in Bluetooth stack (BlueZ / bluetoothd, root) immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Run as a dedicated unprivileged account with only the permissions the workload needs.
- Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.
- Separate administrative functions into their own component with its own identity.

#### T-140 · [E] No effective authorisation model in Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-319 · [E] Privilege crosses a trust boundary into Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Bluetooth pairing / GATT access" enters Bluetooth stack (BlueZ / bluetoothd, root) across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)" without an authorisation decision of its own. Whatever the caller can request, Bluetooth stack (BlueZ / bluetoothd, root) will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Bluetooth pairing / GATT access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-135 · [T] Integrity of the code and configuration of Bluetooth stack (BlueZ / bluetoothd, root) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Bluetooth stack (BlueZ / bluetoothd, root) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-136 · [R] Bluetooth stack (BlueZ / bluetoothd, root) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Bluetooth stack (BlueZ / bluetoothd, root) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-138 · [D] Bluetooth stack (BlueZ / bluetoothd, root) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Bluetooth stack (BlueZ / bluetoothd, root) has, taking it down for everyone.

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### Console session (Data flow)

_Clinician reviews glucose/alarms and administers the device._

#### T-173 · [T] Clinical data at Console session can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Console session, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-046 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-002

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-174 · [D] Clinical data from Console session may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Console session unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-047 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-002

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-167 · [T] Traffic on "Console session" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-169 · [I] Data on "Console session" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-168 · [T] No end-to-end integrity on "Console session" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-170 · [I] Sensitive data leaves a trust boundary on "Console session" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-171 · [D] "Console session" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-172 · [D] Availability of "Console session" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside interaction (Data flow)

_Clinician glances at the kiosk and unlocks it at the bedside._

#### T-181 · [T] Alarm conditions or thresholds at Bedside interaction can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside interaction. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-048 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-183 · [T] Clinical data at Bedside interaction can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside interaction, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-050 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-182 · [D] Alarm delivery through Bedside interaction can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside interaction, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-049 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-184 · [D] Clinical data from Bedside interaction may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside interaction unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-051 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-175 · [T] Traffic on "Bedside interaction" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-177 · [I] Data on "Bedside interaction" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-176 · [T] No end-to-end integrity on "Bedside interaction" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-178 · [I] Sensitive data leaves a trust boundary on "Bedside interaction" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-179 · [D] "Bedside interaction" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-180 · [D] Availability of "Bedside interaction" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### BLE advertiser (runs as root) (Process)

_Non-connectable LE broadcast, company id 0xFFFF, carrying XOR-obfuscated manufacturer data. Surface 7._

#### T-48 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, BLE advertiser (runs as root) executes it, and it executes as a privileged account.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-49 · [T] Clinical data at BLE advertiser (runs as root) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through BLE advertiser (runs as root), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-014 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** Broadcasts patient-linked data over the air. Confidentiality only here, but the process runs as root, so its compromise is a host compromise (CWE-250).  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-007

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-50 · [D] Clinical data from BLE advertiser (runs as root) may be unavailable when a decision has to be made — **HIGH**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes BLE advertiser (runs as root) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-015 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** Broadcasts patient-linked data over the air. Confidentiality only here, but the process runs as root, so its compromise is a host compromise (CWE-250).  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-007

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-40 · [S] BLE advertiser (runs as root) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach BLE advertiser (runs as root) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-41 · [T] Untrusted input reaches BLE advertiser (runs as root) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into BLE advertiser (runs as root) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-44 · [I] Weak authorisation over sensitive data in BLE advertiser (runs as root) — **HIGH**

_Information disclosure — violates Confidentiality_

BLE advertiser (runs as root) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-46 · [E] BLE advertiser (runs as root) runs with administrative privilege — **HIGH**

_Elevation of privilege — violates Authorisation_

Any code-execution or file-write bug in BLE advertiser (runs as root) immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Run as a dedicated unprivileged account with only the permissions the workload needs.
- Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.
- Separate administrative functions into their own component with its own identity.

#### T-47 · [E] No effective authorisation model in BLE advertiser (runs as root) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-42 · [T] Integrity of the code and configuration of BLE advertiser (runs as root) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that BLE advertiser (runs as root) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-43 · [R] BLE advertiser (runs as root) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through BLE advertiser (runs as root) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-45 · [D] BLE advertiser (runs as root) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads BLE advertiser (runs as root) has, taking it down for everyone.

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### Bedside kiosk (Chromium / matchbox on DSI panel) (Process)

_Full-screen bedside display of glucose + alarms; unlock via POST /kiosk/unlock. Owns tty1. Surface 8._

#### T-59 · [S] Alarms carried by Bedside kiosk (Chromium / matchbox on DSI panel) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Bedside kiosk (Chromium / matchbox on DSI panel) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-018 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-57 · [T] Alarm conditions or thresholds at Bedside kiosk (Chromium / matchbox on DSI panel) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside kiosk (Chromium / matchbox on DSI panel). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-016 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-61 · [T] Clinical data at Bedside kiosk (Chromium / matchbox on DSI panel) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside kiosk (Chromium / matchbox on DSI panel), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-020 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-58 · [D] Alarm delivery through Bedside kiosk (Chromium / matchbox on DSI panel) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside kiosk (Chromium / matchbox on DSI panel), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-017 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-62 · [D] Clinical data from Bedside kiosk (Chromium / matchbox on DSI panel) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside kiosk (Chromium / matchbox on DSI panel) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-021 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-310 · [S] Unauthenticated inbound flow "Bedside interaction" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Bedside interaction" from Clinician / caregiver carry no proof of who sent them. Bedside kiosk (Chromium / matchbox on DSI panel) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Bedside interaction

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-60 · [R] Alarm history at Bedside kiosk (Chromium / matchbox on DSI panel) is not reliable evidence — **HIGH**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Bedside kiosk (Chromium / matchbox on DSI panel).

> **Patient safety — SEC-HAZ-019 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-63 · [D] Loss of Bedside kiosk (Chromium / matchbox on DSI panel) delays or prevents care — **HIGH**

_Denial of service — violates Availability_

Bedside kiosk (Chromium / matchbox on DSI panel) is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

> **Patient safety — SEC-HAZ-022 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-311 · [E] Privilege crosses a trust boundary into Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Bedside interaction" enters Bedside kiosk (Chromium / matchbox on DSI panel) across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" without an authorisation decision of its own. Whatever the caller can request, Bedside kiosk (Chromium / matchbox on DSI panel) will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Bedside interaction

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-51 · [S] Bedside kiosk (Chromium / matchbox on DSI panel) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Bedside kiosk (Chromium / matchbox on DSI panel) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-322 · [S] Unauthenticated inbound flow "Touch input / rendered display" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Touch input / rendered display" from Touchscreen HMI (DSI panel + libinput) carry no proof of who sent them. Bedside kiosk (Chromium / matchbox on DSI panel) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Touch input / rendered display

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-323 · [S] Unauthenticated inbound flow "Paired HID input" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Paired HID input" from Bluetooth stack (BlueZ / bluetoothd, root) carry no proof of who sent them. Bedside kiosk (Chromium / matchbox on DSI panel) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Paired HID input

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-52 · [T] Untrusted input reaches Bedside kiosk (Chromium / matchbox on DSI panel) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Bedside kiosk (Chromium / matchbox on DSI panel) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-54 · [I] Weak authorisation over sensitive data in Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Information disclosure — violates Confidentiality_

Bedside kiosk (Chromium / matchbox on DSI panel) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-56 · [E] No effective authorisation model in Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-53 · [R] Bedside kiosk (Chromium / matchbox on DSI panel) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Bedside kiosk (Chromium / matchbox on DSI panel) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-55 · [D] Bedside kiosk (Chromium / matchbox on DSI panel) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Bedside kiosk (Chromium / matchbox on DSI panel) has, taking it down for everyone.

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### Touchscreen HMI (DSI panel + libinput) (Process)

_The 7-inch bedside touch panel: the only thing the clinician actually looks at, and the input device for the kiosk session on tty1. Physical surface — not one of the numbered lab surfaces._

#### T-156 · [S] Alarms carried by Touchscreen HMI (DSI panel + libinput) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Touchscreen HMI (DSI panel + libinput) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

> **Patient safety — SEC-HAZ-041 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-154 · [T] Alarm conditions or thresholds at Touchscreen HMI (DSI panel + libinput) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Touchscreen HMI (DSI panel + libinput). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-039 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-158 · [T] Clinical data at Touchscreen HMI (DSI panel + libinput) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Touchscreen HMI (DSI panel + libinput), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-043 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-155 · [D] Alarm delivery through Touchscreen HMI (DSI panel + libinput) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Touchscreen HMI (DSI panel + libinput), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-040 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-159 · [D] Clinical data from Touchscreen HMI (DSI panel + libinput) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Touchscreen HMI (DSI panel + libinput) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-044 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-157 · [R] Alarm history at Touchscreen HMI (DSI panel + libinput) is not reliable evidence — **HIGH**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Touchscreen HMI (DSI panel + libinput).

> **Patient safety — SEC-HAZ-042 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-160 · [D] Loss of Touchscreen HMI (DSI panel + libinput) delays or prevents care — **HIGH**

_Denial of service — violates Availability_

Touchscreen HMI (DSI panel + libinput) is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

> **Patient safety — SEC-HAZ-045 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-148 · [S] Touchscreen HMI (DSI panel + libinput) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Touchscreen HMI (DSI panel + libinput) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-320 · [S] Unauthenticated inbound flow "Unattended panel use" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Unattended panel use" from Visitor at the bedside carry no proof of who sent them. Touchscreen HMI (DSI panel + libinput) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Unattended panel use

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-149 · [T] Untrusted input reaches Touchscreen HMI (DSI panel + libinput) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Touchscreen HMI (DSI panel + libinput) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-151 · [I] Weak authorisation over sensitive data in Touchscreen HMI (DSI panel + libinput) — **HIGH**

_Information disclosure — violates Confidentiality_

Touchscreen HMI (DSI panel + libinput) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-153 · [E] No effective authorisation model in Touchscreen HMI (DSI panel + libinput) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-321 · [E] Privilege crosses a trust boundary into Touchscreen HMI (DSI panel + libinput) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Unattended panel use" enters Touchscreen HMI (DSI panel + libinput) across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)" without an authorisation decision of its own. Whatever the caller can request, Touchscreen HMI (DSI panel + libinput) will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Unattended panel use

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-150 · [R] Touchscreen HMI (DSI panel + libinput) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Touchscreen HMI (DSI panel + libinput) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-152 · [D] Touchscreen HMI (DSI panel + libinput) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Touchscreen HMI (DSI panel + libinput) has, taking it down for everyone.

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### HL7 v2 query / result (MLLP) (Data flow)

_QRY^Q01 in, ORU^R01 with PHI out. Cleartext, unauthenticated._

#### T-191 · [T] Clinical data at HL7 v2 query / result (MLLP) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through HL7 v2 query / result (MLLP), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-052 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-005

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-192 · [D] Clinical data from HL7 v2 query / result (MLLP) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes HL7 v2 query / result (MLLP) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-053 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-005

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-185 · [T] Traffic on "HL7 v2 query / result (MLLP)" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-187 · [I] Data on "HL7 v2 query / result (MLLP)" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-186 · [T] No end-to-end integrity on "HL7 v2 query / result (MLLP)" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-188 · [I] Sensitive data leaves a trust boundary on "HL7 v2 query / result (MLLP)" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-189 · [D] "HL7 v2 query / result (MLLP)" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-190 · [D] Availability of "HL7 v2 query / result (MLLP)" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside display feed (Data flow)

_Glucose + alarm state pushed to the kiosk._

#### T-227 · [T] Alarm conditions or thresholds at Bedside display feed can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside display feed. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-064 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-229 · [T] Clinical data at Bedside display feed can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside display feed, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-066 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-228 · [D] Alarm delivery through Bedside display feed can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside display feed, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-065 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-230 · [D] Clinical data from Bedside display feed may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside display feed unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-067 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-224 · [T] Traffic on "Bedside display feed" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-225 · [I] Data on "Bedside display feed" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-226 · [D] Availability of "Bedside display feed" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### BLE advertisement (RF) (Data flow)

_Non-connectable broadcast of XOR-obfuscated manufacturer data (company id 0xFFFF)._

#### T-237 · [T] Clinical data at BLE advertisement (RF) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through BLE advertisement (RF), or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-068 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-007

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-238 · [D] Clinical data from BLE advertisement (RF) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes BLE advertisement (RF) unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-069 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-007

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-231 · [T] Traffic on "BLE advertisement (RF)" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-233 · [I] Data on "BLE advertisement (RF)" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-232 · [T] No end-to-end integrity on "BLE advertisement (RF)" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-234 · [I] Sensitive data leaves a trust boundary on "BLE advertisement (RF)" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-235 · [D] "BLE advertisement (RF)" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-236 · [D] Availability of "BLE advertisement (RF)" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Touch input / rendered display (Data flow)

_Touch events into the kiosk session on tty1, and the glucose trend and alarm view rendered back to the panel._

#### T-275 · [T] Alarm conditions or thresholds at Touch input / rendered display can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Touch input / rendered display. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-070 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-277 · [T] Clinical data at Touch input / rendered display can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Touch input / rendered display, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-072 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-276 · [D] Alarm delivery through Touch input / rendered display can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Touch input / rendered display, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-071 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-278 · [D] Clinical data from Touch input / rendered display may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Touch input / rendered display unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-073 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-272 · [T] Traffic on "Touch input / rendered display" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-273 · [I] Data on "Touch input / rendered display" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-274 · [D] Availability of "Touch input / rendered display" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Paired HID input (Data flow)

_A Bluetooth keyboard paired from outside the bay types into the kiosk session exactly as the bedside user would._

#### T-293 · [T] Alarm conditions or thresholds at Paired HID input can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Paired HID input. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

> **Patient safety — SEC-HAZ-078 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-011

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-294 · [D] Alarm delivery through Paired HID input can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Paired HID input, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

> **Patient safety — SEC-HAZ-079 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-011

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-295 · [D] Loss of Paired HID input delays or prevents care — **HIGH**

_Denial of service — violates Availability_

Paired HID input is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

> **Patient safety — SEC-HAZ-080 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-011

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-290 · [T] Traffic on "Paired HID input" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-291 · [I] Data on "Paired HID input" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-292 · [D] Availability of "Paired HID input" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### HL7 MLLP listener (Process)

_Answers a well-formed QRY^Q01 for a known MRN with an ORU^R01 (PHI). Serial in MSH-3; flag in NTE. TCP 2575. Surface 5._

#### T-24 · [T] Clinical data at HL7 MLLP listener can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through HL7 MLLP listener, or the data of one patient can be presented as another's, without the clinician being able to detect it.

> **Patient safety — SEC-HAZ-003 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** Discloses per-patient glucose results and the device serial to any HL7 speaker; wrong or leaked results can misinform a downstream clinical decision.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-005

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-25 · [D] Clinical data from HL7 MLLP listener may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes HL7 MLLP listener unavailable at the moment a clinician needs the data it holds or carries.

> **Patient safety — SEC-HAZ-004 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** Discloses per-patient glucose results and the device serial to any HL7 speaker; wrong or leaked results can misinform a downstream clinical decision.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-005

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-312 · [S] Unauthenticated inbound flow "HL7 v2 query / result (MLLP)" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "HL7 v2 query / result (MLLP)" from Hospital LIS / EHR interface carry no proof of who sent them. HL7 MLLP listener therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: HL7 v2 query / result (MLLP)

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-314 · [S] Unauthenticated inbound flow "Rogue HL7 query" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Rogue HL7 query" from Unauthenticated network client carry no proof of who sent them. HL7 MLLP listener therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

Via data flow: Rogue HL7 query

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-313 · [E] Privilege crosses a trust boundary into HL7 MLLP listener — **HIGH**

_Elevation of privilege — violates Authorisation_

"HL7 v2 query / result (MLLP)" enters HL7 MLLP listener across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" without an authorisation decision of its own. Whatever the caller can request, HL7 MLLP listener will perform - so the trust of the far side becomes the trust of this side.

Via data flow: HL7 v2 query / result (MLLP)

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-315 · [E] Privilege crosses a trust boundary into HL7 MLLP listener — **HIGH**

_Elevation of privilege — violates Authorisation_

"Rogue HL7 query" enters HL7 MLLP listener across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" without an authorisation decision of its own. Whatever the caller can request, HL7 MLLP listener will perform - so the trust of the far side becomes the trust of this side.

Via data flow: Rogue HL7 query

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-18 · [S] HL7 MLLP listener accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach HL7 MLLP listener is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-19 · [T] Untrusted input reaches HL7 MLLP listener without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into HL7 MLLP listener is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-21 · [I] Weak authorisation over sensitive data in HL7 MLLP listener — **HIGH**

_Information disclosure — violates Confidentiality_

HL7 MLLP listener handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-23 · [E] No effective authorisation model in HL7 MLLP listener — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-20 · [R] HL7 MLLP listener keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through HL7 MLLP listener cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-22 · [D] HL7 MLLP listener has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads HL7 MLLP listener has, taking it down for everyone.

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

### Unauthenticated network client (Entity)

_Any device on the lab LAN, and the student's Kali box. Anonymous until it defeats a control._

#### T-01 · [S] No proof of identity for Unauthenticated network client — **HIGH**

_Spoofing — violates Authentication_

Nothing establishes that a request really comes from Unauthenticated network client. An attacker on the network, or anyone who can reach the interface, can act as Unauthenticated network client and every downstream decision made about that identity is worthless.

**Recommended mitigations:**
- Require authentication before any state-changing or data-returning operation.
- Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.
- Bind the session to the authenticated identity and re-check it on every request, not just at login.

#### T-02 · [R] Actions by Unauthenticated network client are not attributable — **HIGH**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Unauthenticated network client did. Unauthenticated network client can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

#### T-03 · [R] Anonymous actor touches sensitive data — **HIGH**

_Repudiation — violates Non-repudiation_

Unauthenticated network client is untrusted and unidentified, yet the interaction involves sensitive data. Nothing can be attributed to a specific person, so abuse is invisible and disputes are unresolvable.

**Recommended mitigations:**
- Require identification before sensitive data is reached, even if the rest of the flow stays anonymous.
- If anonymity is a requirement, minimise what sensitive data is exposed on the anonymous path.

### Visitor at the bedside (Entity)

_A visitor, a patient, a cleaner or a contractor: unauthenticated, unsupervised, and alone with the device for minutes at a time._

#### T-116 · [S] No proof of identity for Visitor at the bedside — **HIGH**

_Spoofing — violates Authentication_

Nothing establishes that a request really comes from Visitor at the bedside. An attacker on the network, or anyone who can reach the interface, can act as Visitor at the bedside and every downstream decision made about that identity is worthless.

**Recommended mitigations:**
- Require authentication before any state-changing or data-returning operation.
- Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.
- Bind the session to the authenticated identity and re-check it on every request, not just at login.

#### T-117 · [R] Actions by Visitor at the bedside are not attributable — **HIGH**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Visitor at the bedside did. Visitor at the bedside can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

#### T-118 · [R] Anonymous actor touches sensitive data — **HIGH**

_Repudiation — violates Non-repudiation_

Visitor at the bedside is untrusted and unidentified, yet the interaction involves sensitive data. Nothing can be attributed to a specific person, so abuse is invisible and disputes are unresolvable.

**Recommended mitigations:**
- Require identification before sensitive data is reached, even if the rest of the flow stays anonymous.
- If anonymity is a requirement, minimise what sensitive data is exposed on the anonymous path.

### Host shell (biomed via SSH) (Process)

_SSH foothold + local privilege escalation to root. Surface 9._

#### T-65 · [T] Untrusted input reaches Host shell (biomed via SSH) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Host shell (biomed via SSH) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-68 · [I] Weak authorisation over sensitive data in Host shell (biomed via SSH) — **HIGH**

_Information disclosure — violates Confidentiality_

Host shell (biomed via SSH) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-71 · [E] Coarse authorisation in Host shell (biomed via SSH) — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-64 · [S] Clients cannot verify they are talking to the real Host shell (biomed via SSH) — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Host shell (biomed via SSH). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-66 · [T] Integrity of the code and configuration of Host shell (biomed via SSH) — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Host shell (biomed via SSH) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-67 · [R] Host shell (biomed via SSH) keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Host shell (biomed via SSH) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-70 · [D] Host shell (biomed via SSH) has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Host shell (biomed via SSH) has, taking it down for everyone.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-69 · [I] Leakage through errors, responses and telemetry from Host shell (biomed via SSH) — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Host shell (biomed via SSH) - versions, paths, schema, and whether a given account exists.

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Device config (cgm.conf) (Data store)

_Holds the MQTT credentials, the device serial (BLE key) and a maintenance token. World-readable, one dir above the report root. Surface 3._

#### T-81 · [T] Unrestricted write access to Device config (cgm.conf) — **HIGH**

_Tampering — violates Integrity_

Write access to Device config (cgm.conf) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-83 · [R] Regulated records in Device config (cgm.conf) without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Device config (cgm.conf) holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-84 · [I] Sensitive data stored unencrypted in Device config (cgm.conf) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Device config (cgm.conf) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-85 · [I] Weak access control on Device config (cgm.conf) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Device config (cgm.conf) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-86 · [D] Loss of Device config (cgm.conf) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Device config (cgm.conf) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-80 · [T] Modification of Device config (cgm.conf) would go unnoticed — **HIGH**

_Tampering — violates Integrity_

Nothing proves that the contents of Device config (cgm.conf) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-82 · [R] No access log for Device config (cgm.conf) — **HIGH**

_Repudiation — violates Non-repudiation_

Reads and writes against Device config (cgm.conf) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-87 · [D] Resource exhaustion against Device config (cgm.conf) — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Device config (cgm.conf) unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### HTTP attack surface (Data flow)

_SQLi login, cookie forgery + IDOR, path traversal, rate-limit bypass, kiosk unlock._

#### T-161 · [T] Traffic on "HTTP attack surface" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-163 · [I] Data on "HTTP attack surface" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-162 · [T] No end-to-end integrity on "HTTP attack surface" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-164 · [I] Sensitive data leaves a trust boundary on "HTTP attack surface" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-165 · [D] "HTTP attack surface" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-166 · [D] Availability of "HTTP attack surface" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Rogue HL7 query (Data flow)

_Any HL7 speaker crafts a valid QRY^Q01 and receives PHI + serial._

#### T-239 · [T] Traffic on "Rogue HL7 query" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-241 · [I] Data on "Rogue HL7 query" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-240 · [T] No end-to-end integrity on "Rogue HL7 query" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-242 · [I] Sensitive data leaves a trust boundary on "Rogue HL7 query" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-243 · [D] "Rogue HL7 query" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-244 · [D] Availability of "Rogue HL7 query" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Clinician / caregiver (Entity)

_Reads glucose and hypo/hyper alarms on the console and bedside kiosk, and acts on them._

#### T-04 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate Clinician / caregiver. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-05 · [R] Actions by Clinician / caregiver are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Clinician / caregiver did. Clinician / caregiver can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### Hospital LIS / EHR interface (Entity)

_Upstream clinical system that queries the CGM over HL7 v2 (MLLP) for glucose results._

#### T-06 · [S] No proof of identity for Hospital LIS / EHR interface — **HIGH**

_Spoofing — violates Authentication_

Nothing establishes that a request really comes from Hospital LIS / EHR interface. An attacker on the network, or anyone who can reach the interface, can act as Hospital LIS / EHR interface and every downstream decision made about that identity is worthless.

**Recommended mitigations:**
- Require authentication before any state-changing or data-returning operation.
- Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.
- Bind the session to the authenticated identity and re-check it on every request, not just at login.

#### T-07 · [R] Actions by Hospital LIS / EHR interface are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Hospital LIS / EHR interface did. Hospital LIS / EHR interface can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### CGM sensor + BLE gateway (Entity)

_The wearable sensor front end that publishes legitimate glucose readings and alarm state onto glucose/#._

#### T-106 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate CGM sensor + BLE gateway. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-107 · [R] Actions by CGM sensor + BLE gateway are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what CGM sensor + BLE gateway did. CGM sensor + BLE gateway can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### User store (cgm.db, SQLite) (Data store)

_Seeded username/role/password rows queried by the login. Surface 1._

#### T-73 · [T] Unrestricted write access to User store (cgm.db, SQLite) — **HIGH**

_Tampering — violates Integrity_

Write access to User store (cgm.db, SQLite) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-75 · [R] Regulated records in User store (cgm.db, SQLite) without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

User store (cgm.db, SQLite) holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-76 · [I] Sensitive data stored unencrypted in User store (cgm.db, SQLite) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of User store (cgm.db, SQLite) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-77 · [I] Weak access control on User store (cgm.db, SQLite) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to User store (cgm.db, SQLite) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-78 · [D] Loss of User store (cgm.db, SQLite) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of User store (cgm.db, SQLite) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-72 · [T] Modification of User store (cgm.db, SQLite) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of User store (cgm.db, SQLite) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-74 · [R] No access log for User store (cgm.db, SQLite) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against User store (cgm.db, SQLite) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-79 · [D] Resource exhaustion against User store (cgm.db, SQLite) — **LOW**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make User store (cgm.db, SQLite) unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Root filesystem / sudoers (/etc/sudoers.d, /root) (Data store)

_The NOPASSWD sudoers drop-in and /root/flag.txt (mode 600). Surface 9._

#### T-100 · [T] Unrestricted write access to Root filesystem / sudoers (/etc/sudoers.d, /root) — **HIGH**

_Tampering — violates Integrity_

Write access to Root filesystem / sudoers (/etc/sudoers.d, /root) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-102 · [I] Sensitive data stored unencrypted in Root filesystem / sudoers (/etc/sudoers.d, /root) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Root filesystem / sudoers (/etc/sudoers.d, /root) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-103 · [I] Weak access control on Root filesystem / sudoers (/etc/sudoers.d, /root) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Root filesystem / sudoers (/etc/sudoers.d, /root) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-104 · [D] Loss of Root filesystem / sudoers (/etc/sudoers.d, /root) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Root filesystem / sudoers (/etc/sudoers.d, /root) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-99 · [T] Modification of Root filesystem / sudoers (/etc/sudoers.d, /root) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Root filesystem / sudoers (/etc/sudoers.d, /root) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-101 · [R] No access log for Root filesystem / sudoers (/etc/sudoers.d, /root) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Root filesystem / sudoers (/etc/sudoers.d, /root) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-105 · [D] Resource exhaustion against Root filesystem / sudoers (/etc/sudoers.d, /root) — **LOW**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Root filesystem / sudoers (/etc/sudoers.d, /root) unavailable without any need to break into it.

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Login query (Data flow)

_String-built SELECT against the user table (SQLi)._

#### T-193 · [T] Traffic on "Login query" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-194 · [I] Data on "Login query" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-195 · [D] Availability of "Login query" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Diagnostic export / config read (Data flow)

_/admin/export joins the filename with no containment -> traversal._

#### T-196 · [T] Traffic on "Diagnostic export / config read" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-197 · [I] Data on "Diagnostic export / config read" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-198 · [D] Availability of "Diagnostic export / config read" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Console telemetry (Data flow)

_Console reads current glucose/alarm state to display._

#### T-199 · [T] Traffic on "Console telemetry" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-200 · [I] Data on "Console telemetry" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-201 · [D] Availability of "Console telemetry" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Retained telemetry (Data flow)

_Broker persists the latest retained reading/alarm per topic._

#### T-209 · [T] Traffic on "Retained telemetry" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-210 · [I] Data on "Retained telemetry" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-211 · [D] Availability of "Retained telemetry" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Privilege escalation (Data flow)

_NOPASSWD sudo on /usr/bin/awk (GTFOBins) spawns a root shell._

#### T-249 · [T] Traffic on "Privilege escalation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-250 · [I] Data on "Privilege escalation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-251 · [D] Availability of "Privilege escalation" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### USB port access (Data flow)

_BadUSB keystroke injection, auto-mounted mass storage, a bootable stick, and imaging the SD card off the device._

#### T-252 · [T] Traffic on "USB port access" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-254 · [I] Data on "USB port access" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-253 · [T] No end-to-end integrity on "USB port access" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-255 · [I] Sensitive data leaves a trust boundary on "USB port access" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-256 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-257 · [D] "USB port access" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-258 · [D] Availability of "USB port access" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bluetooth pairing / GATT access (Data flow)

_Just Works pairing of an HID keyboard, GATT enumeration of the advertiser, and RF flooding of the controller — all from outside the bay._

#### T-259 · [T] Traffic on "Bluetooth pairing / GATT access" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-261 · [I] Data on "Bluetooth pairing / GATT access" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-260 · [T] No end-to-end integrity on "Bluetooth pairing / GATT access" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-262 · [I] Sensitive data leaves a trust boundary on "Bluetooth pairing / GATT access" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-263 · [D] "Bluetooth pairing / GATT access" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-264 · [D] Availability of "Bluetooth pairing / GATT access" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Unattended panel use (Data flow)

_Anyone in the bay can read the panel and drive it: kiosk PIN guessing, gesture escape to the browser, on-screen keyboard._

#### T-265 · [T] Traffic on "Unattended panel use" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-267 · [I] Data on "Unattended panel use" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-266 · [T] No end-to-end integrity on "Unattended panel use" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-268 · [I] Sensitive data leaves a trust boundary on "Unattended panel use" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-269 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-270 · [D] "Unattended panel use" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-271 · [D] Availability of "Unattended panel use" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Removable-media config copy (Data flow)

_Diagnostic dumps written to a USB stick and config restored from one — the device serial and the MQTT credentials travel with them._

#### T-296 · [T] Traffic on "Removable-media config copy" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-297 · [I] Data on "Removable-media config copy" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-298 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-299 · [D] Availability of "Removable-media config copy" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Auto-mount + udev rule execution (Data flow)

_Mount helpers and udev rules run as root the moment a device enumerates, so removable media reaches the root filesystem without anyone logging in._

#### T-300 · [T] Traffic on "Auto-mount + udev rule execution" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-302 · [I] Data on "Auto-mount + udev rule execution" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-301 · [T] No end-to-end integrity on "Auto-mount + udev rule execution" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-303 · [I] Sensitive data leaves a trust boundary on "Auto-mount + udev rule execution" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Host OS / root (SSH)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-304 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-305 · [D] "Auto-mount + udev rule execution" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-306 · [D] Availability of "Auto-mount + udev rule execution" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### HCI advertising control (Data flow)

_The advertiser drives the same controller through BlueZ, so whoever owns bluetoothd owns what the device broadcasts._

#### T-307 · [T] Traffic on "HCI advertising control" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-308 · [I] Data on "HCI advertising control" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-309 · [D] Availability of "HCI advertising control" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Device & broker credentials (Asset)

_MQTT creds, Flask session secret, device serial, biomed SSH password._

#### T-114 · [I] Exposure of the secret Device & broker credentials — **HIGH**

_Information disclosure — violates Confidentiality_

Secrets leak through source control, build logs, container images, environment dumps, error pages and backups. A leaked secret hands over every privilege it grants, and its use by an attacker is indistinguishable from legitimate use.

**Recommended mitigations:**
- Hold secrets in a managed secret store; inject at runtime, never bake into images or repos.
- Rotate on a schedule and immediately on suspicion; make rotation cheap enough to actually do.
- Scan repositories, logs and images for secret material continuously.

#### T-113 · [I] Confidentiality of the asset Device & broker credentials — **MEDIUM**

_Information disclosure — violates Confidentiality_

Device & broker credentials is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

#### T-115 · [D] Availability of the asset Device & broker credentials — **MEDIUM**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

### SSH foothold (Data flow)

_Password-auth SSH; biomed's password is dictionary-crackable._

#### T-245 · [T] No end-to-end integrity on "SSH foothold" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-246 · [I] Sensitive data leaves a trust boundary on "SSH foothold" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "Host OS / root (SSH)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-247 · [D] "SSH foothold" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-248 · [D] Availability of "SSH foothold" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Hypo / hyper alarm path (Asset)

_The end-to-end path that turns a real low or high into an alarm the clinician sees and acts on._

#### T-112 · [D] Availability of the asset Hypo / hyper alarm path — **HIGH**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

#### T-111 · [I] Confidentiality of the asset Hypo / hyper alarm path — **MEDIUM**

_Information disclosure — violates Confidentiality_

Hypo / hyper alarm path is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

### Patient glucose data / PHI (Asset)

_Per-patient readings, MRNs and demographics across HL7, MQTT and BLE._

#### T-110 · [T] Integrity of the asset Patient glucose data / PHI — **MEDIUM**

_Tampering — violates Integrity_

If Patient glucose data / PHI can be altered without detection, decisions made from it are wrong in a way nobody notices. Corruption of a valuable record is often more damaging, and much harder to spot, than its disclosure.

**Recommended mitigations:**
- Establish an authoritative source and reconcile copies against it.
- Keep a tamper-evident history of changes with attribution.

#### T-108 · [I] Confidentiality of the asset Patient glucose data / PHI — **MEDIUM**

_Information disclosure — violates Confidentiality_

Patient glucose data / PHI is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

#### T-109 · [D] Availability of the asset Patient glucose data / PHI — **MEDIUM**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

## 5. Patient safety traceability

Each row is a security threat with a credible path to patient harm. Carry the hazard reference into the safety risk management file (CGM-3000 Risk Management File (ISO 14971), RMF-CGM-3000 rev A) so the security control and the safety risk control are the same decision.

| Hazard ref | Threat | Element | STRIDE | Safety impact | Hazardous situation -> harm | Severity of harm | Severity | Safety file ref |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-HAZ-001 | T-16 | Web admin console (Flask) | T | Clinical data | Clinical data at Web admin console (Flask) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002, RC-021 |
| SEC-HAZ-002 | T-17 | Web admin console (Flask) | D | Clinical data | Clinical data from Web admin console (Flask) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002, RC-021 |
| SEC-HAZ-003 | T-24 | HL7 MLLP listener | T | Clinical data | Clinical data at HL7 MLLP listener can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-004 | T-25 | HL7 MLLP listener | D | Clinical data | Clinical data from HL7 MLLP listener may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-005 | T-31 | MQTT broker (mosquitto) | T | Device control | Therapy parameters handled by MQTT broker (mosquitto) can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-006 | T-32 | MQTT broker (mosquitto) | E | Device control | Therapy control functions in MQTT broker (mosquitto) are reachable without a clinical authorisation decision -> Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-007 | T-33 | MQTT broker (mosquitto) | D | Device control | Loss of MQTT broker (mosquitto) removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-008 | T-34 | MQTT broker (mosquitto) | R | Device control | Therapy changes at MQTT broker (mosquitto) cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-009 | T-35 | MQTT broker (mosquitto) | T | Alarms | Alarm conditions or thresholds at MQTT broker (mosquitto) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | HIGH | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-010 | T-36 | MQTT broker (mosquitto) | D | Alarms | Alarm delivery through MQTT broker (mosquitto) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-011 | T-37 | MQTT broker (mosquitto) | R | Alarms | Alarm history at MQTT broker (mosquitto) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-012 | T-38 | MQTT broker (mosquitto) | T | Clinical data | Clinical data at MQTT broker (mosquitto) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-013 | T-39 | MQTT broker (mosquitto) | D | Clinical data | Clinical data from MQTT broker (mosquitto) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-014 | T-49 | BLE advertiser (runs as root) | T | Clinical data | Clinical data at BLE advertiser (runs as root) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-007 |
| SEC-HAZ-015 | T-50 | BLE advertiser (runs as root) | D | Clinical data | Clinical data from BLE advertiser (runs as root) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | HIGH | SEC-HAZ-007 |
| SEC-HAZ-016 | T-57 | Bedside kiosk (Chromium / matchbox on DSI panel) | T | Alarms | Alarm conditions or thresholds at Bedside kiosk (Chromium / matchbox on DSI panel) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-017 | T-58 | Bedside kiosk (Chromium / matchbox on DSI panel) | D | Alarms | Alarm delivery through Bedside kiosk (Chromium / matchbox on DSI panel) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-018 | T-59 | Bedside kiosk (Chromium / matchbox on DSI panel) | S | Alarms | Alarms carried by Bedside kiosk (Chromium / matchbox on DSI panel) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-019 | T-60 | Bedside kiosk (Chromium / matchbox on DSI panel) | R | Alarms | Alarm history at Bedside kiosk (Chromium / matchbox on DSI panel) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-008 |
| SEC-HAZ-020 | T-61 | Bedside kiosk (Chromium / matchbox on DSI panel) | T | Clinical data | Clinical data at Bedside kiosk (Chromium / matchbox on DSI panel) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-021 | T-62 | Bedside kiosk (Chromium / matchbox on DSI panel) | D | Clinical data | Clinical data from Bedside kiosk (Chromium / matchbox on DSI panel) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-022 | T-63 | Bedside kiosk (Chromium / matchbox on DSI panel) | D | Care delivery | Loss of Bedside kiosk (Chromium / matchbox on DSI panel) delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-008 |
| SEC-HAZ-023 | T-94 | Glucose telemetry (MQTT glucose/#, retained) | T | Clinical data | Clinical data at Glucose telemetry (MQTT glucose/#, retained) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-024 | T-95 | Glucose telemetry (MQTT glucose/#, retained) | D | Clinical data | Clinical data from Glucose telemetry (MQTT glucose/#, retained) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-025 | T-96 | Glucose telemetry (MQTT glucose/#, retained) | T | Alarms | Alarm conditions or thresholds at Glucose telemetry (MQTT glucose/#, retained) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-026 | T-97 | Glucose telemetry (MQTT glucose/#, retained) | D | Alarms | Alarm delivery through Glucose telemetry (MQTT glucose/#, retained) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-027 | T-98 | Glucose telemetry (MQTT glucose/#, retained) | R | Alarms | Alarm history at Glucose telemetry (MQTT glucose/#, retained) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-028 | T-128 | USB host ports (udev auto-mount) | T | Alarms | Alarm conditions or thresholds at USB host ports (udev auto-mount) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-029 | T-129 | USB host ports (udev auto-mount) | D | Alarms | Alarm delivery through USB host ports (udev auto-mount) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-030 | T-130 | USB host ports (udev auto-mount) | S | Alarms | Alarms carried by USB host ports (udev auto-mount) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-031 | T-131 | USB host ports (udev auto-mount) | R | Alarms | Alarm history at USB host ports (udev auto-mount) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-032 | T-132 | USB host ports (udev auto-mount) | D | Care delivery | Loss of USB host ports (udev auto-mount) delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-033 | T-142 | Bluetooth stack (BlueZ / bluetoothd, root) | T | Clinical data | Clinical data at Bluetooth stack (BlueZ / bluetoothd, root) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-034 | T-143 | Bluetooth stack (BlueZ / bluetoothd, root) | D | Clinical data | Clinical data from Bluetooth stack (BlueZ / bluetoothd, root) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-035 | T-144 | Bluetooth stack (BlueZ / bluetoothd, root) | T | Alarms | Alarm conditions or thresholds at Bluetooth stack (BlueZ / bluetoothd, root) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-036 | T-145 | Bluetooth stack (BlueZ / bluetoothd, root) | D | Alarms | Alarm delivery through Bluetooth stack (BlueZ / bluetoothd, root) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-037 | T-146 | Bluetooth stack (BlueZ / bluetoothd, root) | S | Alarms | Alarms carried by Bluetooth stack (BlueZ / bluetoothd, root) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-038 | T-147 | Bluetooth stack (BlueZ / bluetoothd, root) | R | Alarms | Alarm history at Bluetooth stack (BlueZ / bluetoothd, root) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-039 | T-154 | Touchscreen HMI (DSI panel + libinput) | T | Alarms | Alarm conditions or thresholds at Touchscreen HMI (DSI panel + libinput) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-040 | T-155 | Touchscreen HMI (DSI panel + libinput) | D | Alarms | Alarm delivery through Touchscreen HMI (DSI panel + libinput) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-041 | T-156 | Touchscreen HMI (DSI panel + libinput) | S | Alarms | Alarms carried by Touchscreen HMI (DSI panel + libinput) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-042 | T-157 | Touchscreen HMI (DSI panel + libinput) | R | Alarms | Alarm history at Touchscreen HMI (DSI panel + libinput) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-012 |
| SEC-HAZ-043 | T-158 | Touchscreen HMI (DSI panel + libinput) | T | Clinical data | Clinical data at Touchscreen HMI (DSI panel + libinput) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-044 | T-159 | Touchscreen HMI (DSI panel + libinput) | D | Clinical data | Clinical data from Touchscreen HMI (DSI panel + libinput) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-045 | T-160 | Touchscreen HMI (DSI panel + libinput) | D | Care delivery | Loss of Touchscreen HMI (DSI panel + libinput) delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-012 |
| SEC-HAZ-046 | T-173 | Console session | T | Clinical data | Clinical data at Console session can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002 |
| SEC-HAZ-047 | T-174 | Console session | D | Clinical data | Clinical data from Console session may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002 |
| SEC-HAZ-048 | T-181 | Bedside interaction | T | Alarms | Alarm conditions or thresholds at Bedside interaction can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-049 | T-182 | Bedside interaction | D | Alarms | Alarm delivery through Bedside interaction can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-050 | T-183 | Bedside interaction | T | Clinical data | Clinical data at Bedside interaction can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-051 | T-184 | Bedside interaction | D | Clinical data | Clinical data from Bedside interaction may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-052 | T-191 | HL7 v2 query / result (MLLP) | T | Clinical data | Clinical data at HL7 v2 query / result (MLLP) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-053 | T-192 | HL7 v2 query / result (MLLP) | D | Clinical data | Clinical data from HL7 v2 query / result (MLLP) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-054 | T-205 | Legitimate glucose publish | T | Clinical data | Clinical data at Legitimate glucose publish can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-055 | T-206 | Legitimate glucose publish | D | Clinical data | Clinical data from Legitimate glucose publish may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-056 | T-207 | Legitimate glucose publish | T | Alarms | Alarm conditions or thresholds at Legitimate glucose publish can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-057 | T-208 | Legitimate glucose publish | D | Alarms | Alarm delivery through Legitimate glucose publish can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-058 | T-218 | Forged-reading injection | T | Device control | Therapy parameters handled by Forged-reading injection can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-059 | T-219 | Forged-reading injection | D | Device control | Loss of Forged-reading injection removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-060 | T-220 | Forged-reading injection | T | Alarms | Alarm conditions or thresholds at Forged-reading injection can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-061 | T-221 | Forged-reading injection | D | Alarms | Alarm delivery through Forged-reading injection can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-062 | T-222 | Forged-reading injection | T | Clinical data | Clinical data at Forged-reading injection can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-063 | T-223 | Forged-reading injection | D | Clinical data | Clinical data from Forged-reading injection may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-064 | T-227 | Bedside display feed | T | Alarms | Alarm conditions or thresholds at Bedside display feed can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-065 | T-228 | Bedside display feed | D | Alarms | Alarm delivery through Bedside display feed can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-066 | T-229 | Bedside display feed | T | Clinical data | Clinical data at Bedside display feed can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-067 | T-230 | Bedside display feed | D | Clinical data | Clinical data from Bedside display feed may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-068 | T-237 | BLE advertisement (RF) | T | Clinical data | Clinical data at BLE advertisement (RF) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-007 |
| SEC-HAZ-069 | T-238 | BLE advertisement (RF) | D | Clinical data | Clinical data from BLE advertisement (RF) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-007 |
| SEC-HAZ-070 | T-275 | Touch input / rendered display | T | Alarms | Alarm conditions or thresholds at Touch input / rendered display can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-071 | T-276 | Touch input / rendered display | D | Alarms | Alarm delivery through Touch input / rendered display can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-072 | T-277 | Touch input / rendered display | T | Clinical data | Clinical data at Touch input / rendered display can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-073 | T-278 | Touch input / rendered display | D | Clinical data | Clinical data from Touch input / rendered display may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-074 | T-286 | Bedside annunciation | T | Alarms | Alarm conditions or thresholds at Bedside annunciation can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-075 | T-287 | Bedside annunciation | D | Alarms | Alarm delivery through Bedside annunciation can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-076 | T-288 | Bedside annunciation | T | Clinical data | Clinical data at Bedside annunciation can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-077 | T-289 | Bedside annunciation | D | Clinical data | Clinical data from Bedside annunciation may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-078 | T-293 | Paired HID input | T | Alarms | Alarm conditions or thresholds at Paired HID input can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-079 | T-294 | Paired HID input | D | Alarms | Alarm delivery through Paired HID input can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-080 | T-295 | Paired HID input | D | Care delivery | Loss of Paired HID input delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-011 |

### 5.1 Safety-relevant elements with no threat raised

Record these in the safety file as justified residual risks.

| Element | Safety functions | Severity of harm | Controls in place | Safety file ref |
| --- | --- | --- | --- | --- |
| Clinician / caregiver | Clinical data; Alarms | Serious — injury needing professional intervention | none recorded | SEC-HAZ-004 |
| CGM sensor + BLE gateway | Clinical data; Alarms | Critical — permanent impairment or life-threatening injury | none recorded | SEC-HAZ-001 |
| Hypo / hyper alarm path | Alarms; Device control | Critical — permanent impairment or life-threatening injury | none recorded | SEC-HAZ-001, RC-012 |

### 5.2 Breaks in the safety trace

| Element | Type | What is missing |
| --- | --- | --- |
| Unauthenticated network client | Entity | Patient safety impact has not been assessed for this element. |
| Hospital LIS / EHR interface | Entity | Patient safety impact has not been assessed for this element. |
| Host shell (biomed via SSH) | Process | Patient safety impact has not been assessed for this element. |
| User store (cgm.db, SQLite) | Data store | Patient safety impact has not been assessed for this element. |
| Device config (cgm.conf) | Data store | Patient safety impact has not been assessed for this element. |
| Root filesystem / sudoers (/etc/sudoers.d, /root) | Data store | Patient safety impact has not been assessed for this element. |
| Patient glucose data / PHI | Asset | Patient safety impact has not been assessed for this element. |
| Device & broker credentials | Asset | Patient safety impact has not been assessed for this element. |
| Visitor at the bedside | Entity | Patient safety impact has not been assessed for this element. |
| HTTP attack surface | Data flow | Patient safety impact has not been assessed for this element. |
| Login query | Data flow | Patient safety impact has not been assessed for this element. |
| Diagnostic export / config read | Data flow | Patient safety impact has not been assessed for this element. |
| Console telemetry | Data flow | Patient safety impact has not been assessed for this element. |
| Retained telemetry | Data flow | Patient safety impact has not been assessed for this element. |
| Rogue HL7 query | Data flow | Patient safety impact has not been assessed for this element. |
| SSH foothold | Data flow | Patient safety impact has not been assessed for this element. |
| Privilege escalation | Data flow | Patient safety impact has not been assessed for this element. |
| USB port access | Data flow | Patient safety impact has not been assessed for this element. |
| Bluetooth pairing / GATT access | Data flow | Patient safety impact has not been assessed for this element. |
| Unattended panel use | Data flow | Patient safety impact has not been assessed for this element. |
| Removable-media config copy | Data flow | Patient safety impact has not been assessed for this element. |
| Auto-mount + udev rule execution | Data flow | Patient safety impact has not been assessed for this element. |
| HCI advertising control | Data flow | Patient safety impact has not been assessed for this element. |

## 6. Coverage gaps

| Element | Type | Unanswered categories |
| --- | --- | --- |
| Unauthenticated network client | Entity | Safety-relevant functions, Worst-case severity of harm, Hazardous situation |
| Hospital LIS / EHR interface | Entity | Safety-relevant functions, Worst-case severity of harm, Hazardous situation |
| Host shell (biomed via SSH) | Process | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| User store (cgm.db, SQLite) | Data store | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Device config (cgm.conf) | Data store | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Root filesystem / sudoers (/etc/sudoers.d, /root) | Data store | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Patient glucose data / PHI | Asset | Safety-relevant functions, Worst-case severity of harm, Hazardous situation |
| Device & broker credentials | Asset | Safety-relevant functions, Worst-case severity of harm, Hazardous situation |
| Visitor at the bedside | Entity | Safety-relevant functions, Worst-case severity of harm, Hazardous situation |
| HTTP attack surface | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Console session | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Bedside interaction | Data flow | Software safety class (IEC 62304), Hazardous situation |
| HL7 v2 query / result (MLLP) | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Login query | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Diagnostic export / config read | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Console telemetry | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Legitimate glucose publish | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Retained telemetry | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Forged-reading injection | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Bedside display feed | Data flow | Software safety class (IEC 62304), Hazardous situation |
| BLE advertisement (RF) | Data flow | Software safety class (IEC 62304), Hazardous situation |
| Rogue HL7 query | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| SSH foothold | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Privilege escalation | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| USB port access | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Bluetooth pairing / GATT access | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Unattended panel use | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Touch input / rendered display | Data flow | Hazardous situation |
| Bedside annunciation | Data flow | Hazardous situation |
| Paired HID input | Data flow | Hazardous situation |
| Removable-media config copy | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| Auto-mount + udev rule execution | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |
| HCI advertising control | Data flow | Safety-relevant functions, Worst-case severity of harm, Software safety class (IEC 62304), Hazardous situation |

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
