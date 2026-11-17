# CGM lab — GlucoSense CGM-3000 (worked example)

STRIDE threat model report — generated 2026-11-16 23:50

- **System:** Continuous glucose monitoring appliance: a wearable BLE sensor, an MQTT telemetry backbone, an HL7 clinical interface, and a web + bedside-kiosk console, all on one Raspberry Pi with its USB ports, Bluetooth radio and touchscreen live at the bedside.
- **Author:** SecureMED teaching example (CGM-LAB-INT)
- **Date:** 2026-08-29
- **Intended use:** A continuous glucose monitor tracks a patient's interstitial glucose every few minutes and streams it to a display and to the clinical record. Patients and clinicians rely on it for two things: hypo/hyper ALARMS that warn of a dangerous low or high, and the glucose trend used to decide insulin dosing (including automated-delivery loops). A missed low-glucose alarm or a falsely reassuring reading can lead to severe, un-treated hypoglycaemia — seizure, coma or death. This lab is a deliberately vulnerable simulation (GlucoSense CGM-3000) that teaches students to find and fix the flaws that would let an attacker read, forge or suppress that safety-critical data.
- **Environment of use:** A hospital bedside or a patient's home. The appliance sits on whatever network it is given, with its USB ports, Bluetooth radio and touchscreen within reach of anyone at the bedside. In the lab it is on a shared classroom network that every student can reach.
- **Scope:** In scope: the appliance's web/kiosk console, HL7 listener, MQTT broker and telemetry, BLE advertiser, on-device config and user store, the host privilege model, and the Pi's physical interfaces — USB host ports, the on-board Bluetooth controller and the bedside touchscreen panel. Out of scope: the physical sensor hardware and adhesive, the upstream hospital EHR/LIS itself, the lab network fabric, and any real patient.
- **Assumptions:** Networks are assumed hostile: an adversary can alter, drop and replay traffic. The network and the radio environment are hostile: any student on the lab network, and anyone within Bluetooth range, is a potential adversary. Nobody watches the bedside continuously. Clinicians act on what the display shows and cannot tell a forged reading from a real one. The Raspberry Pi OS and its packages are as shipped in the lab image.
- **Safety risk management file:** CGM-3000 Risk Management File (ISO 14971) (RMF-CGM-3000 rev A)
- **Methodology:** STRIDE per element. Rationale: STRIDE per element. The lab's flaws are interface flaws (an unauthenticated broker, a cleartext console, an open HL7 listener) and a per-element sweep finds those systematically. The physical interfaces are drawn as elements so the same method covers them. Findings a student confirms by exploiting them are scored with CVSS v4.0.
- **Severity scale:** Built-in qualitative scale (2 of 385 threats scored with CVSS v4.0)
- **Risk acceptance:** Residual risk up to Medium is acceptable. Teaching criteria: residual Medium or below is acceptable; High and Critical have to be mitigated before the appliance could be considered for clinical use. Every threat to the alarm path is carried into the hazard analysis by its SEC-HAZ reference.

## 1. Summary

| Metric | Value |
| --- | --- |
| Elements analysed | 45 |
| Data flows | 24 |
| Trust boundaries | 4 |
| Assets | 4 |
| Threats identified | 385 |
| Threats affecting patient safety | 80 |
| Safety-relevant elements | 22 |
| Threats with a recorded decision and residual risk | 3 |
| Threats still open | 382 |

| Safety impact | What a compromise does to the patient | Threats |
| --- | --- | --- |
| Device control — Controls or actuates therapy / diagnosis | Unintended, altered or withheld therapy delivered to the patient. | 6 |
| Alarms — Generates, carries or displays alarms | A real alarm is missed or suppressed, or false alarms drive alarm fatigue and unnecessary intervention. | 36 |
| Clinical data — Produces clinical data used for decisions | A clinical decision is made on wrong, stale or missing data. | 34 |
| Care delivery — Needed for timely care delivery | Care is delayed or cannot be delivered. | 4 |

| Severity | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- |
| Threats | 95 | 185 | 78 | 27 | 0 |

| STRIDE | Property | Threats |
| --- | --- | --- |
| S — Spoofing | Authentication | 33 |
| T — Tampering | Integrity | 123 |
| R — Repudiation | Non-repudiation | 30 |
| I — Information disclosure | Confidentiality | 78 |
| D — Denial of service | Availability | 93 |
| E — Elevation of privilege | Authorisation | 28 |

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
| HL7 v2 query / result (MLLP) | Hospital LIS / EHR interface | HL7 MLLP listener (bi) | HL7 / DICOM / FHIR | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Login query | Web admin console (Flask) | User store (cgm.db, SQLite) (bi) | SQL / database protocol | None (cleartext) | no |
| Diagnostic export / config read | Web admin console (Flask) | Device config (cgm.conf) (bi) | Other | None (cleartext) | no |
| Console telemetry | Web admin console (Flask) | MQTT broker (mosquitto) (bi) | MQTT | None (cleartext) | no |
| Legitimate glucose publish | CGM sensor + BLE gateway | MQTT broker (mosquitto) | MQTT | None (cleartext) | no |
| Retained telemetry | MQTT broker (mosquitto) | Glucose telemetry (MQTT glucose/#, retained) (bi) | MQTT | None (cleartext) | no |
| Forged-reading injection | Unauthenticated network client | MQTT broker (mosquitto) (bi) | MQTT | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Bedside display feed | MQTT broker (mosquitto) | Bedside kiosk (Chromium / matchbox on DSI panel) | MQTT | None (cleartext) | no |
| BLE advertisement (RF) | BLE advertiser (runs as root) | Unauthenticated network client | Bluetooth / BLE | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Rogue HL7 query | Unauthenticated network client | HL7 MLLP listener (bi) | HL7 / DICOM / FHIR | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| SSH foothold | Unauthenticated network client | Host shell (biomed via SSH) (bi) | SFTP / SSH | TLS (server authenticated) | Untrusted lab network + BLE RF, Host OS / root (SSH) |
| Privilege escalation | Host shell (biomed via SSH) | Root filesystem / sudoers (/etc/sudoers.d, /root) (bi) | Other | None (cleartext) | no |
| USB port access | Visitor at the bedside | USB host ports (udev auto-mount) (bi) | Physical / manual transfer | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Bluetooth pairing / GATT access | Visitor at the bedside | Bluetooth stack (BlueZ / bluetoothd, root) (bi) | Bluetooth / BLE | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Unattended panel use | Visitor at the bedside | Touchscreen HMI (DSI panel + libinput) (bi) | Physical / manual transfer | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Touch input / rendered display | Touchscreen HMI (DSI panel + libinput) | Bedside kiosk (Chromium / matchbox on DSI panel) (bi) | Other | None (cleartext) | no |
| Bedside annunciation | Touchscreen HMI (DSI panel + libinput) | Clinician / caregiver | Physical / manual transfer | None (cleartext) | Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5) |
| Paired HID input | Bluetooth stack (BlueZ / bluetoothd, root) | Bedside kiosk (Chromium / matchbox on DSI panel) | Bluetooth / BLE | None (cleartext) | no |
| Removable-media config copy | USB host ports (udev auto-mount) | Device config (cgm.conf) (bi) | Physical / manual transfer | None (cleartext) | no |
| Auto-mount + udev rule execution | USB host ports (udev auto-mount) | Root filesystem / sudoers (/etc/sudoers.d, /root) | Physical / manual transfer | None (cleartext) | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH) |
| HCI advertising control | BLE advertiser (runs as root) | Bluetooth stack (BlueZ / bluetoothd, root) | Other | None (cleartext) | no |

## 3. STRIDE coverage matrix

| Element | Type | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Unauthenticated network client | Entity | 1 | · | 2 | · | · | · |
| Clinician / caregiver | Entity | 1 | · | 1 | · | · | · |
| Hospital LIS / EHR interface | Entity | 1 | · | 1 | · | · | · |
| Web admin console (Flask) | Process | 1 | 5 | 1 | 3 | 2 | 1 |
| HL7 MLLP listener | Process | 4 | 4 | 1 | 2 | 2 | 3 |
| MQTT broker (mosquitto) | Process | 1 | 7 | 3 | 3 | 4 | 3 |
| BLE advertiser (runs as root) | Process | 2 | 4 | 1 | 2 | 2 | 3 |
| Bedside kiosk (Chromium / matchbox on DSI panel) | Process | 6 | 6 | 2 | 2 | 4 | 4 |
| Host shell (biomed via SSH) | Process | 1 | 4 | 1 | 3 | 1 | 2 |
| User store (cgm.db, SQLite) | Data store | · | 2 | 2 | 3 | 2 | · |
| Device config (cgm.conf) | Data store | · | 2 | 2 | 3 | 2 | · |
| Glucose telemetry (MQTT glucose/#, retained) | Data store | · | 3 | 3 | 2 | 4 | · |
| Root filesystem / sudoers (/etc/sudoers.d, /root) | Data store | · | 2 | 1 | 3 | 2 | · |
| CGM sensor + BLE gateway | Entity | 1 | · | 1 | · | · | · |
| Patient glucose data / PHI | Asset | · | 1 | · | 1 | 1 | · |
| Hypo / hyper alarm path | Asset | · | o | · | 1 | 1 | · |
| Device & broker credentials | Asset | · | o | · | 2 | 1 | · |
| Visitor at the bedside | Entity | 1 | · | 2 | · | · | · |
| USB host ports (udev auto-mount) | Process | 4 | 5 | 2 | 2 | 3 | 5 |
| Bluetooth stack (BlueZ / bluetoothd, root) | Process | 5 | 6 | 2 | 3 | 3 | 5 |
| Touchscreen HMI (DSI panel + libinput) | Process | 4 | 6 | 2 | 2 | 4 | 2 |
| HTTP attack surface | Data flow | · | 3 | · | 2 | 2 | · |
| Console session | Data flow | · | 4 | · | 2 | 3 | · |
| Bedside interaction | Data flow | · | 5 | · | 2 | 4 | · |
| HL7 v2 query / result (MLLP) | Data flow | · | 3 | · | 2 | 3 | · |
| Login query | Data flow | · | 1 | · | 1 | 1 | · |
| Diagnostic export / config read | Data flow | · | 1 | · | 1 | 1 | · |
| Console telemetry | Data flow | · | 1 | · | 1 | 1 | · |
| Legitimate glucose publish | Data flow | · | 3 | · | 1 | 3 | · |
| Retained telemetry | Data flow | · | 1 | · | 1 | 1 | · |
| Forged-reading injection | Data flow | · | 6 | · | 2 | 5 | · |
| Bedside display feed | Data flow | · | 3 | · | 1 | 3 | · |
| BLE advertisement (RF) | Data flow | · | 4 | · | 2 | 3 | · |
| Rogue HL7 query | Data flow | · | 2 | · | 2 | 2 | · |
| SSH foothold | Data flow | · | 2 | · | 1 | 2 | · |
| Privilege escalation | Data flow | · | 2 | · | 1 | 1 | · |
| USB port access | Data flow | · | 3 | · | 3 | 2 | · |
| Bluetooth pairing / GATT access | Data flow | · | 4 | · | 2 | 2 | · |
| Unattended panel use | Data flow | · | 2 | · | 3 | 2 | · |
| Touch input / rendered display | Data flow | · | 3 | · | 1 | 3 | · |
| Bedside annunciation | Data flow | · | 4 | · | 3 | 4 | · |
| Paired HID input | Data flow | · | 4 | · | 1 | 3 | · |
| Removable-media config copy | Data flow | · | 1 | · | 2 | 1 | · |
| Auto-mount + udev rule execution | Data flow | · | 3 | · | 3 | 2 | · |
| HCI advertising control | Data flow | · | 1 | · | 1 | 1 | · |

## 4. Threats and recommended mitigations

### Web admin console (Flask) (Process)

_Login, /admin maintenance token, /admin/export diagnostic download, and /kiosk/unlock. TCP 8080. Surfaces 1-4 and 8._

#### T-09 · [T] Untrusted input reaches Web admin console (Flask) without strict validation — **CRITICAL**

_Tampering — violates Integrity_

**CVSS v4.0:** 9.2 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` — SQL injection in the login gives an unauthenticated admin session and, via the export traversal, read of on-device secrets. Network, no auth, no interaction. Scored in the CVSS v4.0 calculator as a teaching illustration.

Input crossing into Web admin console (Flask) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

**Risk treatment:** Mitigated by design — residual **LOW** — Control: Parameterised queries and allow-list validation on every console input — Rationale: The lab fix for the login and diagnostic injection flaws. — **no verification evidence referenced**

#### T-16 · [T] Updates to Web admin console (Flask) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Web admin console (Flask) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-19 · [T] Clinical data at Web admin console (Flask) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Web admin console (Flask), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-001 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** The console is where a clinician reads glucose trends and acknowledges alarms; a compromise that alters what it shows biases a dosing decision.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-002, RC-021

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-20 · [D] Clinical data from Web admin console (Flask) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Web admin console (Flask) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

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

_Authorization · Authorization_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-18 · [I] A secret held by Web admin console (Flask) is the same on every device — **HIGH**

_Information disclosure — violates Confidentiality_

The credential or key Web admin console (Flask) relies on is hardcoded, left at its default, or shared across the product line. Extracting it once - from one device, a firmware image or a manual - yields access to every device that carries it.

_Confidentiality · Cryptography · Lifecycle: Manufacturing, Deployment_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Provision a unique credential or key pair per device at manufacture; never derive keys from serial numbers or other discoverable identifiers.
- Remove hardcoded and default passwords; force a change at commissioning where a password has to exist.
- Use public-key schemes so that nothing extracted from one device authenticates as another.

#### T-15 · [E] Coarse authorisation in Web admin console (Flask) — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

_Authorization · Authorization_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-08 · [S] Clients cannot verify they are talking to the real Web admin console (Flask) — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Web admin console (Flask). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-10 · [T] Integrity of the code and configuration of Web admin console (Flask) — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Web admin console (Flask) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-17 · [T] Third-party software in Web admin console (Flask) is not traced to an SBOM — **HIGH**

_Tampering — violates Integrity_

Web admin console (Flask) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-11 · [R] Web admin console (Flask) keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Web admin console (Flask) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-14 · [D] Web admin console (Flask) has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Web admin console (Flask) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-13 · [I] Leakage through errors, responses and telemetry from Web admin console (Flask) — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Web admin console (Flask) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### MQTT broker (mosquitto) (Process)

_Telemetry backbone. glucose/# carries readings + alarm state; cgm/service/# holds a retained capture flag. TCP 1883. Surface 6._

#### T-49 · [T] Alarm conditions or thresholds at MQTT broker (mosquitto) can be tampered with — **HIGH**

_Tampering — violates Integrity_

**CVSS v4.0:** 8.7 (High) — `CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:H` — With a leaked broker credential, forging a retained 'in range' reading on glucose/# suppresses a genuine hypoglycaemia alarm (integrity + safety impact). Adjacent network, low privilege. Illustrative CVSS v4.0 score.

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through MQTT broker (mosquitto). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

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

**Risk treatment:** Mitigated by design — residual **MEDIUM** — Control: Broker ACLs and a TLS client certificate per sensor, so only the paired sensor can publish to glucose/# — Rationale: The lab fix. A forged reading now needs the sensor's private key rather than a shared password. — Evidence: Lab retest: forged publish to glucose/# rejected

#### T-47 · [D] Loss of MQTT broker (mosquitto) removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops MQTT broker (mosquitto) responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery_

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

#### T-50 · [D] Alarm delivery through MQTT broker (mosquitto) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts MQTT broker (mosquitto), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

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

#### T-53 · [D] Clinical data from MQTT broker (mosquitto) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes MQTT broker (mosquitto) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-013 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-41 · [T] Updates to MQTT broker (mosquitto) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to MQTT broker (mosquitto) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-45 · [T] Therapy parameters handled by MQTT broker (mosquitto) can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through MQTT broker (mosquitto) can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-005 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-52 · [T] Clinical data at MQTT broker (mosquitto) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through MQTT broker (mosquitto), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-012 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-46 · [E] Therapy control functions in MQTT broker (mosquitto) are reachable without a clinical authorisation decision — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A caller who is authenticated for some other purpose — a service account, a read-only integration, a patient-facing feature — can invoke the functions that change therapy, because authorisation does not separate clinical control from everything else.

_Authorization · Authorization_

> **Patient safety — SEC-HAZ-006 · Controls or actuates therapy / diagnosis**  
> **Harm:** Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Separate therapy-control operations behind their own authorisation, deny by default, and require a clinical role.
- Require step-up authentication or a second person for high-consequence changes.
- Log every therapy-control call with the authenticated identity and the resulting parameter change.

#### T-48 · [R] Therapy changes at MQTT broker (mosquitto) cannot be reconstructed afterwards — **CRITICAL**

_Repudiation — violates Non-repudiation_

There is no tamper-evident record tying each therapy change to an identity, a time and a patient. After an adverse event nobody can establish what the device was told to do, by whom, or whether the instruction was legitimate.

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-008 · Controls or actuates therapy / diagnosis**  
> **Harm:** A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Keep an append-only therapy audit trail: identity, timestamp, previous and new value, patient context and outcome.
- Retain it for the period your vigilance and post-market surveillance obligations require.
- Make sure the device keeps this record locally even when disconnected.

#### T-51 · [R] Alarm history at MQTT broker (mosquitto) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at MQTT broker (mosquitto).

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-011 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011, RC-012

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-34 · [T] Untrusted input reaches MQTT broker (mosquitto) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into MQTT broker (mosquitto) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-37 · [I] Weak authorisation over sensitive data in MQTT broker (mosquitto) — **HIGH**

_Information disclosure — violates Confidentiality_

MQTT broker (mosquitto) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-44 · [I] A secret held by MQTT broker (mosquitto) is the same on every device — **HIGH**

_Information disclosure — violates Confidentiality_

The credential or key MQTT broker (mosquitto) relies on is hardcoded, left at its default, or shared across the product line. Extracting it once - from one device, a firmware image or a manual - yields access to every device that carries it.

_Confidentiality · Cryptography · Lifecycle: Manufacturing, Deployment_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Provision a unique credential or key pair per device at manufacture; never derive keys from serial numbers or other discoverable identifiers.
- Remove hardcoded and default passwords; force a change at commissioning where a password has to exist.
- Use public-key schemes so that nothing extracted from one device authenticates as another.

#### T-40 · [E] Coarse authorisation in MQTT broker (mosquitto) — **HIGH**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

_Authorization · Authorization_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-43 · [E] MQTT broker (mosquitto) runs software that no longer receives security fixes — **HIGH**

_Elevation of privilege — violates Authorisation_

Vulnerabilities in the software behind MQTT broker (mosquitto) will keep being published and will never be patched upstream. Each one is a ready-made way into the device for anyone who reads the advisory.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain, Maintenance and update_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Plan the replacement or in-house maintenance of the component before its support ends, not after.
- Keep the design modular enough that a third-party component can be swapped.
- Until then, reduce what can reach it, and tell users what they need to know to manage the risk.

#### T-39 · [D] MQTT broker (mosquitto) has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads MQTT broker (mosquitto) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-33 · [S] Clients cannot verify they are talking to the real MQTT broker (mosquitto) — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as MQTT broker (mosquitto). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-35 · [T] Integrity of the code and configuration of MQTT broker (mosquitto) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that MQTT broker (mosquitto) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-42 · [T] Third-party software in MQTT broker (mosquitto) is not traced to an SBOM — **MEDIUM**

_Tampering — violates Integrity_

MQTT broker (mosquitto) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-36 · [R] MQTT broker (mosquitto) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through MQTT broker (mosquitto) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-38 · [I] Leakage through errors, responses and telemetry from MQTT broker (mosquitto) — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about MQTT broker (mosquitto) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Host shell (biomed via SSH) (Process)

_SSH foothold + local privilege escalation to root. Surface 9._

#### T-95 · [T] Updates to Host shell (biomed via SSH) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Host shell (biomed via SSH) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-88 · [T] Untrusted input reaches Host shell (biomed via SSH) without strict validation — **CRITICAL**

_Tampering — violates Integrity_

Input crossing into Host shell (biomed via SSH) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-91 · [I] Weak authorisation over sensitive data in Host shell (biomed via SSH) — **CRITICAL**

_Information disclosure — violates Confidentiality_

Host shell (biomed via SSH) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-97 · [I] A secret held by Host shell (biomed via SSH) is the same on every device — **CRITICAL**

_Information disclosure — violates Confidentiality_

The credential or key Host shell (biomed via SSH) relies on is hardcoded, left at its default, or shared across the product line. Extracting it once - from one device, a firmware image or a manual - yields access to every device that carries it.

_Confidentiality · Cryptography · Lifecycle: Manufacturing, Deployment · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Provision a unique credential or key pair per device at manufacture; never derive keys from serial numbers or other discoverable identifiers.
- Remove hardcoded and default passwords; force a change at commissioning where a password has to exist.
- Use public-key schemes so that nothing extracted from one device authenticates as another.

**Risk treatment:** Transferred to the user (disclosed in labeling) — residual **HIGH** (above the acceptance threshold) — Rationale: Operators are told to change the SSH password at commissioning. Nothing enforces it, so the risk stays with every site that does not.

#### T-94 · [E] Coarse authorisation in Host shell (biomed via SSH) — **CRITICAL**

_Elevation of privilege — violates Authorisation_

A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.

_Authorization · Authorization · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.
- Deny by default so a new route is unreachable until it is explicitly authorised.
- Test horizontal (another user's object) and vertical (an admin function) escalation explicitly.

#### T-373 · [E] Service access over "SSH foothold" into Host shell (biomed via SSH) lacks strong authentication — **CRITICAL**

_Elevation of privilege — violates Authorisation_

"SSH foothold" exists for maintenance and carries the privilege that goes with it, yet nothing stronger than a shared or single-factor credential stands in front of it. Service credentials are passed between people, written down and rarely changed.

_Authorization · Authentication · Lifecycle: Maintenance and update · Multi-patient_

Via data flow: SSH foothold

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Require multi-factor or certificate-based authentication for service and maintenance access.
- Issue service credentials per person and per device, time-limited, and revoke them when no longer needed.
- Log every service session and make an open one visible at the device.

#### T-87 · [S] Clients cannot verify they are talking to the real Host shell (biomed via SSH) — **HIGH**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Host shell (biomed via SSH). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-89 · [T] Integrity of the code and configuration of Host shell (biomed via SSH) — **HIGH**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Host shell (biomed via SSH) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-96 · [T] Third-party software in Host shell (biomed via SSH) is not traced to an SBOM — **HIGH**

_Tampering — violates Integrity_

Host shell (biomed via SSH) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-90 · [R] Host shell (biomed via SSH) keeps no security audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Actions taken by or through Host shell (biomed via SSH) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-93 · [D] Host shell (biomed via SSH) has no protection against resource exhaustion — **HIGH**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Host shell (biomed via SSH) has, taking it down for everyone.

_Availability · Resiliency and recovery · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-92 · [I] Leakage through errors, responses and telemetry from Host shell (biomed via SSH) — **MEDIUM**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Host shell (biomed via SSH) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment · Multi-patient_

**Controls already in place:** biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### SSH foothold (Data flow)

_Password-auth SSH; biomed's password is dictionary-crackable._

#### T-298 · [T] Code delivered over "SSH foothold" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update · Multi-patient_

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-294 · [T] No end-to-end integrity on "SSH foothold" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation · Multi-patient_

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-295 · [I] Sensitive data leaves a trust boundary on "SSH foothold" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "Host OS / root (SSH)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation · Multi-patient_

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-296 · [D] "SSH foothold" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-297 · [D] Availability of "SSH foothold" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery · Multi-patient_

Crosses: Untrusted lab network + BLE RF, Host OS / root (SSH)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Forged-reading injection (Data flow)

_With the leaked cred: WRITE glucose/# (forge 'IN_RANGE') and READ cgm/service/# (flag). READ glucose/# denied._

#### T-267 · [D] Loss of Forged-reading injection removes control of therapy — **CRITICAL**

_Denial of service — violates Availability_

Flooding, resource exhaustion or an unavailable dependency stops Forged-reading injection responding. Therapy cannot be started, adjusted or — the case people forget — stopped, and the clinician may not be told that control has been lost.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-059 · Controls or actuates therapy / diagnosis**  
> **Harm:** Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define and implement the safe state the device falls back to when its controller is unreachable, and test it.
- Keep therapy control functional and locally overridable when the network, server or cloud is unavailable.
- Rate limit and prioritise control traffic ahead of telemetry, logging and updates.
- Alarm on loss of control communication rather than failing silently.

#### T-269 · [D] Alarm delivery through Forged-reading injection can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Forged-reading injection, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-061 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-271 · [D] Clinical data from Forged-reading injection may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Forged-reading injection unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-063 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-266 · [T] Therapy parameters handled by Forged-reading injection can be altered without detection — **CRITICAL**

_Tampering — violates Integrity_

Dose, rate, duration, energy or programme values passing through Forged-reading injection can be modified — in transit, at rest, or by malformed input the code accepts — and neither the device nor the clinician can tell the value is not the one that was prescribed.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-058 · Controls or actuates therapy / diagnosis**  
> **Harm:** The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign or MAC therapy parameters end to end, and verify at the point of actuation rather than at the gateway.
- Range-check every parameter against clinically safe limits at the device, independently of whatever sent it.
- Cross-check the value actually being delivered against the value that was prescribed, and alarm on divergence.

#### T-268 · [T] Alarm conditions or thresholds at Forged-reading injection can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Forged-reading injection. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-060 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-270 · [T] Clinical data at Forged-reading injection can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Forged-reading injection, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-062 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001, RC-011, RC-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-259 · [T] Traffic on "Forged-reading injection" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-265 · [T] Commands on "Forged-reading injection" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-261 · [I] Data on "Forged-reading injection" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-263 · [D] "Forged-reading injection" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-260 · [T] No end-to-end integrity on "Forged-reading injection" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-262 · [I] Sensitive data leaves a trust boundary on "Forged-reading injection" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-264 · [D] Availability of "Forged-reading injection" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside annunciation (Data flow)

_What the clinician actually sees and hears at the bedside: current glucose, trend, and the hypo / hyper alarm._

#### T-341 · [D] Alarm delivery through Bedside annunciation can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside annunciation, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-075 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-343 · [D] Clinical data from Bedside annunciation may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside annunciation unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-077 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-340 · [T] Alarm conditions or thresholds at Bedside annunciation can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside annunciation. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-074 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-342 · [T] Clinical data at Bedside annunciation can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside annunciation, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-076 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-333 · [T] Traffic on "Bedside annunciation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-335 · [I] Data on "Bedside annunciation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-338 · [D] "Bedside annunciation" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-334 · [T] No end-to-end integrity on "Bedside annunciation" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-336 · [I] Sensitive data leaves a trust boundary on "Bedside annunciation" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-337 · [I] Sensitive data moved by file share or physical transfer — **HIGH**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

_Confidentiality · Confidentiality_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-339 · [D] Availability of "Bedside annunciation" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Glucose telemetry (MQTT glucose/#, retained) (Data store)

_Per-patient readings and alarm state. A forged retained message persists to later subscribers._

#### T-124 · [D] Clinical data from Glucose telemetry (MQTT glucose/#, retained) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Glucose telemetry (MQTT glucose/#, retained) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-024 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-126 · [D] Alarm delivery through Glucose telemetry (MQTT glucose/#, retained) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Glucose telemetry (MQTT glucose/#, retained), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-026 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-123 · [T] Clinical data at Glucose telemetry (MQTT glucose/#, retained) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Glucose telemetry (MQTT glucose/#, retained), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-023 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-125 · [T] Alarm conditions or thresholds at Glucose telemetry (MQTT glucose/#, retained) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Glucose telemetry (MQTT glucose/#, retained). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-025 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-127 · [R] Alarm history at Glucose telemetry (MQTT glucose/#, retained) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Glucose telemetry (MQTT glucose/#, retained).

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-027 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-001, RC-011

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-120 · [D] Loss of Glucose telemetry (MQTT glucose/#, retained) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Glucose telemetry (MQTT glucose/#, retained) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-118 · [R] Regulated records in Glucose telemetry (MQTT glucose/#, retained) without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Glucose telemetry (MQTT glucose/#, retained) holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-119 · [I] Sensitive data stored unencrypted in Glucose telemetry (MQTT glucose/#, retained) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Glucose telemetry (MQTT glucose/#, retained) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-116 · [T] Modification of Glucose telemetry (MQTT glucose/#, retained) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Glucose telemetry (MQTT glucose/#, retained) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-117 · [R] No access log for Glucose telemetry (MQTT glucose/#, retained) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Glucose telemetry (MQTT glucose/#, retained) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-121 · [D] Resource exhaustion against Glucose telemetry (MQTT glucose/#, retained) — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Glucose telemetry (MQTT glucose/#, retained) unavailable without any need to break into it.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

#### T-122 · [I] Sensitive data in Glucose telemetry (MQTT glucose/#, retained) outlives the device's time in service — **LOW**

_Information disclosure — violates Confidentiality_

When the device is returned, repaired, resold or thrown away, Glucose telemetry (MQTT glucose/#, retained) still holds patient data and credentials. Whoever handles it next has the device in their hands and all the time they need.

_Confidentiality · Confidentiality · Lifecycle: Decommission_

**Recommended mitigations:**
- Provide a sanitisation function that erases data and credentials, and say how to use it in the labeling.
- Encrypt with a key that can be destroyed, so erasure does not depend on overwriting every block.
- Revoke the device's identity and credentials on the server side when it leaves service.

### Legitimate glucose publish (Data flow)

_Real readings + alarm state onto glucose/<patient>._

#### T-253 · [D] Clinical data from Legitimate glucose publish may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Legitimate glucose publish unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-055 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-255 · [D] Alarm delivery through Legitimate glucose publish can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Legitimate glucose publish, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-057 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-252 · [T] Clinical data at Legitimate glucose publish can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Legitimate glucose publish, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-054 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-254 · [T] Alarm conditions or thresholds at Legitimate glucose publish can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Legitimate glucose publish. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-056 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: not set · Safety file: SEC-HAZ-001

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-249 · [T] Traffic on "Legitimate glucose publish" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-250 · [I] Data on "Legitimate glucose publish" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-251 · [D] Availability of "Legitimate glucose publish" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### USB host ports (udev auto-mount) (Process)

_The Pi's four USB-A ports, live and unblanked at the bedside. udev auto-mounts any removable volume and the kernel binds any device that enumerates as a keyboard. Physical surface — not one of the numbered lab surfaces._

#### T-164 · [S] Alarms carried by USB host ports (udev auto-mount) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach USB host ports (udev auto-mount) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication_

> **Patient safety — SEC-HAZ-030 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-160 · [T] Updates to USB host ports (udev auto-mount) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to USB host ports (udev auto-mount) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-162 · [T] Alarm conditions or thresholds at USB host ports (udev auto-mount) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through USB host ports (udev auto-mount). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

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

#### T-163 · [D] Alarm delivery through USB host ports (udev auto-mount) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts USB host ports (udev auto-mount), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

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

#### T-159 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, USB host ports (udev auto-mount) executes it, and it executes as a privileged account.

_Authorization · Code, data and execution integrity_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-165 · [R] Alarm history at USB host ports (udev auto-mount) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at USB host ports (udev auto-mount).

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-031 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-166 · [D] Loss of USB host ports (udev auto-mount) delays or prevents care — **CRITICAL**

_Denial of service — violates Availability_

USB host ports (udev auto-mount) is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-032 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-010

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-149 · [S] USB host ports (udev auto-mount) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach USB host ports (udev auto-mount) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-374 · [S] Unauthenticated inbound flow "USB port access" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "USB port access" from Visitor at the bedside carry no proof of who sent them. USB host ports (udev auto-mount) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: USB port access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-151 · [T] Untrusted input reaches USB host ports (udev auto-mount) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into USB host ports (udev auto-mount) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-154 · [I] Weak authorisation over sensitive data in USB host ports (udev auto-mount) — **HIGH**

_Information disclosure — violates Confidentiality_

USB host ports (udev auto-mount) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-157 · [E] USB host ports (udev auto-mount) runs with administrative privilege — **HIGH**

_Elevation of privilege — violates Authorisation_

Any code-execution or file-write bug in USB host ports (udev auto-mount) immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.

_Authorization · Authorization_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Run as a dedicated unprivileged account with only the permissions the workload needs.
- Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.
- Separate administrative functions into their own component with its own identity.

#### T-158 · [E] No effective authorisation model in USB host ports (udev auto-mount) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-375 · [E] Privilege crosses a trust boundary into USB host ports (udev auto-mount) — **HIGH**

_Elevation of privilege — violates Authorisation_

"USB port access" enters USB host ports (udev auto-mount) across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)" without an authorisation decision of its own. Whatever the caller can request, USB host ports (udev auto-mount) will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: USB port access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-376 · [E] Debug or dormant interface "USB port access" reaches USB host ports (udev auto-mount) — **HIGH**

_Elevation of privilege — violates Authorisation_

"USB port access" is not part of the intended use, but it is still there. Development and unused interfaces are rarely held to the access control of the clinical ones, and through this one Visitor at the bedside reaches USB host ports (udev auto-mount) directly.

_Authorization · Authorization · Lifecycle: Manufacturing, Deployment_

Via data flow: USB port access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Remove or disable debug, test and unused interfaces before the product ships, and verify on a production unit that they are gone.
- Where an interface has to remain, require the same authentication and authorisation as any other entry point.
- Show that dormant functionality cannot be activated, and seal ports that should never be opened.

#### T-150 · [S] Clients cannot verify they are talking to the real USB host ports (udev auto-mount) — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as USB host ports (udev auto-mount). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-152 · [T] Integrity of the code and configuration of USB host ports (udev auto-mount) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that USB host ports (udev auto-mount) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-161 · [T] Third-party software in USB host ports (udev auto-mount) is not traced to an SBOM — **MEDIUM**

_Tampering — violates Integrity_

USB host ports (udev auto-mount) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-153 · [R] USB host ports (udev auto-mount) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through USB host ports (udev auto-mount) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-156 · [D] USB host ports (udev auto-mount) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads USB host ports (udev auto-mount) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-155 · [I] Leakage through errors, responses and telemetry from USB host ports (udev auto-mount) — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about USB host ports (udev auto-mount) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Bluetooth stack (BlueZ / bluetoothd, root) (Process)

_The Pi's on-board controller and the BlueZ daemon: discoverable and pairable in the lab image, and the same radio the BLE advertiser broadcasts on. Physical / RF surface — not one of the numbered lab surfaces._

#### T-185 · [S] Alarms carried by Bluetooth stack (BlueZ / bluetoothd, root) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Bluetooth stack (BlueZ / bluetoothd, root) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication_

> **Patient safety — SEC-HAZ-037 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-178 · [T] Updates to Bluetooth stack (BlueZ / bluetoothd, root) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Bluetooth stack (BlueZ / bluetoothd, root) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-181 · [T] Clinical data at Bluetooth stack (BlueZ / bluetoothd, root) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bluetooth stack (BlueZ / bluetoothd, root), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-033 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-183 · [T] Alarm conditions or thresholds at Bluetooth stack (BlueZ / bluetoothd, root) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bluetooth stack (BlueZ / bluetoothd, root). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

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

#### T-182 · [D] Clinical data from Bluetooth stack (BlueZ / bluetoothd, root) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bluetooth stack (BlueZ / bluetoothd, root) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-034 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-184 · [D] Alarm delivery through Bluetooth stack (BlueZ / bluetoothd, root) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bluetooth stack (BlueZ / bluetoothd, root), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

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

#### T-177 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, Bluetooth stack (BlueZ / bluetoothd, root) executes it, and it executes as a privileged account.

_Authorization · Code, data and execution integrity_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-186 · [R] Alarm history at Bluetooth stack (BlueZ / bluetoothd, root) is not reliable evidence — **CRITICAL**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Bluetooth stack (BlueZ / bluetoothd, root).

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-038 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.  
> Severity of harm: Critical — permanent impairment or life-threatening injury · Software safety class: Class C — death or serious injury possible · Safety file: SEC-HAZ-011

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-167 · [S] Bluetooth stack (BlueZ / bluetoothd, root) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Bluetooth stack (BlueZ / bluetoothd, root) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-377 · [S] Unauthenticated inbound flow "Bluetooth pairing / GATT access" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Bluetooth pairing / GATT access" from Visitor at the bedside carry no proof of who sent them. Bluetooth stack (BlueZ / bluetoothd, root) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Bluetooth pairing / GATT access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-385 · [S] Unauthenticated inbound flow "HCI advertising control" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "HCI advertising control" from BLE advertiser (runs as root) carry no proof of who sent them. Bluetooth stack (BlueZ / bluetoothd, root) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: HCI advertising control

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-169 · [T] Untrusted input reaches Bluetooth stack (BlueZ / bluetoothd, root) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Bluetooth stack (BlueZ / bluetoothd, root) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-172 · [I] Weak authorisation over sensitive data in Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Information disclosure — violates Confidentiality_

Bluetooth stack (BlueZ / bluetoothd, root) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-175 · [E] Bluetooth stack (BlueZ / bluetoothd, root) runs with administrative privilege — **HIGH**

_Elevation of privilege — violates Authorisation_

Any code-execution or file-write bug in Bluetooth stack (BlueZ / bluetoothd, root) immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.

_Authorization · Authorization_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Run as a dedicated unprivileged account with only the permissions the workload needs.
- Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.
- Separate administrative functions into their own component with its own identity.

#### T-176 · [E] No effective authorisation model in Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-378 · [E] Privilege crosses a trust boundary into Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Bluetooth pairing / GATT access" enters Bluetooth stack (BlueZ / bluetoothd, root) across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)" without an authorisation decision of its own. Whatever the caller can request, Bluetooth stack (BlueZ / bluetoothd, root) will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: Bluetooth pairing / GATT access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-379 · [E] Debug or dormant interface "Bluetooth pairing / GATT access" reaches Bluetooth stack (BlueZ / bluetoothd, root) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Bluetooth pairing / GATT access" is not part of the intended use, but it is still there. Development and unused interfaces are rarely held to the access control of the clinical ones, and through this one Visitor at the bedside reaches Bluetooth stack (BlueZ / bluetoothd, root) directly.

_Authorization · Authorization · Lifecycle: Manufacturing, Deployment_

Via data flow: Bluetooth pairing / GATT access

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Remove or disable debug, test and unused interfaces before the product ships, and verify on a production unit that they are gone.
- Where an interface has to remain, require the same authentication and authorisation as any other entry point.
- Show that dormant functionality cannot be activated, and seal ports that should never be opened.

#### T-168 · [S] Clients cannot verify they are talking to the real Bluetooth stack (BlueZ / bluetoothd, root) — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Bluetooth stack (BlueZ / bluetoothd, root). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-170 · [T] Integrity of the code and configuration of Bluetooth stack (BlueZ / bluetoothd, root) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Bluetooth stack (BlueZ / bluetoothd, root) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-179 · [T] Third-party software in Bluetooth stack (BlueZ / bluetoothd, root) is not traced to an SBOM — **MEDIUM**

_Tampering — violates Integrity_

Bluetooth stack (BlueZ / bluetoothd, root) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-171 · [R] Bluetooth stack (BlueZ / bluetoothd, root) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Bluetooth stack (BlueZ / bluetoothd, root) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-174 · [D] Bluetooth stack (BlueZ / bluetoothd, root) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Bluetooth stack (BlueZ / bluetoothd, root) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-173 · [I] Leakage through errors, responses and telemetry from Bluetooth stack (BlueZ / bluetoothd, root) — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Bluetooth stack (BlueZ / bluetoothd, root) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

#### T-180 · [I] Keys held by Bluetooth stack (BlueZ / bluetoothd, root) can be read out of storage — **LOW**

_Information disclosure — violates Confidentiality_

The keys are unique to the device but live in ordinary storage. Anyone with the device in their hands, a filesystem image or code execution in Bluetooth stack (BlueZ / bluetoothd, root) can copy them and impersonate this device from elsewhere.

_Confidentiality · Cryptography · Lifecycle: Manufacturing_

**Controls already in place:** Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.

**Recommended mitigations:**
- Hold keys in a secure element, TPM or hardware-backed keystore so they can be used but not exported.
- Limit what a single device key can do, and be able to revoke it.

### HL7 MLLP listener (Process)

_Answers a well-formed QRY^Q01 for a known MRN with an ORU^R01 (PHI). Serial in MSH-3; flag in NTE. TCP 2575. Surface 5._

#### T-30 · [T] Updates to HL7 MLLP listener are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to HL7 MLLP listener as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-31 · [T] Clinical data at HL7 MLLP listener can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through HL7 MLLP listener, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-003 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** Discloses per-patient glucose results and the device serial to any HL7 speaker; wrong or leaked results can misinform a downstream clinical decision.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-005

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-32 · [D] Clinical data from HL7 MLLP listener may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes HL7 MLLP listener unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-004 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** Discloses per-patient glucose results and the device serial to any HL7 speaker; wrong or leaked results can misinform a downstream clinical decision.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-005

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-369 · [S] Unauthenticated inbound flow "HL7 v2 query / result (MLLP)" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "HL7 v2 query / result (MLLP)" from Hospital LIS / EHR interface carry no proof of who sent them. HL7 MLLP listener therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: HL7 v2 query / result (MLLP)

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-371 · [S] Unauthenticated inbound flow "Rogue HL7 query" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Rogue HL7 query" from Unauthenticated network client carry no proof of who sent them. HL7 MLLP listener therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Rogue HL7 query

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-370 · [E] Privilege crosses a trust boundary into HL7 MLLP listener — **HIGH**

_Elevation of privilege — violates Authorisation_

"HL7 v2 query / result (MLLP)" enters HL7 MLLP listener across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" without an authorisation decision of its own. Whatever the caller can request, HL7 MLLP listener will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: HL7 v2 query / result (MLLP)

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-372 · [E] Privilege crosses a trust boundary into HL7 MLLP listener — **HIGH**

_Elevation of privilege — violates Authorisation_

"Rogue HL7 query" enters HL7 MLLP listener across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" without an authorisation decision of its own. Whatever the caller can request, HL7 MLLP listener will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: Rogue HL7 query

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-21 · [S] HL7 MLLP listener accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach HL7 MLLP listener is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-23 · [T] Untrusted input reaches HL7 MLLP listener without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into HL7 MLLP listener is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-26 · [I] Weak authorisation over sensitive data in HL7 MLLP listener — **HIGH**

_Information disclosure — violates Confidentiality_

HL7 MLLP listener handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-29 · [E] No effective authorisation model in HL7 MLLP listener — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-22 · [S] Clients cannot verify they are talking to the real HL7 MLLP listener — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as HL7 MLLP listener. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-24 · [T] Integrity of the code and configuration of HL7 MLLP listener — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that HL7 MLLP listener runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-25 · [R] HL7 MLLP listener keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through HL7 MLLP listener cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-28 · [D] HL7 MLLP listener has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads HL7 MLLP listener has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-27 · [I] Leakage through errors, responses and telemetry from HL7 MLLP listener — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about HL7 MLLP listener - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### BLE advertiser (runs as root) (Process)

_Non-connectable LE broadcast, company id 0xFFFF, carrying XOR-obfuscated manufacturer data. Surface 7._

#### T-65 · [T] Updates to BLE advertiser (runs as root) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to BLE advertiser (runs as root) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-64 · [E] Injection into a privileged process — **CRITICAL**

_Elevation of privilege — violates Authorisation_

Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, BLE advertiser (runs as root) executes it, and it executes as a privileged account.

_Authorization · Code, data and execution integrity_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.
- Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.
- Add detection for anomalous child processes and outbound connections from this component.

#### T-66 · [T] Clinical data at BLE advertiser (runs as root) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through BLE advertiser (runs as root), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-014 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** Broadcasts patient-linked data over the air. Confidentiality only here, but the process runs as root, so its compromise is a host compromise (CWE-250).  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-007

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-67 · [D] Clinical data from BLE advertiser (runs as root) may be unavailable when a decision has to be made — **HIGH**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes BLE advertiser (runs as root) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-015 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** Broadcasts patient-linked data over the air. Confidentiality only here, but the process runs as root, so its compromise is a host compromise (CWE-250).  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-007

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-54 · [S] BLE advertiser (runs as root) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach BLE advertiser (runs as root) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-56 · [T] Untrusted input reaches BLE advertiser (runs as root) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into BLE advertiser (runs as root) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-59 · [I] Weak authorisation over sensitive data in BLE advertiser (runs as root) — **HIGH**

_Information disclosure — violates Confidentiality_

BLE advertiser (runs as root) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-62 · [E] BLE advertiser (runs as root) runs with administrative privilege — **HIGH**

_Elevation of privilege — violates Authorisation_

Any code-execution or file-write bug in BLE advertiser (runs as root) immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.

_Authorization · Authorization_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Run as a dedicated unprivileged account with only the permissions the workload needs.
- Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.
- Separate administrative functions into their own component with its own identity.

#### T-63 · [E] No effective authorisation model in BLE advertiser (runs as root) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-55 · [S] Clients cannot verify they are talking to the real BLE advertiser (runs as root) — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as BLE advertiser (runs as root). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-57 · [T] Integrity of the code and configuration of BLE advertiser (runs as root) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that BLE advertiser (runs as root) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-58 · [R] BLE advertiser (runs as root) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through BLE advertiser (runs as root) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-61 · [D] BLE advertiser (runs as root) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads BLE advertiser (runs as root) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-60 · [I] Leakage through errors, responses and telemetry from BLE advertiser (runs as root) — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about BLE advertiser (runs as root) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Bedside kiosk (Chromium / matchbox on DSI panel) (Process)

_Full-screen bedside display of glucose + alarms; unlock via POST /kiosk/unlock. Owns tty1. Surface 8._

#### T-77 · [T] Updates to Bedside kiosk (Chromium / matchbox on DSI panel) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Bedside kiosk (Chromium / matchbox on DSI panel) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-82 · [S] Alarms carried by Bedside kiosk (Chromium / matchbox on DSI panel) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Bedside kiosk (Chromium / matchbox on DSI panel) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication_

> **Patient safety — SEC-HAZ-018 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-80 · [T] Alarm conditions or thresholds at Bedside kiosk (Chromium / matchbox on DSI panel) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside kiosk (Chromium / matchbox on DSI panel). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

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

#### T-84 · [T] Clinical data at Bedside kiosk (Chromium / matchbox on DSI panel) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside kiosk (Chromium / matchbox on DSI panel), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-020 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-81 · [D] Alarm delivery through Bedside kiosk (Chromium / matchbox on DSI panel) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside kiosk (Chromium / matchbox on DSI panel), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

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

#### T-85 · [D] Clinical data from Bedside kiosk (Chromium / matchbox on DSI panel) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside kiosk (Chromium / matchbox on DSI panel) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-021 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-367 · [S] Unauthenticated inbound flow "Bedside interaction" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Bedside interaction" from Clinician / caregiver carry no proof of who sent them. Bedside kiosk (Chromium / matchbox on DSI panel) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Bedside interaction

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-83 · [R] Alarm history at Bedside kiosk (Chromium / matchbox on DSI panel) is not reliable evidence — **HIGH**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Bedside kiosk (Chromium / matchbox on DSI panel).

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-019 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-86 · [D] Loss of Bedside kiosk (Chromium / matchbox on DSI panel) delays or prevents care — **HIGH**

_Denial of service — violates Availability_

Bedside kiosk (Chromium / matchbox on DSI panel) is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-022 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-008

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-368 · [E] Privilege crosses a trust boundary into Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Bedside interaction" enters Bedside kiosk (Chromium / matchbox on DSI panel) across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" without an authorisation decision of its own. Whatever the caller can request, Bedside kiosk (Chromium / matchbox on DSI panel) will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: Bedside interaction

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-68 · [S] Bedside kiosk (Chromium / matchbox on DSI panel) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Bedside kiosk (Chromium / matchbox on DSI panel) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-382 · [S] Unauthenticated inbound flow "Touch input / rendered display" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Touch input / rendered display" from Touchscreen HMI (DSI panel + libinput) carry no proof of who sent them. Bedside kiosk (Chromium / matchbox on DSI panel) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Touch input / rendered display

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-383 · [S] Unauthenticated inbound flow "Paired HID input" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Paired HID input" from Bluetooth stack (BlueZ / bluetoothd, root) carry no proof of who sent them. Bedside kiosk (Chromium / matchbox on DSI panel) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Paired HID input

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-70 · [T] Untrusted input reaches Bedside kiosk (Chromium / matchbox on DSI panel) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Bedside kiosk (Chromium / matchbox on DSI panel) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-73 · [I] Weak authorisation over sensitive data in Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Information disclosure — violates Confidentiality_

Bedside kiosk (Chromium / matchbox on DSI panel) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-76 · [E] No effective authorisation model in Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-79 · [E] Bedside kiosk (Chromium / matchbox on DSI panel) runs software that no longer receives security fixes — **HIGH**

_Elevation of privilege — violates Authorisation_

Vulnerabilities in the software behind Bedside kiosk (Chromium / matchbox on DSI panel) will keep being published and will never be patched upstream. Each one is a ready-made way into the device for anyone who reads the advisory.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain, Maintenance and update_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Plan the replacement or in-house maintenance of the component before its support ends, not after.
- Keep the design modular enough that a third-party component can be swapped.
- Until then, reduce what can reach it, and tell users what they need to know to manage the risk.

#### T-384 · [E] Debug or dormant interface "Paired HID input" reaches Bedside kiosk (Chromium / matchbox on DSI panel) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Paired HID input" is not part of the intended use, but it is still there. Development and unused interfaces are rarely held to the access control of the clinical ones, and through this one Bluetooth stack (BlueZ / bluetoothd, root) reaches Bedside kiosk (Chromium / matchbox on DSI panel) directly.

_Authorization · Authorization · Lifecycle: Manufacturing, Deployment_

Via data flow: Paired HID input

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Remove or disable debug, test and unused interfaces before the product ships, and verify on a production unit that they are gone.
- Where an interface has to remain, require the same authentication and authorisation as any other entry point.
- Show that dormant functionality cannot be activated, and seal ports that should never be opened.

#### T-69 · [S] Clients cannot verify they are talking to the real Bedside kiosk (Chromium / matchbox on DSI panel) — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Bedside kiosk (Chromium / matchbox on DSI panel). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-71 · [T] Integrity of the code and configuration of Bedside kiosk (Chromium / matchbox on DSI panel) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Bedside kiosk (Chromium / matchbox on DSI panel) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-78 · [T] Third-party software in Bedside kiosk (Chromium / matchbox on DSI panel) is not traced to an SBOM — **MEDIUM**

_Tampering — violates Integrity_

Bedside kiosk (Chromium / matchbox on DSI panel) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-72 · [R] Bedside kiosk (Chromium / matchbox on DSI panel) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Bedside kiosk (Chromium / matchbox on DSI panel) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-75 · [D] Bedside kiosk (Chromium / matchbox on DSI panel) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Bedside kiosk (Chromium / matchbox on DSI panel) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-74 · [I] Leakage through errors, responses and telemetry from Bedside kiosk (Chromium / matchbox on DSI panel) — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Bedside kiosk (Chromium / matchbox on DSI panel) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Touchscreen HMI (DSI panel + libinput) (Process)

_The 7-inch bedside touch panel: the only thing the clinician actually looks at, and the input device for the kiosk session on tty1. Physical surface — not one of the numbered lab surfaces._

#### T-196 · [T] Updates to Touchscreen HMI (DSI panel + libinput) are installed without cryptographic authentication — **CRITICAL**

_Tampering — violates Integrity_

Whatever is presented to Touchscreen HMI (DSI panel + libinput) as an update is installed. Anyone who can reach the update path - a USB port, a service tool, a file share, a spoofed server - can replace the software, and every control implemented in that software goes with it.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Accept only updates whose signature verifies against a key anchored in the device; refuse to install when the signature is absent or fails.
- Sign the version number and metadata along with the image, so an old vulnerable release cannot be presented as new.
- Require an authenticated, authorised user or server before an update is offered at all.

#### T-200 · [S] Alarms carried by Touchscreen HMI (DSI panel + libinput) cannot be shown to be genuine — **CRITICAL**

_Spoofing — violates Authentication_

Anything that can reach Touchscreen HMI (DSI panel + libinput) can announce an alarm, or announce that an alarm has cleared, while claiming to be a device. Receivers have no way to tell a real alarm from a forged one.

_Authenticity, which includes integrity · Authentication_

> **Patient safety — SEC-HAZ-041 · Generates, carries or displays alarms**  
> **Harm:** False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Authenticate the alarm source; prefer per-device identity (certificates) over a shared credential.
- Include device identity, patient context and a timestamp inside the signed alarm payload.
- Reconcile remote alarm state against the device periodically instead of trusting the last message received.

#### T-198 · [T] Alarm conditions or thresholds at Touchscreen HMI (DSI panel + libinput) can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Touchscreen HMI (DSI panel + libinput). An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

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

#### T-202 · [T] Clinical data at Touchscreen HMI (DSI panel + libinput) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Touchscreen HMI (DSI panel + libinput), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-043 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-199 · [D] Alarm delivery through Touchscreen HMI (DSI panel + libinput) can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Touchscreen HMI (DSI panel + libinput), so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

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

#### T-203 · [D] Clinical data from Touchscreen HMI (DSI panel + libinput) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Touchscreen HMI (DSI panel + libinput) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-044 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-201 · [R] Alarm history at Touchscreen HMI (DSI panel + libinput) is not reliable evidence — **HIGH**

_Repudiation — violates Non-repudiation_

Whether an alarm fired, when it was annunciated, who acknowledged it and when it cleared is not recorded tamper-evidently at Touchscreen HMI (DSI panel + libinput).

_Authenticity, which includes integrity · Event detection and logging_

> **Patient safety — SEC-HAZ-042 · Generates, carries or displays alarms**  
> **Harm:** After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Log every alarm raise, annunciate, acknowledge, silence and clear event with identity and timestamp.
- Store alarm history where the clinical or service user cannot edit it, and synchronise clocks.
- Review silenced and repeatedly-acknowledged alarms as a safety signal.

#### T-204 · [D] Loss of Touchscreen HMI (DSI panel + libinput) delays or prevents care — **HIGH**

_Denial of service — violates Availability_

Touchscreen HMI (DSI panel + libinput) is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-045 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> **Hazardous situation (as modelled):** This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-187 · [S] Touchscreen HMI (DSI panel + libinput) accepts unauthenticated callers — **HIGH**

_Spoofing — violates Authentication_

Any party that can reach Touchscreen HMI (DSI panel + libinput) is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Authenticate every caller, including internal service-to-service calls.
- Use mutual TLS or signed service tokens between internal components.
- Do not rely on network position alone as proof of identity.

#### T-380 · [S] Unauthenticated inbound flow "Unattended panel use" — **HIGH**

_Spoofing — violates Authentication_

Requests arriving over "Unattended panel use" from Visitor at the bedside carry no proof of who sent them. Touchscreen HMI (DSI panel + libinput) therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Via data flow: Unattended panel use

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Authenticate the flow itself: mutual TLS, a signed service token or a request signature.
- Reject requests whose identity cannot be verified rather than defaulting to a shared identity.
- Do not treat "it came from inside the network" as authentication.

#### T-189 · [T] Untrusted input reaches Touchscreen HMI (DSI panel + libinput) without strict validation — **HIGH**

_Tampering — violates Integrity_

Input crossing into Touchscreen HMI (DSI panel + libinput) is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Validate against an allow-list of type, length, format and range at the trust boundary.
- Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.
- Encode output for the context it lands in, and re-validate on the server even if the client already did.

#### T-192 · [I] Weak authorisation over sensitive data in Touchscreen HMI (DSI panel + libinput) — **HIGH**

_Information disclosure — violates Confidentiality_

Touchscreen HMI (DSI panel + libinput) handles sensitive data without a robust access decision on each object and function. A caller can request another user's record by changing an identifier, or reach a function that was only ever meant for staff.

_Authorization · Authorization_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.
- Check object-level ownership, not just that the caller is logged in.
- Cover the negative cases in tests: another tenant's id, a guessed id, a removed role.

#### T-195 · [E] No effective authorisation model in Touchscreen HMI (DSI panel + libinput) — **HIGH**

_Elevation of privilege — violates Authorisation_

Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.

_Authorization · Authorization_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Introduce roles or policies with deny-by-default, evaluated server-side.
- Separate administrative endpoints and require step-up authentication for them.
- Log every authorisation denial - a burst of denials is an attack in progress.

#### T-381 · [E] Privilege crosses a trust boundary into Touchscreen HMI (DSI panel + libinput) — **HIGH**

_Elevation of privilege — violates Authorisation_

"Unattended panel use" enters Touchscreen HMI (DSI panel + libinput) across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)" without an authorisation decision of its own. Whatever the caller can request, Touchscreen HMI (DSI panel + libinput) will perform - so the trust of the far side becomes the trust of this side.

_Authorization · Authorization · Lifecycle: Interoperation_

Via data flow: Unattended panel use

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.
- Grant the calling identity the narrowest set of operations that flow actually needs.
- Treat everything arriving from across the boundary as untrusted input as well.

#### T-188 · [S] Clients cannot verify they are talking to the real Touchscreen HMI (DSI panel + libinput) — **MEDIUM**

_Spoofing — violates Authentication_

A rogue endpoint, DNS hijack or malicious proxy can pose as Touchscreen HMI (DSI panel + libinput). Callers would hand credentials and data to the impostor and receive attacker-controlled responses.

_Authenticity, which includes integrity · Authentication_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.
- Use mutual TLS or a service mesh identity for internal callers.
- Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).

#### T-190 · [T] Integrity of the code and configuration of Touchscreen HMI (DSI panel + libinput) — **MEDIUM**

_Tampering — violates Integrity_

If an attacker can alter the binary, container image, dependency or configuration that Touchscreen HMI (DSI panel + libinput) runs, every other control inside it is void. Supply-chain and deployment paths are part of this element's attack surface.

_Authenticity, which includes integrity · Code, data and execution integrity · Lifecycle: Supply chain_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Pin and verify dependencies; review lockfile changes.
- Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.
- Treat configuration as code with review and integrity checks; restrict who can deploy.

#### T-197 · [T] Third-party software in Touchscreen HMI (DSI panel + libinput) is not traced to an SBOM — **MEDIUM**

_Tampering — violates Integrity_

Touchscreen HMI (DSI panel + libinput) is built from components the manufacturer did not write, but nothing here ties it to a software bill of materials. When a vulnerability is published in one of those components, nobody can say whether this device is affected.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Supply chain_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Maintain a machine-readable SBOM covering proprietary, purchased and open-source components and their upstream dependencies.
- Record each component's level of support and end-of-support date alongside it.
- Monitor the SBOM against vulnerability sources, including the CISA Known Exploited Vulnerabilities catalogue.

#### T-191 · [R] Touchscreen HMI (DSI panel + libinput) keeps no security audit trail — **MEDIUM**

_Repudiation — violates Non-repudiation_

Actions taken by or through Touchscreen HMI (DSI panel + libinput) cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.

_Authenticity, which includes integrity · Event detection and logging_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Log authentication, authorisation decisions, and every change to data or configuration.
- Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.
- Forward logs off the host to storage the process cannot rewrite.

#### T-194 · [D] Touchscreen HMI (DSI panel + libinput) has no protection against resource exhaustion — **MEDIUM**

_Denial of service — violates Availability_

A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads Touchscreen HMI (DSI panel + libinput) has, taking it down for everyone.

_Availability · Resiliency and recovery_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.
- Bound request sizes, page sizes, recursion and query cost.
- Fail fast with circuit breakers and shed load rather than queueing indefinitely.

#### T-193 · [I] Leakage through errors, responses and telemetry from Touchscreen HMI (DSI panel + libinput) — **LOW**

_Information disclosure — violates Confidentiality_

Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about Touchscreen HMI (DSI panel + libinput) - versions, paths, schema, and whether a given account exists.

_Confidentiality · Confidentiality · Lifecycle: Deployment_

**Controls already in place:** None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.

**Recommended mitigations:**
- Return generic errors to callers and keep the detail in server-side logs.
- Disable debug endpoints and directory listings in production.
- Return only the fields the caller needs; do not filter sensitive fields in the client.

### Console session (Data flow)

_Clinician reviews glucose/alarms and administers the device._

#### T-219 · [T] Clinical data at Console session can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Console session, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-046 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-002

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-220 · [D] Clinical data from Console session may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Console session unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-047 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-002

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-212 · [T] Traffic on "Console session" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-218 · [T] Commands on "Console session" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-214 · [I] Data on "Console session" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-213 · [T] No end-to-end integrity on "Console session" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-215 · [I] Sensitive data leaves a trust boundary on "Console session" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-216 · [D] "Console session" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-217 · [D] Availability of "Console session" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside interaction (Data flow)

_Clinician glances at the kiosk and unlocks it at the bedside._

#### T-228 · [T] Alarm conditions or thresholds at Bedside interaction can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside interaction. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-048 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-230 · [T] Clinical data at Bedside interaction can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside interaction, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-050 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-229 · [D] Alarm delivery through Bedside interaction can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside interaction, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-049 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-231 · [D] Clinical data from Bedside interaction may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside interaction unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-051 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-221 · [T] Traffic on "Bedside interaction" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-227 · [T] Commands on "Bedside interaction" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-223 · [I] Data on "Bedside interaction" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-222 · [T] No end-to-end integrity on "Bedside interaction" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-224 · [I] Sensitive data leaves a trust boundary on "Bedside interaction" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-225 · [D] "Bedside interaction" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-226 · [D] Availability of "Bedside interaction" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Privilege escalation (Data flow)

_NOPASSWD sudo on /usr/bin/awk (GTFOBins) spawns a root shell._

#### T-302 · [T] Code delivered over "Privilege escalation" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-299 · [T] Traffic on "Privilege escalation" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-300 · [I] Data on "Privilege escalation" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-301 · [D] Availability of "Privilege escalation" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### USB port access (Data flow)

_BadUSB keystroke injection, auto-mounted mass storage, a bootable stick, and imaging the SD card off the device._

#### T-310 · [T] Code delivered over "USB port access" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-303 · [T] Traffic on "USB port access" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-305 · [I] Data on "USB port access" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-304 · [T] No end-to-end integrity on "USB port access" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-306 · [I] Sensitive data leaves a trust boundary on "USB port access" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-307 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

_Confidentiality · Confidentiality_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-308 · [D] "USB port access" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-309 · [D] Availability of "USB port access" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Auto-mount + udev rule execution (Data flow)

_Mount helpers and udev rules run as root the moment a device enumerates, so removable media reaches the root filesystem without anyone logging in._

#### T-363 · [T] Code delivered over "Auto-mount + udev rule execution" is not authenticated end to end — **CRITICAL**

_Tampering — violates Integrity_

This path carries software, firmware or configuration that the receiver will run, protected by the transport at most. Anything on the path that the manufacturer does not control - a hospital proxy, a laptop, removable media - can substitute its own code.

_Secure and timely updatability and patchability · Firmware and software updates · Lifecycle: Maintenance and update_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Sign the code at the source and verify the signature on the device before it is installed or executed.
- Treat the delivery path as untrusted from the update server to the device: transport security is an addition, not the control.
- Define what the receiver does when a transfer is interrupted or a signature fails, and test it.

#### T-356 · [T] Traffic on "Auto-mount + udev rule execution" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-358 · [I] Data on "Auto-mount + udev rule execution" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-357 · [T] No end-to-end integrity on "Auto-mount + udev rule execution" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-359 · [I] Sensitive data leaves a trust boundary on "Auto-mount + udev rule execution" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Host OS / root (SSH)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-360 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

_Confidentiality · Confidentiality_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-361 · [D] "Auto-mount + udev rule execution" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-362 · [D] Availability of "Auto-mount + udev rule execution" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### HL7 v2 query / result (MLLP) (Data flow)

_QRY^Q01 in, ORU^R01 with PHI out. Cleartext, unauthenticated._

#### T-238 · [T] Clinical data at HL7 v2 query / result (MLLP) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through HL7 v2 query / result (MLLP), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-052 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-005

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-239 · [D] Clinical data from HL7 v2 query / result (MLLP) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes HL7 v2 query / result (MLLP) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-053 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-005

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-232 · [T] Traffic on "HL7 v2 query / result (MLLP)" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-234 · [I] Data on "HL7 v2 query / result (MLLP)" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-233 · [T] No end-to-end integrity on "HL7 v2 query / result (MLLP)" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-235 · [I] Sensitive data leaves a trust boundary on "HL7 v2 query / result (MLLP)" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-236 · [D] "HL7 v2 query / result (MLLP)" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-237 · [D] Availability of "HL7 v2 query / result (MLLP)" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bedside display feed (Data flow)

_Glucose + alarm state pushed to the kiosk._

#### T-275 · [T] Alarm conditions or thresholds at Bedside display feed can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Bedside display feed. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-064 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-277 · [T] Clinical data at Bedside display feed can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Bedside display feed, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-066 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-276 · [D] Alarm delivery through Bedside display feed can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Bedside display feed, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-065 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-278 · [D] Clinical data from Bedside display feed may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Bedside display feed unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-067 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: not set · Safety file: SEC-HAZ-008

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-272 · [T] Traffic on "Bedside display feed" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-273 · [I] Data on "Bedside display feed" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-274 · [D] Availability of "Bedside display feed" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### BLE advertisement (RF) (Data flow)

_Non-connectable broadcast of XOR-obfuscated manufacturer data (company id 0xFFFF)._

#### T-286 · [T] Clinical data at BLE advertisement (RF) can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through BLE advertisement (RF), or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-068 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-007

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-287 · [D] Clinical data from BLE advertisement (RF) may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes BLE advertisement (RF) unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-069 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Minor — temporary injury, no professional intervention · Software safety class: not set · Safety file: SEC-HAZ-007

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-279 · [T] Traffic on "BLE advertisement (RF)" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-281 · [I] Data on "BLE advertisement (RF)" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-280 · [T] No end-to-end integrity on "BLE advertisement (RF)" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-285 · [T] "BLE advertisement (RF)" relies on the security of the wireless link alone — **HIGH**

_Tampering — violates Integrity_

Pairing and link encryption are the only protection on this flow. A weakness in the radio protocol or its stack - and they are found regularly - leaves nothing underneath to protect what the device receives.

_Authenticity, which includes integrity · Cryptography · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Add application-layer authentication and integrity beneath the link, so the payload is protected whatever happens to the radio protocol.
- Use the strongest pairing mode the protocol offers and refuse to fall back to a weaker one.
- Reject connections the device has not been explicitly paired or provisioned for.

#### T-282 · [I] Sensitive data leaves a trust boundary on "BLE advertisement (RF)" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-283 · [D] "BLE advertisement (RF)" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-284 · [D] Availability of "BLE advertisement (RF)" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Touch input / rendered display (Data flow)

_Touch events into the kiosk session on tty1, and the glucose trend and alarm view rendered back to the panel._

#### T-329 · [T] Alarm conditions or thresholds at Touch input / rendered display can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Touch input / rendered display. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-070 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-331 · [T] Clinical data at Touch input / rendered display can be altered or substituted — **CRITICAL**

_Tampering — violates Integrity_

Measurements, images, results or the patient identity attached to them can be modified through Touch input / rendered display, or the data of one patient can be presented as another's, without the clinician being able to detect it.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-072 · Produces clinical data used for decisions**  
> **Harm:** A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Bind clinical data to patient identity cryptographically and verify it at the point of display.
- Sign results at the source; verify signatures before a result is used clinically.
- Detect and flag stale data rather than displaying a last-known value as current.

#### T-330 · [D] Alarm delivery through Touch input / rendered display can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Touch input / rendered display, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-071 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-332 · [D] Clinical data from Touch input / rendered display may be unavailable when a decision has to be made — **CRITICAL**

_Denial of service — violates Availability_

An attack, an outage or a ransomware event makes Touch input / rendered display unavailable at the moment a clinician needs the data it holds or carries.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-073 · Produces clinical data used for decisions**  
> **Harm:** Treatment is delayed, or a decision is made without information that was available yesterday.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-012

**Recommended mitigations:**
- Define the downtime procedure and make sure clinicians have practised it.
- Keep an independent, offline-capable copy of data needed for urgent care.
- Cache the most recent values locally with an explicit staleness indicator.

#### T-326 · [T] Traffic on "Touch input / rendered display" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-327 · [I] Data on "Touch input / rendered display" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-328 · [D] Availability of "Touch input / rendered display" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Paired HID input (Data flow)

_A Bluetooth keyboard paired from outside the bay types into the kiosk session exactly as the bedside user would._

#### T-349 · [T] Alarm conditions or thresholds at Paired HID input can be tampered with — **CRITICAL**

_Tampering — violates Integrity_

Alarm limits, priorities, escalation rules or the alarm messages themselves can be modified through Paired HID input. An alarm can be silenced, downgraded, re-routed or fabricated, and the clinical team sees the altered state as the truth.

_Authenticity, which includes integrity · Code, data and execution integrity_

> **Patient safety — SEC-HAZ-078 · Generates, carries or displays alarms**  
> **Harm:** A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-011

**Recommended mitigations:**
- Protect alarm limits and escalation configuration with integrity checks; treat a change to them as a clinical event, not a setting.
- Sign alarm messages so a receiver can prove the alarm came from the device that raised it.
- Restrict who can change alarm limits, and record every change with the identity that made it.
- Annunciate locally at the device as well as remotely, so tampering with one path does not silence both.

#### T-350 · [D] Alarm delivery through Paired HID input can be blocked, delayed or flooded — **CRITICAL**

_Denial of service — violates Availability_

An attacker floods, exhausts or simply cuts Paired HID input, so alarms are queued, dropped or delayed past the point where they are clinically useful. The inverse is equally dangerous: a flood of injected alarms buries the real one.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-079 · Generates, carries or displays alarms**  
> **Harm:** Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-011

**Recommended mitigations:**
- Set and verify a maximum alarm annunciation delay end to end; monitor it in service.
- Give alarm traffic its own prioritised, rate-limited path that ordinary traffic cannot starve.
- Fail loud: if the alarm path cannot be confirmed available, raise a local technical alarm.
- Keep an independent local annunciation that does not depend on the network at all.

#### T-351 · [D] Loss of Paired HID input delays or prevents care — **HIGH**

_Denial of service — violates Availability_

Paired HID input is on the path for delivering care. A denial-of-service, ransomware event or dependency outage removes it, and the clinical workflow it supports stops.

_Availability · Resiliency and recovery_

> **Patient safety — SEC-HAZ-080 · Needed for timely care delivery**  
> **Harm:** Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm.  
> Severity of harm: Serious — injury needing professional intervention · Software safety class: Class B — non-serious injury possible · Safety file: SEC-HAZ-011

**Recommended mitigations:**
- Agree the maximum tolerable downtime with the clinical service and design to it.
- Provide a documented, rehearsed manual fallback that does not depend on the compromised system.
- Segment the device network so an outage elsewhere in the hospital cannot take clinical care down with it.

#### T-344 · [T] Traffic on "Paired HID input" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-347 · [T] Commands on "Paired HID input" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-345 · [I] Data on "Paired HID input" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-348 · [T] "Paired HID input" relies on the security of the wireless link alone — **MEDIUM**

_Tampering — violates Integrity_

Pairing and link encryption are the only protection on this flow. A weakness in the radio protocol or its stack - and they are found regularly - leaves nothing underneath to protect what the device receives.

_Authenticity, which includes integrity · Cryptography · Lifecycle: Interoperation_

**Recommended mitigations:**
- Add application-layer authentication and integrity beneath the link, so the payload is protected whatever happens to the radio protocol.
- Use the strongest pairing mode the protocol offers and refuse to fall back to a weaker one.
- Reject connections the device has not been explicitly paired or provisioned for.

#### T-346 · [D] Availability of "Paired HID input" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Unauthenticated network client (Entity)

_Any device on the lab LAN, and the student's Kali box. Anonymous until it defeats a control._

#### T-01 · [S] No proof of identity for Unauthenticated network client — **HIGH**

_Spoofing — violates Authentication_

Nothing establishes that a request really comes from Unauthenticated network client. An attacker on the network, or anyone who can reach the interface, can act as Unauthenticated network client and every downstream decision made about that identity is worthless.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Require authentication before any state-changing or data-returning operation.
- Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.
- Bind the session to the authenticated identity and re-check it on every request, not just at login.

#### T-02 · [R] Actions by Unauthenticated network client are not attributable — **HIGH**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Unauthenticated network client did. Unauthenticated network client can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

#### T-03 · [R] Anonymous actor touches sensitive data — **HIGH**

_Repudiation — violates Non-repudiation_

Unauthenticated network client is untrusted and unidentified, yet the interaction involves sensitive data. Nothing can be attributed to a specific person, so abuse is invisible and disputes are unresolvable.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Require identification before sensitive data is reached, even if the rest of the flow stays anonymous.
- If anonymity is a requirement, minimise what sensitive data is exposed on the anonymous path.

### Hospital LIS / EHR interface (Entity)

_Upstream clinical system that queries the CGM over HL7 v2 (MLLP) for glucose results._

#### T-06 · [S] No proof of identity for Hospital LIS / EHR interface — **HIGH**

_Spoofing — violates Authentication_

Nothing establishes that a request really comes from Hospital LIS / EHR interface. An attacker on the network, or anyone who can reach the interface, can act as Hospital LIS / EHR interface and every downstream decision made about that identity is worthless.

_Authenticity, which includes integrity · Authentication · Multi-patient_

**Recommended mitigations:**
- Require authentication before any state-changing or data-returning operation.
- Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.
- Bind the session to the authenticated identity and re-check it on every request, not just at login.

#### T-07 · [R] Actions by Hospital LIS / EHR interface are not attributable — **HIGH**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Hospital LIS / EHR interface did. Hospital LIS / EHR interface can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging · Multi-patient_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### Visitor at the bedside (Entity)

_A visitor, a patient, a cleaner or a contractor: unauthenticated, unsupervised, and alone with the device for minutes at a time._

#### T-146 · [S] No proof of identity for Visitor at the bedside — **HIGH**

_Spoofing — violates Authentication_

Nothing establishes that a request really comes from Visitor at the bedside. An attacker on the network, or anyone who can reach the interface, can act as Visitor at the bedside and every downstream decision made about that identity is worthless.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Require authentication before any state-changing or data-returning operation.
- Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.
- Bind the session to the authenticated identity and re-check it on every request, not just at login.

#### T-147 · [R] Actions by Visitor at the bedside are not attributable — **HIGH**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Visitor at the bedside did. Visitor at the bedside can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

#### T-148 · [R] Anonymous actor touches sensitive data — **HIGH**

_Repudiation — violates Non-repudiation_

Visitor at the bedside is untrusted and unidentified, yet the interaction involves sensitive data. Nothing can be attributed to a specific person, so abuse is invisible and disputes are unresolvable.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Require identification before sensitive data is reached, even if the rest of the flow stays anonymous.
- If anonymity is a requirement, minimise what sensitive data is exposed on the anonymous path.

### Device config (cgm.conf) (Data store)

_Holds the MQTT credentials, the device serial (BLE key) and a maintenance token. World-readable, one dir above the report root. Surface 3._

#### T-108 · [T] Unrestricted write access to Device config (cgm.conf) — **HIGH**

_Tampering — violates Integrity_

Write access to Device config (cgm.conf) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

_Authorization · Authorization_

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-110 · [R] Regulated records in Device config (cgm.conf) without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

Device config (cgm.conf) holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-111 · [I] Sensitive data stored unencrypted in Device config (cgm.conf) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Device config (cgm.conf) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-112 · [I] Weak access control on Device config (cgm.conf) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Device config (cgm.conf) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

_Confidentiality · Authentication_

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-113 · [D] Loss of Device config (cgm.conf) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Device config (cgm.conf) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-107 · [T] Modification of Device config (cgm.conf) would go unnoticed — **HIGH**

_Tampering — violates Integrity_

Nothing proves that the contents of Device config (cgm.conf) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-109 · [R] No access log for Device config (cgm.conf) — **HIGH**

_Repudiation — violates Non-repudiation_

Reads and writes against Device config (cgm.conf) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-115 · [I] Sensitive data in Device config (cgm.conf) outlives the device's time in service — **MEDIUM**

_Information disclosure — violates Confidentiality_

When the device is returned, repaired, resold or thrown away, Device config (cgm.conf) still holds patient data and credentials. Whoever handles it next has the device in their hands and all the time they need.

_Confidentiality · Confidentiality · Lifecycle: Decommission_

**Recommended mitigations:**
- Provide a sanitisation function that erases data and credentials, and say how to use it in the labeling.
- Encrypt with a key that can be destroyed, so erasure does not depend on overwriting every block.
- Revoke the device's identity and credentials on the server side when it leaves service.

#### T-114 · [D] Resource exhaustion against Device config (cgm.conf) — **MEDIUM**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Device config (cgm.conf) unavailable without any need to break into it.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### HTTP attack surface (Data flow)

_SQLi login, cookie forgery + IDOR, path traversal, rate-limit bypass, kiosk unlock._

#### T-205 · [T] Traffic on "HTTP attack surface" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-211 · [T] Commands on "HTTP attack surface" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-207 · [I] Data on "HTTP attack surface" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-206 · [T] No end-to-end integrity on "HTTP attack surface" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-208 · [I] Sensitive data leaves a trust boundary on "HTTP attack surface" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-209 · [D] "HTTP attack surface" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-210 · [D] Availability of "HTTP attack surface" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Rogue HL7 query (Data flow)

_Any HL7 speaker crafts a valid QRY^Q01 and receives PHI + serial._

#### T-288 · [T] Traffic on "Rogue HL7 query" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-290 · [I] Data on "Rogue HL7 query" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-289 · [T] No end-to-end integrity on "Rogue HL7 query" across a trust boundary — **HIGH**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-291 · [I] Sensitive data leaves a trust boundary on "Rogue HL7 query" — **HIGH**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "Untrusted lab network + BLE RF" / "GlucoSense CGM-3000 appliance (Raspberry Pi 5)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-292 · [D] "Rogue HL7 query" can be flooded — **HIGH**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-293 · [D] Availability of "Rogue HL7 query" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: Untrusted lab network + BLE RF, GlucoSense CGM-3000 appliance (Raspberry Pi 5)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Device & broker credentials (Asset)

_MQTT creds, Flask session secret, device serial, biomed SSH password._

#### T-144 · [I] Exposure of the secret Device & broker credentials — **HIGH**

_Information disclosure — violates Confidentiality_

Secrets leak through source control, build logs, container images, environment dumps, error pages and backups. A leaked secret hands over every privilege it grants, and its use by an attacker is indistinguishable from legitimate use.

_Confidentiality · Cryptography · Lifecycle: Manufacturing · Multi-patient_

**Recommended mitigations:**
- Hold secrets in a managed secret store; inject at runtime, never bake into images or repos.
- Rotate on a schedule and immediately on suspicion; make rotation cheap enough to actually do.
- Scan repositories, logs and images for secret material continuously.

#### T-143 · [I] Confidentiality of the asset Device & broker credentials — **HIGH**

_Information disclosure — violates Confidentiality_

Device & broker credentials is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

_Confidentiality · Confidentiality · Multi-patient_

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

#### T-145 · [D] Availability of the asset Device & broker credentials — **HIGH**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

_Availability · Resiliency and recovery · Multi-patient_

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

### Clinician / caregiver (Entity)

_Reads glucose and hypo/hyper alarms on the console and bedside kiosk, and acts on them._

#### T-04 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate Clinician / caregiver. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-05 · [R] Actions by Clinician / caregiver are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what Clinician / caregiver did. Clinician / caregiver can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### CGM sensor + BLE gateway (Entity)

_The wearable sensor front end that publishes legitimate glucose readings and alarm state onto glucose/#._

#### T-136 · [S] Single-factor credentials for a high-value identity — **HIGH**

_Spoofing — violates Authentication_

A stolen, phished, reused or brute-forced password is enough to fully impersonate CGM sensor + BLE gateway. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.

_Authenticity, which includes integrity · Authentication_

**Recommended mitigations:**
- Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.
- Add credential-stuffing defences: breached-password checks, lockout or progressive delays.
- Alert on logins from new devices, locations or impossible travel.

#### T-137 · [R] Actions by CGM sensor + BLE gateway are not attributable — **MEDIUM**

_Repudiation — violates Non-repudiation_

There is no reliable record of what CGM sensor + BLE gateway did. CGM sensor + BLE gateway can deny an action, and an investigation after an incident cannot establish what happened or how far it went.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Log authentication events and every security-relevant action with the actor identity, source and timestamp.
- Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.
- Synchronise clocks (NTP) so events can be correlated across systems.

### User store (cgm.db, SQLite) (Data store)

_Seeded username/role/password rows queried by the login. Surface 1._

#### T-99 · [T] Unrestricted write access to User store (cgm.db, SQLite) — **HIGH**

_Tampering — violates Integrity_

Write access to User store (cgm.db, SQLite) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

_Authorization · Authorization_

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-101 · [R] Regulated records in User store (cgm.db, SQLite) without a full audit trail — **HIGH**

_Repudiation — violates Non-repudiation_

User store (cgm.db, SQLite) holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable per-record access auditing with tamper-evident storage and defined retention.
- Review audit trails routinely rather than only after an incident.
- Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).

#### T-102 · [I] Sensitive data stored unencrypted in User store (cgm.db, SQLite) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of User store (cgm.db, SQLite) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-103 · [I] Weak access control on User store (cgm.db, SQLite) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to User store (cgm.db, SQLite) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

_Confidentiality · Authentication_

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-104 · [D] Loss of User store (cgm.db, SQLite) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of User store (cgm.db, SQLite) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-98 · [T] Modification of User store (cgm.db, SQLite) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of User store (cgm.db, SQLite) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-100 · [R] No access log for User store (cgm.db, SQLite) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against User store (cgm.db, SQLite) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-106 · [I] Sensitive data in User store (cgm.db, SQLite) outlives the device's time in service — **LOW**

_Information disclosure — violates Confidentiality_

When the device is returned, repaired, resold or thrown away, User store (cgm.db, SQLite) still holds patient data and credentials. Whoever handles it next has the device in their hands and all the time they need.

_Confidentiality · Confidentiality · Lifecycle: Decommission_

**Recommended mitigations:**
- Provide a sanitisation function that erases data and credentials, and say how to use it in the labeling.
- Encrypt with a key that can be destroyed, so erasure does not depend on overwriting every block.
- Revoke the device's identity and credentials on the server side when it leaves service.

#### T-105 · [D] Resource exhaustion against User store (cgm.db, SQLite) — **LOW**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make User store (cgm.db, SQLite) unavailable without any need to break into it.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Root filesystem / sudoers (/etc/sudoers.d, /root) (Data store)

_The NOPASSWD sudoers drop-in and /root/flag.txt (mode 600). Surface 9._

#### T-129 · [T] Unrestricted write access to Root filesystem / sudoers (/etc/sudoers.d, /root) — **HIGH**

_Tampering — violates Integrity_

Write access to Root filesystem / sudoers (/etc/sudoers.d, /root) is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.

_Authorization · Authorization_

**Recommended mitigations:**
- Give each service its own database identity with only the tables and verbs it needs.
- Separate read-only and read-write credentials; keep schema-change rights out of the application account.
- Restrict network access to the store to the components that legitimately use it.

#### T-131 · [I] Sensitive data stored unencrypted in Root filesystem / sudoers (/etc/sudoers.d, /root) — **HIGH**

_Information disclosure — violates Confidentiality_

The contents of Root filesystem / sudoers (/etc/sudoers.d, /root) are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt at rest with keys held in a managed KMS, separated from the data.
- Encrypt sensitive fields individually so a database dump alone is not enough.
- Cover snapshots, replicas and backups with the same protection.

#### T-132 · [I] Weak access control on Root filesystem / sudoers (/etc/sudoers.d, /root) — **HIGH**

_Information disclosure — violates Confidentiality_

Access to Root filesystem / sudoers (/etc/sudoers.d, /root) depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.

_Confidentiality · Authentication_

**Recommended mitigations:**
- Use per-service identities issued and rotated by the platform (IAM roles, workload identity).
- Deny public network access by default; require private networking or an explicit allow-list.
- Check object-storage buckets and shares for anonymous or over-broad grants.

#### T-133 · [D] Loss of Root filesystem / sudoers (/etc/sudoers.d, /root) may be unrecoverable — **HIGH**

_Denial of service — violates Availability_

Deletion or corruption of Root filesystem / sudoers (/etc/sudoers.d, /root) - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Keep offline or immutable copies that the production credentials cannot delete.
- Restore-test on a schedule and record the achieved recovery time.
- Enable soft delete / versioning and require approval for bulk deletes.

#### T-128 · [T] Modification of Root filesystem / sudoers (/etc/sudoers.d, /root) would go unnoticed — **MEDIUM**

_Tampering — violates Integrity_

Nothing proves that the contents of Root filesystem / sudoers (/etc/sudoers.d, /root) are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Record a signed hash or use append-only / WORM storage for records that must not change.
- Keep a separate change history rather than updating rows in place for critical records.
- Alert on direct writes that bypass the application path.

#### T-130 · [R] No access log for Root filesystem / sudoers (/etc/sudoers.d, /root) — **MEDIUM**

_Repudiation — violates Non-repudiation_

Reads and writes against Root filesystem / sudoers (/etc/sudoers.d, /root) are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.

_Authenticity, which includes integrity · Event detection and logging_

**Recommended mitigations:**
- Enable native database or object-store audit logging for reads as well as writes.
- Send audit records to a separate account or system so the same compromise cannot erase them.

#### T-135 · [I] Sensitive data in Root filesystem / sudoers (/etc/sudoers.d, /root) outlives the device's time in service — **LOW**

_Information disclosure — violates Confidentiality_

When the device is returned, repaired, resold or thrown away, Root filesystem / sudoers (/etc/sudoers.d, /root) still holds patient data and credentials. Whoever handles it next has the device in their hands and all the time they need.

_Confidentiality · Confidentiality · Lifecycle: Decommission_

**Recommended mitigations:**
- Provide a sanitisation function that erases data and credentials, and say how to use it in the labeling.
- Encrypt with a key that can be destroyed, so erasure does not depend on overwriting every block.
- Revoke the device's identity and credentials on the server side when it leaves service.

#### T-134 · [D] Resource exhaustion against Root filesystem / sudoers (/etc/sudoers.d, /root) — **LOW**

_Denial of service — violates Availability_

Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make Root filesystem / sudoers (/etc/sudoers.d, /root) unavailable without any need to break into it.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set quotas, growth alerts and retention/archival policies.
- Bound query cost and result size; add timeouts and connection limits.

### Login query (Data flow)

_String-built SELECT against the user table (SQLi)._

#### T-240 · [T] Traffic on "Login query" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-241 · [I] Data on "Login query" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-242 · [D] Availability of "Login query" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Diagnostic export / config read (Data flow)

_/admin/export joins the filename with no containment -> traversal._

#### T-243 · [T] Traffic on "Diagnostic export / config read" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-244 · [I] Data on "Diagnostic export / config read" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-245 · [D] Availability of "Diagnostic export / config read" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Console telemetry (Data flow)

_Console reads current glucose/alarm state to display._

#### T-246 · [T] Traffic on "Console telemetry" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-247 · [I] Data on "Console telemetry" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-248 · [D] Availability of "Console telemetry" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Retained telemetry (Data flow)

_Broker persists the latest retained reading/alarm per topic._

#### T-256 · [T] Traffic on "Retained telemetry" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-257 · [I] Data on "Retained telemetry" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-258 · [D] Availability of "Retained telemetry" as a dependency — **MEDIUM**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Bluetooth pairing / GATT access (Data flow)

_Just Works pairing of an HID keyboard, GATT enumeration of the advertiser, and RF flooding of the controller — all from outside the bay._

#### T-311 · [T] Traffic on "Bluetooth pairing / GATT access" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-317 · [T] Commands on "Bluetooth pairing / GATT access" can be captured and replayed — **HIGH**

_Tampering — violates Integrity_

A command recorded from this flow is still valid when it is sent again. An attacker does not need to forge or even understand it - only to hold it and repeat it at a moment of their choosing.

_Authenticity, which includes integrity · Authentication_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Bind each command to a session and a nonce or monotonic counter, and reject anything already seen.
- Authenticate the counter along with the command, so it cannot be rewritten in transit.
- Limit how long a session, and therefore a captured message, stays valid.

#### T-313 · [I] Data on "Bluetooth pairing / GATT access" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-312 · [T] No end-to-end integrity on "Bluetooth pairing / GATT access" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-318 · [T] "Bluetooth pairing / GATT access" relies on the security of the wireless link alone — **MEDIUM**

_Tampering — violates Integrity_

Pairing and link encryption are the only protection on this flow. A weakness in the radio protocol or its stack - and they are found regularly - leaves nothing underneath to protect what the device receives.

_Authenticity, which includes integrity · Cryptography · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Add application-layer authentication and integrity beneath the link, so the payload is protected whatever happens to the radio protocol.
- Use the strongest pairing mode the protocol offers and refuse to fall back to a weaker one.
- Reject connections the device has not been explicitly paired or provisioned for.

#### T-314 · [I] Sensitive data leaves a trust boundary on "Bluetooth pairing / GATT access" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-315 · [D] "Bluetooth pairing / GATT access" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-316 · [D] Availability of "Bluetooth pairing / GATT access" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Unattended panel use (Data flow)

_Anyone in the bay can read the panel and drive it: kiosk PIN guessing, gesture escape to the browser, on-screen keyboard._

#### T-319 · [T] Traffic on "Unattended panel use" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-321 · [I] Data on "Unattended panel use" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-320 · [T] No end-to-end integrity on "Unattended panel use" across a trust boundary — **MEDIUM**

_Tampering — violates Integrity_

The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.

_Authenticity, which includes integrity · Authentication · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Sign messages or use a MAC so the receiver can verify the original sender.
- Validate signed tokens at the destination rather than trusting a header added by a proxy.
- Re-authorise at the destination instead of assuming the gateway did it.

#### T-322 · [I] Sensitive data leaves a trust boundary on "Unattended panel use" — **MEDIUM**

_Information disclosure — violates Confidentiality_

This flow moves sensitive data across the trust boundary "GlucoSense CGM-3000 appliance (Raspberry Pi 5)" / "Unattended bedside (physical access)". Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else's.

_Confidentiality · Confidentiality · Lifecycle: Interoperation_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Minimise the payload: send identifiers or aggregates instead of full records where possible.
- Mask, tokenise or redact fields the far side does not need.
- Record the transfer, and confirm the receiving side's controls contractually and technically.

#### T-323 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

_Confidentiality · Confidentiality_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-324 · [D] "Unattended panel use" can be flooded — **MEDIUM**

_Denial of service — violates Availability_

The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Rate limit per identity and per source at the boundary, before the expensive work happens.
- Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.
- Put a CDN or scrubbing service in front of internet-facing entry points.

#### T-325 · [D] Availability of "Unattended panel use" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

Crosses: GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access)

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Removable-media config copy (Data flow)

_Diagnostic dumps written to a USB stick and config restored from one — the device serial and the MQTT credentials travel with them._

#### T-352 · [T] Traffic on "Removable-media config copy" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-353 · [I] Data on "Removable-media config copy" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-354 · [I] Sensitive data moved by file share or physical transfer — **MEDIUM**

_Information disclosure — violates Confidentiality_

Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.

_Confidentiality · Confidentiality_

**Recommended mitigations:**
- Replace manual transfer with an authenticated, logged interface.
- Encrypt media and files at rest, and track custody.
- Set an expiry on the copy and verify deletion.

#### T-355 · [D] Availability of "Removable-media config copy" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### HCI advertising control (Data flow)

_The advertiser drives the same controller through BlueZ, so whoever owns bluetoothd owns what the device broadcasts._

#### T-364 · [T] Traffic on "HCI advertising control" can be altered in transit — **HIGH**

_Tampering — violates Integrity_

The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.

_Authenticity, which includes integrity · Cryptography_

**Recommended mitigations:**
- Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.
- Use mutual TLS where both ends are services you control.
- Reject downgrade to plaintext rather than falling back to it.

#### T-365 · [I] Data on "HCI advertising control" is exposed in transit — **HIGH**

_Information disclosure — violates Confidentiality_

Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.

_Confidentiality · Cryptography_

**Recommended mitigations:**
- Encrypt in transit end to end; treat internal networks as hostile too.
- Keep secrets out of URLs and query strings, which are logged by every intermediary.
- For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.

#### T-366 · [D] Availability of "HCI advertising control" as a dependency — **LOW**

_Denial of service — violates Availability_

If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.
- Monitor certificate expiry and dependency health as first-class alerts.
- Queue or cache where eventual processing is acceptable.

### Hypo / hyper alarm path (Asset)

_The end-to-end path that turns a real low or high into an alarm the clinician sees and acts on._

#### T-142 · [D] Availability of the asset Hypo / hyper alarm path — **HIGH**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

#### T-141 · [I] Confidentiality of the asset Hypo / hyper alarm path — **MEDIUM**

_Information disclosure — violates Confidentiality_

Hypo / hyper alarm path is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

_Confidentiality · Confidentiality_

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

### Patient glucose data / PHI (Asset)

_Per-patient readings, MRNs and demographics across HL7, MQTT and BLE._

#### T-140 · [T] Integrity of the asset Patient glucose data / PHI — **MEDIUM**

_Tampering — violates Integrity_

If Patient glucose data / PHI can be altered without detection, decisions made from it are wrong in a way nobody notices. Corruption of a valuable record is often more damaging, and much harder to spot, than its disclosure.

_Authenticity, which includes integrity · Code, data and execution integrity_

**Recommended mitigations:**
- Establish an authoritative source and reconcile copies against it.
- Keep a tamper-evident history of changes with attribution.

#### T-138 · [I] Confidentiality of the asset Patient glucose data / PHI — **MEDIUM**

_Information disclosure — violates Confidentiality_

Patient glucose data / PHI is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.

_Confidentiality · Confidentiality_

**Recommended mitigations:**
- Trace every element that touches this asset and confirm each one carries the same classification.
- Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.
- Define who is allowed to see it and review that list.

#### T-139 · [D] Availability of the asset Patient glucose data / PHI — **MEDIUM**

_Denial of service — violates Availability_

This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.

_Availability · Resiliency and recovery_

**Recommended mitigations:**
- Define the acceptable downtime and data loss (RTO/RPO) and test against them.
- Keep an independent recovery path that a single compromise cannot reach.
- Document the manual fallback that runs while the asset is unavailable.

## 5. Patient safety traceability

Each row is a security threat with a credible path to patient harm. Carry the hazard reference into the safety risk management file (CGM-3000 Risk Management File (ISO 14971), RMF-CGM-3000 rev A) so the security control and the safety risk control are the same decision.

| Hazard ref | Threat | Element | STRIDE | Safety impact | Hazardous situation -> harm | Severity of harm | Severity | Safety file ref |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-HAZ-001 | T-19 | Web admin console (Flask) | T | Clinical data | Clinical data at Web admin console (Flask) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002, RC-021 |
| SEC-HAZ-002 | T-20 | Web admin console (Flask) | D | Clinical data | Clinical data from Web admin console (Flask) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002, RC-021 |
| SEC-HAZ-003 | T-31 | HL7 MLLP listener | T | Clinical data | Clinical data at HL7 MLLP listener can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-004 | T-32 | HL7 MLLP listener | D | Clinical data | Clinical data from HL7 MLLP listener may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-005 | T-45 | MQTT broker (mosquitto) | T | Device control | Therapy parameters handled by MQTT broker (mosquitto) can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-006 | T-46 | MQTT broker (mosquitto) | E | Device control | Therapy control functions in MQTT broker (mosquitto) are reachable without a clinical authorisation decision -> Someone with no clinical authority, or malware acting as them, changes the therapy a patient is receiving. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-007 | T-47 | MQTT broker (mosquitto) | D | Device control | Loss of MQTT broker (mosquitto) removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-008 | T-48 | MQTT broker (mosquitto) | R | Device control | Therapy changes at MQTT broker (mosquitto) cannot be reconstructed afterwards -> A harmful setting cannot be traced, so the same hazard recurs; incident investigation, vigilance reporting and clinical defence all fail. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-009 | T-49 | MQTT broker (mosquitto) | T | Alarms | Alarm conditions or thresholds at MQTT broker (mosquitto) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | HIGH | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-010 | T-50 | MQTT broker (mosquitto) | D | Alarms | Alarm delivery through MQTT broker (mosquitto) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-011 | T-51 | MQTT broker (mosquitto) | R | Alarms | Alarm history at MQTT broker (mosquitto) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-012 | T-52 | MQTT broker (mosquitto) | T | Clinical data | Clinical data at MQTT broker (mosquitto) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-013 | T-53 | MQTT broker (mosquitto) | D | Clinical data | Clinical data from MQTT broker (mosquitto) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-014 | T-66 | BLE advertiser (runs as root) | T | Clinical data | Clinical data at BLE advertiser (runs as root) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-007 |
| SEC-HAZ-015 | T-67 | BLE advertiser (runs as root) | D | Clinical data | Clinical data from BLE advertiser (runs as root) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | HIGH | SEC-HAZ-007 |
| SEC-HAZ-016 | T-80 | Bedside kiosk (Chromium / matchbox on DSI panel) | T | Alarms | Alarm conditions or thresholds at Bedside kiosk (Chromium / matchbox on DSI panel) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-017 | T-81 | Bedside kiosk (Chromium / matchbox on DSI panel) | D | Alarms | Alarm delivery through Bedside kiosk (Chromium / matchbox on DSI panel) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-018 | T-82 | Bedside kiosk (Chromium / matchbox on DSI panel) | S | Alarms | Alarms carried by Bedside kiosk (Chromium / matchbox on DSI panel) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-019 | T-83 | Bedside kiosk (Chromium / matchbox on DSI panel) | R | Alarms | Alarm history at Bedside kiosk (Chromium / matchbox on DSI panel) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-008 |
| SEC-HAZ-020 | T-84 | Bedside kiosk (Chromium / matchbox on DSI panel) | T | Clinical data | Clinical data at Bedside kiosk (Chromium / matchbox on DSI panel) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-021 | T-85 | Bedside kiosk (Chromium / matchbox on DSI panel) | D | Clinical data | Clinical data from Bedside kiosk (Chromium / matchbox on DSI panel) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-022 | T-86 | Bedside kiosk (Chromium / matchbox on DSI panel) | D | Care delivery | Loss of Bedside kiosk (Chromium / matchbox on DSI panel) delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-008 |
| SEC-HAZ-023 | T-123 | Glucose telemetry (MQTT glucose/#, retained) | T | Clinical data | Clinical data at Glucose telemetry (MQTT glucose/#, retained) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-024 | T-124 | Glucose telemetry (MQTT glucose/#, retained) | D | Clinical data | Clinical data from Glucose telemetry (MQTT glucose/#, retained) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-025 | T-125 | Glucose telemetry (MQTT glucose/#, retained) | T | Alarms | Alarm conditions or thresholds at Glucose telemetry (MQTT glucose/#, retained) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-026 | T-126 | Glucose telemetry (MQTT glucose/#, retained) | D | Alarms | Alarm delivery through Glucose telemetry (MQTT glucose/#, retained) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-027 | T-127 | Glucose telemetry (MQTT glucose/#, retained) | R | Alarms | Alarm history at Glucose telemetry (MQTT glucose/#, retained) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011 |
| SEC-HAZ-028 | T-162 | USB host ports (udev auto-mount) | T | Alarms | Alarm conditions or thresholds at USB host ports (udev auto-mount) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-029 | T-163 | USB host ports (udev auto-mount) | D | Alarms | Alarm delivery through USB host ports (udev auto-mount) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-030 | T-164 | USB host ports (udev auto-mount) | S | Alarms | Alarms carried by USB host ports (udev auto-mount) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-031 | T-165 | USB host ports (udev auto-mount) | R | Alarms | Alarm history at USB host ports (udev auto-mount) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-032 | T-166 | USB host ports (udev auto-mount) | D | Care delivery | Loss of USB host ports (udev auto-mount) delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-010 |
| SEC-HAZ-033 | T-181 | Bluetooth stack (BlueZ / bluetoothd, root) | T | Clinical data | Clinical data at Bluetooth stack (BlueZ / bluetoothd, root) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-034 | T-182 | Bluetooth stack (BlueZ / bluetoothd, root) | D | Clinical data | Clinical data from Bluetooth stack (BlueZ / bluetoothd, root) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-035 | T-183 | Bluetooth stack (BlueZ / bluetoothd, root) | T | Alarms | Alarm conditions or thresholds at Bluetooth stack (BlueZ / bluetoothd, root) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-036 | T-184 | Bluetooth stack (BlueZ / bluetoothd, root) | D | Alarms | Alarm delivery through Bluetooth stack (BlueZ / bluetoothd, root) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-037 | T-185 | Bluetooth stack (BlueZ / bluetoothd, root) | S | Alarms | Alarms carried by Bluetooth stack (BlueZ / bluetoothd, root) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-038 | T-186 | Bluetooth stack (BlueZ / bluetoothd, root) | R | Alarms | Alarm history at Bluetooth stack (BlueZ / bluetoothd, root) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-039 | T-198 | Touchscreen HMI (DSI panel + libinput) | T | Alarms | Alarm conditions or thresholds at Touchscreen HMI (DSI panel + libinput) can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-040 | T-199 | Touchscreen HMI (DSI panel + libinput) | D | Alarms | Alarm delivery through Touchscreen HMI (DSI panel + libinput) can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-041 | T-200 | Touchscreen HMI (DSI panel + libinput) | S | Alarms | Alarms carried by Touchscreen HMI (DSI panel + libinput) cannot be shown to be genuine -> False alarms cause unnecessary and potentially harmful intervention and erode trust in the alarm system; a forged "alarm cleared" hides a real one. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-042 | T-201 | Touchscreen HMI (DSI panel + libinput) | R | Alarms | Alarm history at Touchscreen HMI (DSI panel + libinput) is not reliable evidence -> After an adverse event it cannot be established whether the alarm system worked, so a systemic alarm failure stays invisible and uncorrected. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-012 |
| SEC-HAZ-043 | T-202 | Touchscreen HMI (DSI panel + libinput) | T | Clinical data | Clinical data at Touchscreen HMI (DSI panel + libinput) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-044 | T-203 | Touchscreen HMI (DSI panel + libinput) | D | Clinical data | Clinical data from Touchscreen HMI (DSI panel + libinput) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-045 | T-204 | Touchscreen HMI (DSI panel + libinput) | D | Care delivery | Loss of Touchscreen HMI (DSI panel + libinput) delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-012 |
| SEC-HAZ-046 | T-219 | Console session | T | Clinical data | Clinical data at Console session can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002 |
| SEC-HAZ-047 | T-220 | Console session | D | Clinical data | Clinical data from Console session may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-002 |
| SEC-HAZ-048 | T-228 | Bedside interaction | T | Alarms | Alarm conditions or thresholds at Bedside interaction can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-049 | T-229 | Bedside interaction | D | Alarms | Alarm delivery through Bedside interaction can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-050 | T-230 | Bedside interaction | T | Clinical data | Clinical data at Bedside interaction can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-051 | T-231 | Bedside interaction | D | Clinical data | Clinical data from Bedside interaction may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-052 | T-238 | HL7 v2 query / result (MLLP) | T | Clinical data | Clinical data at HL7 v2 query / result (MLLP) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-053 | T-239 | HL7 v2 query / result (MLLP) | D | Clinical data | Clinical data from HL7 v2 query / result (MLLP) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-005 |
| SEC-HAZ-054 | T-252 | Legitimate glucose publish | T | Clinical data | Clinical data at Legitimate glucose publish can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-055 | T-253 | Legitimate glucose publish | D | Clinical data | Clinical data from Legitimate glucose publish may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-056 | T-254 | Legitimate glucose publish | T | Alarms | Alarm conditions or thresholds at Legitimate glucose publish can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-057 | T-255 | Legitimate glucose publish | D | Alarms | Alarm delivery through Legitimate glucose publish can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001 |
| SEC-HAZ-058 | T-266 | Forged-reading injection | T | Device control | Therapy parameters handled by Forged-reading injection can be altered without detection -> The patient receives an over-dose, under-dose or wrong therapy while the display and records show the intended value. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-059 | T-267 | Forged-reading injection | D | Device control | Loss of Forged-reading injection removes control of therapy -> Therapy is interrupted, continues when it should have been stopped, or cannot be titrated while the patient deteriorates. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-060 | T-268 | Forged-reading injection | T | Alarms | Alarm conditions or thresholds at Forged-reading injection can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-061 | T-269 | Forged-reading injection | D | Alarms | Alarm delivery through Forged-reading injection can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-062 | T-270 | Forged-reading injection | T | Clinical data | Clinical data at Forged-reading injection can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-063 | T-271 | Forged-reading injection | D | Clinical data | Clinical data from Forged-reading injection may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-001, RC-011, RC-012 |
| SEC-HAZ-064 | T-275 | Bedside display feed | T | Alarms | Alarm conditions or thresholds at Bedside display feed can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-065 | T-276 | Bedside display feed | D | Alarms | Alarm delivery through Bedside display feed can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-066 | T-277 | Bedside display feed | T | Clinical data | Clinical data at Bedside display feed can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-067 | T-278 | Bedside display feed | D | Clinical data | Clinical data from Bedside display feed may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-008 |
| SEC-HAZ-068 | T-286 | BLE advertisement (RF) | T | Clinical data | Clinical data at BLE advertisement (RF) can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-007 |
| SEC-HAZ-069 | T-287 | BLE advertisement (RF) | D | Clinical data | Clinical data from BLE advertisement (RF) may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Minor — temporary injury, no professional intervention | CRITICAL | SEC-HAZ-007 |
| SEC-HAZ-070 | T-329 | Touch input / rendered display | T | Alarms | Alarm conditions or thresholds at Touch input / rendered display can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-071 | T-330 | Touch input / rendered display | D | Alarms | Alarm delivery through Touch input / rendered display can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-072 | T-331 | Touch input / rendered display | T | Clinical data | Clinical data at Touch input / rendered display can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-073 | T-332 | Touch input / rendered display | D | Clinical data | Clinical data from Touch input / rendered display may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-074 | T-340 | Bedside annunciation | T | Alarms | Alarm conditions or thresholds at Bedside annunciation can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-075 | T-341 | Bedside annunciation | D | Alarms | Alarm delivery through Bedside annunciation can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-076 | T-342 | Bedside annunciation | T | Clinical data | Clinical data at Bedside annunciation can be altered or substituted -> A clinician diagnoses or treats on wrong data: missed condition, unnecessary treatment, or the right treatment given to the wrong patient. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-077 | T-343 | Bedside annunciation | D | Clinical data | Clinical data from Bedside annunciation may be unavailable when a decision has to be made -> Treatment is delayed, or a decision is made without information that was available yesterday. | Critical — permanent impairment or life-threatening injury | CRITICAL | SEC-HAZ-012 |
| SEC-HAZ-078 | T-349 | Paired HID input | T | Alarms | Alarm conditions or thresholds at Paired HID input can be tampered with -> A genuine deteriorating-patient alarm never reaches anyone, or false alarms are injected — driving alarm fatigue, desensitisation and unnecessary intervention. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-079 | T-350 | Paired HID input | D | Alarms | Alarm delivery through Paired HID input can be blocked, delayed or flooded -> Deterioration goes unnoticed because nobody was alerted in time, or the alert that mattered was lost among false ones. | Serious — injury needing professional intervention | CRITICAL | SEC-HAZ-011 |
| SEC-HAZ-080 | T-351 | Paired HID input | D | Care delivery | Loss of Paired HID input delays or prevents care -> Treatment is delayed or diverted; in a time-critical pathway that delay is itself the harm. | Serious — injury needing professional intervention | HIGH | SEC-HAZ-011 |

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

## 7. Security architecture views

The four views FDA asks for (section V.B.2). The diagram is the picture for all of them; these tables are the text.

### 7.1 Global system view

| Path | From -> to | Carries | Protocol | Interface | Authentication | Encryption | Integrity | Replay protection |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HTTP attack surface | Unauthenticated network client <-> Web admin console (Flask) | Data, Commands | HTTP (cleartext) (HTTP/1.1, tcp/5000) | In use for the intended use | Username + password | None (cleartext) | None | None |
| Console session | Clinician / caregiver <-> Web admin console (Flask) | Data, Commands | HTTP (cleartext) (HTTP/1.1, tcp/5000) | In use for the intended use | Username + password | None (cleartext) | None | None |
| Bedside interaction | Clinician / caregiver <-> Bedside kiosk (Chromium / matchbox on DSI panel) | Data, Commands | HTTP (cleartext) (HTTP/1.1 on localhost, kiosk browser) | In use for the intended use | None / anonymous | None (cleartext) | None | None |
| HL7 v2 query / result (MLLP) | Hospital LIS / EHR interface <-> HL7 MLLP listener | Data | HL7 / DICOM / FHIR (HL7 v2 over MLLP, tcp/2575) | In use for the intended use | None / anonymous | None (cleartext) | None | None |
| Login query | Web admin console (Flask) <-> User store (cgm.db, SQLite) | Data | SQL / database protocol (SQLite file access) | In use for the intended use | Shared secret or API key | None (cleartext) | None | Not applicable — not a replayable channel |
| Diagnostic export / config read | Web admin console (Flask) <-> Device config (cgm.conf) | Data | Other (Local file read) | Service / maintenance only | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Console telemetry | Web admin console (Flask) <-> MQTT broker (mosquitto) | Data | MQTT (MQTT 3.1.1, tcp/1883) | In use for the intended use | Username + password | None (cleartext) | None | None |
| Legitimate glucose publish | CGM sensor + BLE gateway -> MQTT broker (mosquitto) | Data | MQTT (MQTT 3.1.1, tcp/1883, topic glucose/#) | In use for the intended use | Username + password | None (cleartext) | None | None |
| Retained telemetry | MQTT broker (mosquitto) <-> Glucose telemetry (MQTT glucose/#, retained) | Data | MQTT (Retained messages on glucose/#) | In use for the intended use | Username + password | None (cleartext) | None | Not applicable — not a replayable channel |
| Forged-reading injection | Unauthenticated network client <-> MQTT broker (mosquitto) | Data, Commands | MQTT (MQTT 3.1.1, tcp/1883) | In use for the intended use | Username + password | None (cleartext) | None | None |
| Bedside display feed | MQTT broker (mosquitto) -> Bedside kiosk (Chromium / matchbox on DSI panel) | Data | MQTT (MQTT 3.1.1 subscription) | In use for the intended use | Username + password | None (cleartext) | None | None |
| BLE advertisement (RF) | BLE advertiser (runs as root) -> Unauthenticated network client | Data | Bluetooth / BLE (BLE advertising, 2.4 GHz channels 37-39) | In use for the intended use | None / anonymous | None (cleartext) | None | None |
| Rogue HL7 query | Unauthenticated network client <-> HL7 MLLP listener | Data | HL7 / DICOM / FHIR (HL7 v2 over MLLP, tcp/2575) | In use for the intended use | None / anonymous | None (cleartext) | None | None |
| SSH foothold | Unauthenticated network client <-> Host shell (biomed via SSH) | Code, Commands | SFTP / SSH (SSH-2, tcp/22) | Service / maintenance only | Username + password | TLS (server authenticated) | Transport (TLS) only | Cryptographic nonce / session-bound |
| Privilege escalation | Host shell (biomed via SSH) <-> Root filesystem / sudoers (/etc/sudoers.d, /root) | Code, Commands | Other (sudo on the local host) | Service / maintenance only | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| USB port access | Visitor at the bedside <-> USB host ports (udev auto-mount) | Data, Code | Physical / manual transfer (USB host ports: mass storage and HID) | Built in but unused / dormant | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Bluetooth pairing / GATT access | Visitor at the bedside <-> Bluetooth stack (BlueZ / bluetoothd, root) | Data, Commands | Bluetooth / BLE (Bluetooth pairing and GATT) | Built in but unused / dormant | None / anonymous | None (cleartext) | None | None |
| Unattended panel use | Visitor at the bedside <-> Touchscreen HMI (DSI panel + libinput) | Commands | Physical / manual transfer (Capacitive touch panel) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Touch input / rendered display | Touchscreen HMI (DSI panel + libinput) <-> Bedside kiosk (Chromium / matchbox on DSI panel) | Data, Commands | Other (libinput events in, DSI display out) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Bedside annunciation | Touchscreen HMI (DSI panel + libinput) -> Clinician / caregiver | Data | Physical / manual transfer (Visual display and audible alarm) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Paired HID input | Bluetooth stack (BlueZ / bluetoothd, root) -> Bedside kiosk (Chromium / matchbox on DSI panel) | Commands | Bluetooth / BLE (Bluetooth HID profile) | Built in but unused / dormant | None / anonymous | None (cleartext) | None | None |
| Removable-media config copy | USB host ports (udev auto-mount) <-> Device config (cgm.conf) | Data | Physical / manual transfer (Mounted mass-storage volume) | Built in but unused / dormant | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| Auto-mount + udev rule execution | USB host ports (udev auto-mount) -> Root filesystem / sudoers (/etc/sudoers.d, /root) | Code | Physical / manual transfer (udev rules run on device insertion) | Built in but unused / dormant | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |
| HCI advertising control | BLE advertiser (runs as root) -> Bluetooth stack (BlueZ / bluetoothd, root) | Commands | Other (HCI between advertiser and controller) | In use for the intended use | None / anonymous | None (cleartext) | None | Not applicable — not a replayable channel |

### 7.2 Multi-patient harm view

| Element | Type | Safety impact | Severity of harm | Threats | Controls in place |
| --- | --- | --- | --- | --- | --- |
| Hospital LIS / EHR interface | Entity | — | not set | 2 | none recorded |
| Host shell (biomed via SSH) | Process | — | not set | 12 | biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root. |
| Device & broker credentials | Asset | — | not set | 3 | none recorded |
| SSH foothold | Data flow | — | not set | 5 | none recorded |

### 7.3 Updatability and patchability view

| Code-carrying path | From -> to | Protocol | Authentication | Integrity of the code | Crosses |
| --- | --- | --- | --- | --- | --- |
| SSH foothold | Unauthenticated network client -> Host shell (biomed via SSH) | SFTP / SSH | Username + password | Transport (TLS) only | Untrusted lab network + BLE RF, Host OS / root (SSH) |
| Privilege escalation | Host shell (biomed via SSH) -> Root filesystem / sudoers (/etc/sudoers.d, /root) | Other | None / anonymous | None | no boundary |
| USB port access | Visitor at the bedside -> USB host ports (udev auto-mount) | Physical / manual transfer | None / anonymous | None | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Unattended bedside (physical access) |
| Auto-mount + udev rule execution | USB host ports (udev auto-mount) -> Root filesystem / sudoers (/etc/sudoers.d, /root) | Physical / manual transfer | None / anonymous | None | GlucoSense CGM-3000 appliance (Raspberry Pi 5), Host OS / root (SSH) |

| Software | Origin | Support status | Update mechanism | SBOM reference |
| --- | --- | --- | --- | --- |
| Web admin console (Flask) | Mixed — includes third-party components | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| HL7 MLLP listener | Proprietary (manufacturer-developed) | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| MQTT broker (mosquitto) | Open source | No longer maintained (end of support) | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| BLE advertiser (runs as root) | Proprietary (manufacturer-developed) | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| Bedside kiosk (Chromium / matchbox on DSI panel) | Open source | No longer maintained (end of support) | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| Host shell (biomed via SSH) | Open source | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| USB host ports (udev auto-mount) | Open source | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| Bluetooth stack (BlueZ / bluetoothd, root) | Open source | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |
| Touchscreen HMI (DSI panel + libinput) | Open source | Actively maintained | Unauthenticated (unsigned image, file, USB or service tool) | **missing** |

### 7.4 Security use case views

| Use case | Elements and paths involved | Safety impact | Threats | Open |
| --- | --- | --- | --- | --- |
| Viewing glucose data | Clinician / caregiver, Web admin console (Flask), Bedside kiosk (Chromium / matchbox on DSI panel), Patient glucose data / PHI, Touchscreen HMI (DSI panel + libinput), Console session, Bedside interaction, Console telemetry, Bedside display feed, Touch input / rendered display, Bedside annunciation | Clinical data; Alarms; Care delivery | 110 | 109 |
| Alarming | Clinician / caregiver, MQTT broker (mosquitto), Bedside kiosk (Chromium / matchbox on DSI panel), Glucose telemetry (MQTT glucose/#, retained), Hypo / hyper alarm path, Touchscreen HMI (DSI panel + libinput), Bedside interaction, Legitimate glucose publish, Retained telemetry, Bedside display feed, Touch input / rendered display, Bedside annunciation | Clinical data; Alarms; Device control; Care delivery | 127 | 126 |
| Reporting results to the EHR | Hospital LIS / EHR interface, HL7 MLLP listener, Patient glucose data / PHI, HL7 v2 query / result (MLLP) | Clinical data | 29 | 29 |
| Device administration | Web admin console (Flask), Host shell (biomed via SSH), User store (cgm.db, SQLite), Device config (cgm.conf), Root filesystem / sudoers (/etc/sudoers.d, /root), Device & broker credentials, USB host ports (udev auto-mount), Console session, Login query, Diagnostic export / config read, SSH foothold, Privilege escalation | Clinical data; Alarms; Care delivery | 99 | 97 |
| Glucose monitoring | MQTT broker (mosquitto), BLE advertiser (runs as root), Glucose telemetry (MQTT glucose/#, retained), CGM sensor + BLE gateway, Bluetooth stack (BlueZ / bluetoothd, root), Legitimate glucose publish, Retained telemetry, BLE advertisement (RF), HCI advertising control | Device control; Alarms; Clinical data | 95 | 94 |
| Software update | Host shell (biomed via SSH), Root filesystem / sudoers (/etc/sudoers.d, /root), SSH foothold, Privilege escalation | — | 29 | 28 |

**Safety-relevant, but in no use case:** Forged-reading injection, Paired HID input.

## 8. Cybersecurity risk assessment

Pre-mitigation risk is the severity the model computed (or the CVSS v4.0 band where one was entered). Security risk is rated on exploitability and impact, not on a probability of occurrence.

**Acceptance criteria:** residual risk up to Medium is acceptable. Teaching criteria: residual Medium or below is acceptable; High and Critical have to be mitigated before the appliance could be considered for clinical use. Every threat to the alarm path is carried into the hazard analysis by its SEC-HAZ reference.

| Decision | Threats |
| --- | --- |
| Open — no decision recorded | 382 |
| Mitigated by design | 2 |
| Transferred to the user (disclosed in labeling) | 1 |

**Residual risk above the acceptance threshold:** T-97.

**Mitigated, but no verification evidence referenced:** T-09.

| Threat | Element | Risk | Pre-mitigation | Decision | Control / rationale | Residual | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-09 | Web admin console (Flask) | [T] Untrusted input reaches Web admin console (Flask) without strict validation | CRITICAL | Mitigated by design | Parameterised queries and allow-list validation on every console input — The lab fix for the login and diagnostic injection flaws. | LOW | **missing** |
| T-49 | MQTT broker (mosquitto) | [T] Alarm conditions or thresholds at MQTT broker (mosquitto) can be tampered with | HIGH | Mitigated by design | Broker ACLs and a TLS client certificate per sensor, so only the paired sensor can publish to glucose/# — The lab fix. A forged reading now needs the sensor's private key rather than a shared password. | MEDIUM | Lab retest: forged publish to glucose/# rejected |
| T-95 | Host shell (biomed via SSH) | [T] Updates to Host shell (biomed via SSH) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-298 | SSH foothold | [T] Code delivered over "SSH foothold" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-267 | Forged-reading injection | [D] Loss of Forged-reading injection removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-269 | Forged-reading injection | [D] Alarm delivery through Forged-reading injection can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-271 | Forged-reading injection | [D] Clinical data from Forged-reading injection may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-341 | Bedside annunciation | [D] Alarm delivery through Bedside annunciation can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-343 | Bedside annunciation | [D] Clinical data from Bedside annunciation may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-16 | Web admin console (Flask) | [T] Updates to Web admin console (Flask) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-266 | Forged-reading injection | [T] Therapy parameters handled by Forged-reading injection can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-268 | Forged-reading injection | [T] Alarm conditions or thresholds at Forged-reading injection can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-270 | Forged-reading injection | [T] Clinical data at Forged-reading injection can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-340 | Bedside annunciation | [T] Alarm conditions or thresholds at Bedside annunciation can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-342 | Bedside annunciation | [T] Clinical data at Bedside annunciation can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-47 | MQTT broker (mosquitto) | [D] Loss of MQTT broker (mosquitto) removes control of therapy | CRITICAL | Open |  | as pre-mitigation |  |
| T-50 | MQTT broker (mosquitto) | [D] Alarm delivery through MQTT broker (mosquitto) can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-53 | MQTT broker (mosquitto) | [D] Clinical data from MQTT broker (mosquitto) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-124 | Glucose telemetry (MQTT glucose/#, retained) | [D] Clinical data from Glucose telemetry (MQTT glucose/#, retained) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-126 | Glucose telemetry (MQTT glucose/#, retained) | [D] Alarm delivery through Glucose telemetry (MQTT glucose/#, retained) can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-253 | Legitimate glucose publish | [D] Clinical data from Legitimate glucose publish may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-255 | Legitimate glucose publish | [D] Alarm delivery through Legitimate glucose publish can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-164 | USB host ports (udev auto-mount) | [S] Alarms carried by USB host ports (udev auto-mount) cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-185 | Bluetooth stack (BlueZ / bluetoothd, root) | [S] Alarms carried by Bluetooth stack (BlueZ / bluetoothd, root) cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-19 | Web admin console (Flask) | [T] Clinical data at Web admin console (Flask) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-30 | HL7 MLLP listener | [T] Updates to HL7 MLLP listener are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-41 | MQTT broker (mosquitto) | [T] Updates to MQTT broker (mosquitto) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-45 | MQTT broker (mosquitto) | [T] Therapy parameters handled by MQTT broker (mosquitto) can be altered without detection | CRITICAL | Open |  | as pre-mitigation |  |
| T-52 | MQTT broker (mosquitto) | [T] Clinical data at MQTT broker (mosquitto) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-65 | BLE advertiser (runs as root) | [T] Updates to BLE advertiser (runs as root) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-77 | Bedside kiosk (Chromium / matchbox on DSI panel) | [T] Updates to Bedside kiosk (Chromium / matchbox on DSI panel) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-123 | Glucose telemetry (MQTT glucose/#, retained) | [T] Clinical data at Glucose telemetry (MQTT glucose/#, retained) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-125 | Glucose telemetry (MQTT glucose/#, retained) | [T] Alarm conditions or thresholds at Glucose telemetry (MQTT glucose/#, retained) can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-160 | USB host ports (udev auto-mount) | [T] Updates to USB host ports (udev auto-mount) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-162 | USB host ports (udev auto-mount) | [T] Alarm conditions or thresholds at USB host ports (udev auto-mount) can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-178 | Bluetooth stack (BlueZ / bluetoothd, root) | [T] Updates to Bluetooth stack (BlueZ / bluetoothd, root) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-181 | Bluetooth stack (BlueZ / bluetoothd, root) | [T] Clinical data at Bluetooth stack (BlueZ / bluetoothd, root) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-183 | Bluetooth stack (BlueZ / bluetoothd, root) | [T] Alarm conditions or thresholds at Bluetooth stack (BlueZ / bluetoothd, root) can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-196 | Touchscreen HMI (DSI panel + libinput) | [T] Updates to Touchscreen HMI (DSI panel + libinput) are installed without cryptographic authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-219 | Console session | [T] Clinical data at Console session can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-228 | Bedside interaction | [T] Alarm conditions or thresholds at Bedside interaction can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-230 | Bedside interaction | [T] Clinical data at Bedside interaction can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-252 | Legitimate glucose publish | [T] Clinical data at Legitimate glucose publish can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-254 | Legitimate glucose publish | [T] Alarm conditions or thresholds at Legitimate glucose publish can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-302 | Privilege escalation | [T] Code delivered over "Privilege escalation" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-310 | USB port access | [T] Code delivered over "USB port access" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-363 | Auto-mount + udev rule execution | [T] Code delivered over "Auto-mount + udev rule execution" is not authenticated end to end | CRITICAL | Open |  | as pre-mitigation |  |
| T-20 | Web admin console (Flask) | [D] Clinical data from Web admin console (Flask) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-163 | USB host ports (udev auto-mount) | [D] Alarm delivery through USB host ports (udev auto-mount) can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-182 | Bluetooth stack (BlueZ / bluetoothd, root) | [D] Clinical data from Bluetooth stack (BlueZ / bluetoothd, root) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-184 | Bluetooth stack (BlueZ / bluetoothd, root) | [D] Alarm delivery through Bluetooth stack (BlueZ / bluetoothd, root) can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-220 | Console session | [D] Clinical data from Console session may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-229 | Bedside interaction | [D] Alarm delivery through Bedside interaction can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-231 | Bedside interaction | [D] Clinical data from Bedside interaction may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-46 | MQTT broker (mosquitto) | [E] Therapy control functions in MQTT broker (mosquitto) are reachable without a clinical authorisation decision | CRITICAL | Open |  | as pre-mitigation |  |
| T-64 | BLE advertiser (runs as root) | [E] Injection into a privileged process | CRITICAL | Open |  | as pre-mitigation |  |
| T-159 | USB host ports (udev auto-mount) | [E] Injection into a privileged process | CRITICAL | Open |  | as pre-mitigation |  |
| T-177 | Bluetooth stack (BlueZ / bluetoothd, root) | [E] Injection into a privileged process | CRITICAL | Open |  | as pre-mitigation |  |
| T-82 | Bedside kiosk (Chromium / matchbox on DSI panel) | [S] Alarms carried by Bedside kiosk (Chromium / matchbox on DSI panel) cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-200 | Touchscreen HMI (DSI panel + libinput) | [S] Alarms carried by Touchscreen HMI (DSI panel + libinput) cannot be shown to be genuine | CRITICAL | Open |  | as pre-mitigation |  |
| T-80 | Bedside kiosk (Chromium / matchbox on DSI panel) | [T] Alarm conditions or thresholds at Bedside kiosk (Chromium / matchbox on DSI panel) can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-84 | Bedside kiosk (Chromium / matchbox on DSI panel) | [T] Clinical data at Bedside kiosk (Chromium / matchbox on DSI panel) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-198 | Touchscreen HMI (DSI panel + libinput) | [T] Alarm conditions or thresholds at Touchscreen HMI (DSI panel + libinput) can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-202 | Touchscreen HMI (DSI panel + libinput) | [T] Clinical data at Touchscreen HMI (DSI panel + libinput) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-238 | HL7 v2 query / result (MLLP) | [T] Clinical data at HL7 v2 query / result (MLLP) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-275 | Bedside display feed | [T] Alarm conditions or thresholds at Bedside display feed can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-277 | Bedside display feed | [T] Clinical data at Bedside display feed can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-286 | BLE advertisement (RF) | [T] Clinical data at BLE advertisement (RF) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-329 | Touch input / rendered display | [T] Alarm conditions or thresholds at Touch input / rendered display can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-331 | Touch input / rendered display | [T] Clinical data at Touch input / rendered display can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-349 | Paired HID input | [T] Alarm conditions or thresholds at Paired HID input can be tampered with | CRITICAL | Open |  | as pre-mitigation |  |
| T-81 | Bedside kiosk (Chromium / matchbox on DSI panel) | [D] Alarm delivery through Bedside kiosk (Chromium / matchbox on DSI panel) can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-85 | Bedside kiosk (Chromium / matchbox on DSI panel) | [D] Clinical data from Bedside kiosk (Chromium / matchbox on DSI panel) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-199 | Touchscreen HMI (DSI panel + libinput) | [D] Alarm delivery through Touchscreen HMI (DSI panel + libinput) can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-203 | Touchscreen HMI (DSI panel + libinput) | [D] Clinical data from Touchscreen HMI (DSI panel + libinput) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-239 | HL7 v2 query / result (MLLP) | [D] Clinical data from HL7 v2 query / result (MLLP) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-276 | Bedside display feed | [D] Alarm delivery through Bedside display feed can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-278 | Bedside display feed | [D] Clinical data from Bedside display feed may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-330 | Touch input / rendered display | [D] Alarm delivery through Touch input / rendered display can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-332 | Touch input / rendered display | [D] Clinical data from Touch input / rendered display may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-350 | Paired HID input | [D] Alarm delivery through Paired HID input can be blocked, delayed or flooded | CRITICAL | Open |  | as pre-mitigation |  |
| T-31 | HL7 MLLP listener | [T] Clinical data at HL7 MLLP listener can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-66 | BLE advertiser (runs as root) | [T] Clinical data at BLE advertiser (runs as root) can be altered or substituted | CRITICAL | Open |  | as pre-mitigation |  |
| T-88 | Host shell (biomed via SSH) | [T] Untrusted input reaches Host shell (biomed via SSH) without strict validation | CRITICAL | Open |  | as pre-mitigation |  |
| T-48 | MQTT broker (mosquitto) | [R] Therapy changes at MQTT broker (mosquitto) cannot be reconstructed afterwards | CRITICAL | Open |  | as pre-mitigation |  |
| T-51 | MQTT broker (mosquitto) | [R] Alarm history at MQTT broker (mosquitto) is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-127 | Glucose telemetry (MQTT glucose/#, retained) | [R] Alarm history at Glucose telemetry (MQTT glucose/#, retained) is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-165 | USB host ports (udev auto-mount) | [R] Alarm history at USB host ports (udev auto-mount) is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-186 | Bluetooth stack (BlueZ / bluetoothd, root) | [R] Alarm history at Bluetooth stack (BlueZ / bluetoothd, root) is not reliable evidence | CRITICAL | Open |  | as pre-mitigation |  |
| T-91 | Host shell (biomed via SSH) | [I] Weak authorisation over sensitive data in Host shell (biomed via SSH) | CRITICAL | Open |  | as pre-mitigation |  |
| T-97 | Host shell (biomed via SSH) | [I] A secret held by Host shell (biomed via SSH) is the same on every device | CRITICAL | Transferred to the user (disclosed in labeling) | Operators are told to change the SSH password at commissioning. Nothing enforces it, so the risk stays with every site that does not. | HIGH (above threshold) |  |
| T-32 | HL7 MLLP listener | [D] Clinical data from HL7 MLLP listener may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-166 | USB host ports (udev auto-mount) | [D] Loss of USB host ports (udev auto-mount) delays or prevents care | CRITICAL | Open |  | as pre-mitigation |  |
| T-287 | BLE advertisement (RF) | [D] Clinical data from BLE advertisement (RF) may be unavailable when a decision has to be made | CRITICAL | Open |  | as pre-mitigation |  |
| T-94 | Host shell (biomed via SSH) | [E] Coarse authorisation in Host shell (biomed via SSH) | CRITICAL | Open |  | as pre-mitigation |  |
| T-373 | Host shell (biomed via SSH) | [E] Service access over "SSH foothold" into Host shell (biomed via SSH) lacks strong authentication | CRITICAL | Open |  | as pre-mitigation |  |
| T-01 | Unauthenticated network client | [S] No proof of identity for Unauthenticated network client | HIGH | Open |  | as pre-mitigation |  |
| T-06 | Hospital LIS / EHR interface | [S] No proof of identity for Hospital LIS / EHR interface | HIGH | Open |  | as pre-mitigation |  |
| T-146 | Visitor at the bedside | [S] No proof of identity for Visitor at the bedside | HIGH | Open |  | as pre-mitigation |  |
| T-367 | Bedside kiosk (Chromium / matchbox on DSI panel) | [S] Unauthenticated inbound flow "Bedside interaction" | HIGH | Open |  | as pre-mitigation |  |
| T-369 | HL7 MLLP listener | [S] Unauthenticated inbound flow "HL7 v2 query / result (MLLP)" | HIGH | Open |  | as pre-mitigation |  |
| T-371 | HL7 MLLP listener | [S] Unauthenticated inbound flow "Rogue HL7 query" | HIGH | Open |  | as pre-mitigation |  |
| T-108 | Device config (cgm.conf) | [T] Unrestricted write access to Device config (cgm.conf) | HIGH | Open |  | as pre-mitigation |  |
| T-205 | HTTP attack surface | [T] Traffic on "HTTP attack surface" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-211 | HTTP attack surface | [T] Commands on "HTTP attack surface" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-212 | Console session | [T] Traffic on "Console session" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-218 | Console session | [T] Commands on "Console session" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-221 | Bedside interaction | [T] Traffic on "Bedside interaction" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-227 | Bedside interaction | [T] Commands on "Bedside interaction" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-232 | HL7 v2 query / result (MLLP) | [T] Traffic on "HL7 v2 query / result (MLLP)" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-259 | Forged-reading injection | [T] Traffic on "Forged-reading injection" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-265 | Forged-reading injection | [T] Commands on "Forged-reading injection" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-279 | BLE advertisement (RF) | [T] Traffic on "BLE advertisement (RF)" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-288 | Rogue HL7 query | [T] Traffic on "Rogue HL7 query" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-333 | Bedside annunciation | [T] Traffic on "Bedside annunciation" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-83 | Bedside kiosk (Chromium / matchbox on DSI panel) | [R] Alarm history at Bedside kiosk (Chromium / matchbox on DSI panel) is not reliable evidence | HIGH | Open |  | as pre-mitigation |  |
| T-110 | Device config (cgm.conf) | [R] Regulated records in Device config (cgm.conf) without a full audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-201 | Touchscreen HMI (DSI panel + libinput) | [R] Alarm history at Touchscreen HMI (DSI panel + libinput) is not reliable evidence | HIGH | Open |  | as pre-mitigation |  |
| T-12 | Web admin console (Flask) | [I] Weak authorisation over sensitive data in Web admin console (Flask) | HIGH | Open |  | as pre-mitigation |  |
| T-18 | Web admin console (Flask) | [I] A secret held by Web admin console (Flask) is the same on every device | HIGH | Open |  | as pre-mitigation |  |
| T-111 | Device config (cgm.conf) | [I] Sensitive data stored unencrypted in Device config (cgm.conf) | HIGH | Open |  | as pre-mitigation |  |
| T-112 | Device config (cgm.conf) | [I] Weak access control on Device config (cgm.conf) | HIGH | Open |  | as pre-mitigation |  |
| T-144 | Device & broker credentials | [I] Exposure of the secret Device & broker credentials | HIGH | Open |  | as pre-mitigation |  |
| T-207 | HTTP attack surface | [I] Data on "HTTP attack surface" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-214 | Console session | [I] Data on "Console session" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-223 | Bedside interaction | [I] Data on "Bedside interaction" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-234 | HL7 v2 query / result (MLLP) | [I] Data on "HL7 v2 query / result (MLLP)" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-261 | Forged-reading injection | [I] Data on "Forged-reading injection" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-281 | BLE advertisement (RF) | [I] Data on "BLE advertisement (RF)" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-290 | Rogue HL7 query | [I] Data on "Rogue HL7 query" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-335 | Bedside annunciation | [I] Data on "Bedside annunciation" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-67 | BLE advertiser (runs as root) | [D] Clinical data from BLE advertiser (runs as root) may be unavailable when a decision has to be made | HIGH | Open |  | as pre-mitigation |  |
| T-86 | Bedside kiosk (Chromium / matchbox on DSI panel) | [D] Loss of Bedside kiosk (Chromium / matchbox on DSI panel) delays or prevents care | HIGH | Open |  | as pre-mitigation |  |
| T-113 | Device config (cgm.conf) | [D] Loss of Device config (cgm.conf) may be unrecoverable | HIGH | Open |  | as pre-mitigation |  |
| T-120 | Glucose telemetry (MQTT glucose/#, retained) | [D] Loss of Glucose telemetry (MQTT glucose/#, retained) may be unrecoverable | HIGH | Open |  | as pre-mitigation |  |
| T-204 | Touchscreen HMI (DSI panel + libinput) | [D] Loss of Touchscreen HMI (DSI panel + libinput) delays or prevents care | HIGH | Open |  | as pre-mitigation |  |
| T-351 | Paired HID input | [D] Loss of Paired HID input delays or prevents care | HIGH | Open |  | as pre-mitigation |  |
| T-15 | Web admin console (Flask) | [E] Coarse authorisation in Web admin console (Flask) | HIGH | Open |  | as pre-mitigation |  |
| T-368 | Bedside kiosk (Chromium / matchbox on DSI panel) | [E] Privilege crosses a trust boundary into Bedside kiosk (Chromium / matchbox on DSI panel) | HIGH | Open |  | as pre-mitigation |  |
| T-370 | HL7 MLLP listener | [E] Privilege crosses a trust boundary into HL7 MLLP listener | HIGH | Open |  | as pre-mitigation |  |
| T-372 | HL7 MLLP listener | [E] Privilege crosses a trust boundary into HL7 MLLP listener | HIGH | Open |  | as pre-mitigation |  |
| T-04 | Clinician / caregiver | [S] Single-factor credentials for a high-value identity | HIGH | Open |  | as pre-mitigation |  |
| T-21 | HL7 MLLP listener | [S] HL7 MLLP listener accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-54 | BLE advertiser (runs as root) | [S] BLE advertiser (runs as root) accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-68 | Bedside kiosk (Chromium / matchbox on DSI panel) | [S] Bedside kiosk (Chromium / matchbox on DSI panel) accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-87 | Host shell (biomed via SSH) | [S] Clients cannot verify they are talking to the real Host shell (biomed via SSH) | HIGH | Open |  | as pre-mitigation |  |
| T-136 | CGM sensor + BLE gateway | [S] Single-factor credentials for a high-value identity | HIGH | Open |  | as pre-mitigation |  |
| T-149 | USB host ports (udev auto-mount) | [S] USB host ports (udev auto-mount) accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-167 | Bluetooth stack (BlueZ / bluetoothd, root) | [S] Bluetooth stack (BlueZ / bluetoothd, root) accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-187 | Touchscreen HMI (DSI panel + libinput) | [S] Touchscreen HMI (DSI panel + libinput) accepts unauthenticated callers | HIGH | Open |  | as pre-mitigation |  |
| T-374 | USB host ports (udev auto-mount) | [S] Unauthenticated inbound flow "USB port access" | HIGH | Open |  | as pre-mitigation |  |
| T-377 | Bluetooth stack (BlueZ / bluetoothd, root) | [S] Unauthenticated inbound flow "Bluetooth pairing / GATT access" | HIGH | Open |  | as pre-mitigation |  |
| T-380 | Touchscreen HMI (DSI panel + libinput) | [S] Unauthenticated inbound flow "Unattended panel use" | HIGH | Open |  | as pre-mitigation |  |
| T-382 | Bedside kiosk (Chromium / matchbox on DSI panel) | [S] Unauthenticated inbound flow "Touch input / rendered display" | HIGH | Open |  | as pre-mitigation |  |
| T-383 | Bedside kiosk (Chromium / matchbox on DSI panel) | [S] Unauthenticated inbound flow "Paired HID input" | HIGH | Open |  | as pre-mitigation |  |
| T-385 | Bluetooth stack (BlueZ / bluetoothd, root) | [S] Unauthenticated inbound flow "HCI advertising control" | HIGH | Open |  | as pre-mitigation |  |
| T-23 | HL7 MLLP listener | [T] Untrusted input reaches HL7 MLLP listener without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-34 | MQTT broker (mosquitto) | [T] Untrusted input reaches MQTT broker (mosquitto) without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-56 | BLE advertiser (runs as root) | [T] Untrusted input reaches BLE advertiser (runs as root) without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-70 | Bedside kiosk (Chromium / matchbox on DSI panel) | [T] Untrusted input reaches Bedside kiosk (Chromium / matchbox on DSI panel) without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-89 | Host shell (biomed via SSH) | [T] Integrity of the code and configuration of Host shell (biomed via SSH) | HIGH | Open |  | as pre-mitigation |  |
| T-96 | Host shell (biomed via SSH) | [T] Third-party software in Host shell (biomed via SSH) is not traced to an SBOM | HIGH | Open |  | as pre-mitigation |  |
| T-99 | User store (cgm.db, SQLite) | [T] Unrestricted write access to User store (cgm.db, SQLite) | HIGH | Open |  | as pre-mitigation |  |
| T-129 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [T] Unrestricted write access to Root filesystem / sudoers (/etc/sudoers.d, /root) | HIGH | Open |  | as pre-mitigation |  |
| T-151 | USB host ports (udev auto-mount) | [T] Untrusted input reaches USB host ports (udev auto-mount) without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-169 | Bluetooth stack (BlueZ / bluetoothd, root) | [T] Untrusted input reaches Bluetooth stack (BlueZ / bluetoothd, root) without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-189 | Touchscreen HMI (DSI panel + libinput) | [T] Untrusted input reaches Touchscreen HMI (DSI panel + libinput) without strict validation | HIGH | Open |  | as pre-mitigation |  |
| T-240 | Login query | [T] Traffic on "Login query" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-243 | Diagnostic export / config read | [T] Traffic on "Diagnostic export / config read" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-246 | Console telemetry | [T] Traffic on "Console telemetry" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-249 | Legitimate glucose publish | [T] Traffic on "Legitimate glucose publish" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-256 | Retained telemetry | [T] Traffic on "Retained telemetry" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-272 | Bedside display feed | [T] Traffic on "Bedside display feed" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-294 | SSH foothold | [T] No end-to-end integrity on "SSH foothold" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-299 | Privilege escalation | [T] Traffic on "Privilege escalation" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-303 | USB port access | [T] Traffic on "USB port access" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-311 | Bluetooth pairing / GATT access | [T] Traffic on "Bluetooth pairing / GATT access" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-317 | Bluetooth pairing / GATT access | [T] Commands on "Bluetooth pairing / GATT access" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-319 | Unattended panel use | [T] Traffic on "Unattended panel use" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-326 | Touch input / rendered display | [T] Traffic on "Touch input / rendered display" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-344 | Paired HID input | [T] Traffic on "Paired HID input" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-347 | Paired HID input | [T] Commands on "Paired HID input" can be captured and replayed | HIGH | Open |  | as pre-mitigation |  |
| T-352 | Removable-media config copy | [T] Traffic on "Removable-media config copy" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-356 | Auto-mount + udev rule execution | [T] Traffic on "Auto-mount + udev rule execution" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-364 | HCI advertising control | [T] Traffic on "HCI advertising control" can be altered in transit | HIGH | Open |  | as pre-mitigation |  |
| T-90 | Host shell (biomed via SSH) | [R] Host shell (biomed via SSH) keeps no security audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-101 | User store (cgm.db, SQLite) | [R] Regulated records in User store (cgm.db, SQLite) without a full audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-118 | Glucose telemetry (MQTT glucose/#, retained) | [R] Regulated records in Glucose telemetry (MQTT glucose/#, retained) without a full audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-26 | HL7 MLLP listener | [I] Weak authorisation over sensitive data in HL7 MLLP listener | HIGH | Open |  | as pre-mitigation |  |
| T-37 | MQTT broker (mosquitto) | [I] Weak authorisation over sensitive data in MQTT broker (mosquitto) | HIGH | Open |  | as pre-mitigation |  |
| T-44 | MQTT broker (mosquitto) | [I] A secret held by MQTT broker (mosquitto) is the same on every device | HIGH | Open |  | as pre-mitigation |  |
| T-59 | BLE advertiser (runs as root) | [I] Weak authorisation over sensitive data in BLE advertiser (runs as root) | HIGH | Open |  | as pre-mitigation |  |
| T-73 | Bedside kiosk (Chromium / matchbox on DSI panel) | [I] Weak authorisation over sensitive data in Bedside kiosk (Chromium / matchbox on DSI panel) | HIGH | Open |  | as pre-mitigation |  |
| T-102 | User store (cgm.db, SQLite) | [I] Sensitive data stored unencrypted in User store (cgm.db, SQLite) | HIGH | Open |  | as pre-mitigation |  |
| T-103 | User store (cgm.db, SQLite) | [I] Weak access control on User store (cgm.db, SQLite) | HIGH | Open |  | as pre-mitigation |  |
| T-119 | Glucose telemetry (MQTT glucose/#, retained) | [I] Sensitive data stored unencrypted in Glucose telemetry (MQTT glucose/#, retained) | HIGH | Open |  | as pre-mitigation |  |
| T-131 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [I] Sensitive data stored unencrypted in Root filesystem / sudoers (/etc/sudoers.d, /root) | HIGH | Open |  | as pre-mitigation |  |
| T-132 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [I] Weak access control on Root filesystem / sudoers (/etc/sudoers.d, /root) | HIGH | Open |  | as pre-mitigation |  |
| T-154 | USB host ports (udev auto-mount) | [I] Weak authorisation over sensitive data in USB host ports (udev auto-mount) | HIGH | Open |  | as pre-mitigation |  |
| T-172 | Bluetooth stack (BlueZ / bluetoothd, root) | [I] Weak authorisation over sensitive data in Bluetooth stack (BlueZ / bluetoothd, root) | HIGH | Open |  | as pre-mitigation |  |
| T-192 | Touchscreen HMI (DSI panel + libinput) | [I] Weak authorisation over sensitive data in Touchscreen HMI (DSI panel + libinput) | HIGH | Open |  | as pre-mitigation |  |
| T-241 | Login query | [I] Data on "Login query" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-244 | Diagnostic export / config read | [I] Data on "Diagnostic export / config read" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-247 | Console telemetry | [I] Data on "Console telemetry" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-250 | Legitimate glucose publish | [I] Data on "Legitimate glucose publish" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-257 | Retained telemetry | [I] Data on "Retained telemetry" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-273 | Bedside display feed | [I] Data on "Bedside display feed" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-295 | SSH foothold | [I] Sensitive data leaves a trust boundary on "SSH foothold" | HIGH | Open |  | as pre-mitigation |  |
| T-300 | Privilege escalation | [I] Data on "Privilege escalation" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-305 | USB port access | [I] Data on "USB port access" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-313 | Bluetooth pairing / GATT access | [I] Data on "Bluetooth pairing / GATT access" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-321 | Unattended panel use | [I] Data on "Unattended panel use" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-327 | Touch input / rendered display | [I] Data on "Touch input / rendered display" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-345 | Paired HID input | [I] Data on "Paired HID input" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-353 | Removable-media config copy | [I] Data on "Removable-media config copy" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-358 | Auto-mount + udev rule execution | [I] Data on "Auto-mount + udev rule execution" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-365 | HCI advertising control | [I] Data on "HCI advertising control" is exposed in transit | HIGH | Open |  | as pre-mitigation |  |
| T-93 | Host shell (biomed via SSH) | [D] Host shell (biomed via SSH) has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-104 | User store (cgm.db, SQLite) | [D] Loss of User store (cgm.db, SQLite) may be unrecoverable | HIGH | Open |  | as pre-mitigation |  |
| T-133 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [D] Loss of Root filesystem / sudoers (/etc/sudoers.d, /root) may be unrecoverable | HIGH | Open |  | as pre-mitigation |  |
| T-263 | Forged-reading injection | [D] "Forged-reading injection" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-296 | SSH foothold | [D] "SSH foothold" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-338 | Bedside annunciation | [D] "Bedside annunciation" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-29 | HL7 MLLP listener | [E] No effective authorisation model in HL7 MLLP listener | HIGH | Open |  | as pre-mitigation |  |
| T-40 | MQTT broker (mosquitto) | [E] Coarse authorisation in MQTT broker (mosquitto) | HIGH | Open |  | as pre-mitigation |  |
| T-43 | MQTT broker (mosquitto) | [E] MQTT broker (mosquitto) runs software that no longer receives security fixes | HIGH | Open |  | as pre-mitigation |  |
| T-62 | BLE advertiser (runs as root) | [E] BLE advertiser (runs as root) runs with administrative privilege | HIGH | Open |  | as pre-mitigation |  |
| T-63 | BLE advertiser (runs as root) | [E] No effective authorisation model in BLE advertiser (runs as root) | HIGH | Open |  | as pre-mitigation |  |
| T-76 | Bedside kiosk (Chromium / matchbox on DSI panel) | [E] No effective authorisation model in Bedside kiosk (Chromium / matchbox on DSI panel) | HIGH | Open |  | as pre-mitigation |  |
| T-79 | Bedside kiosk (Chromium / matchbox on DSI panel) | [E] Bedside kiosk (Chromium / matchbox on DSI panel) runs software that no longer receives security fixes | HIGH | Open |  | as pre-mitigation |  |
| T-157 | USB host ports (udev auto-mount) | [E] USB host ports (udev auto-mount) runs with administrative privilege | HIGH | Open |  | as pre-mitigation |  |
| T-158 | USB host ports (udev auto-mount) | [E] No effective authorisation model in USB host ports (udev auto-mount) | HIGH | Open |  | as pre-mitigation |  |
| T-175 | Bluetooth stack (BlueZ / bluetoothd, root) | [E] Bluetooth stack (BlueZ / bluetoothd, root) runs with administrative privilege | HIGH | Open |  | as pre-mitigation |  |
| T-176 | Bluetooth stack (BlueZ / bluetoothd, root) | [E] No effective authorisation model in Bluetooth stack (BlueZ / bluetoothd, root) | HIGH | Open |  | as pre-mitigation |  |
| T-195 | Touchscreen HMI (DSI panel + libinput) | [E] No effective authorisation model in Touchscreen HMI (DSI panel + libinput) | HIGH | Open |  | as pre-mitigation |  |
| T-375 | USB host ports (udev auto-mount) | [E] Privilege crosses a trust boundary into USB host ports (udev auto-mount) | HIGH | Open |  | as pre-mitigation |  |
| T-376 | USB host ports (udev auto-mount) | [E] Debug or dormant interface "USB port access" reaches USB host ports (udev auto-mount) | HIGH | Open |  | as pre-mitigation |  |
| T-378 | Bluetooth stack (BlueZ / bluetoothd, root) | [E] Privilege crosses a trust boundary into Bluetooth stack (BlueZ / bluetoothd, root) | HIGH | Open |  | as pre-mitigation |  |
| T-379 | Bluetooth stack (BlueZ / bluetoothd, root) | [E] Debug or dormant interface "Bluetooth pairing / GATT access" reaches Bluetooth stack (BlueZ / bluetoothd, root) | HIGH | Open |  | as pre-mitigation |  |
| T-381 | Touchscreen HMI (DSI panel + libinput) | [E] Privilege crosses a trust boundary into Touchscreen HMI (DSI panel + libinput) | HIGH | Open |  | as pre-mitigation |  |
| T-384 | Bedside kiosk (Chromium / matchbox on DSI panel) | [E] Debug or dormant interface "Paired HID input" reaches Bedside kiosk (Chromium / matchbox on DSI panel) | HIGH | Open |  | as pre-mitigation |  |
| T-08 | Web admin console (Flask) | [S] Clients cannot verify they are talking to the real Web admin console (Flask) | HIGH | Open |  | as pre-mitigation |  |
| T-10 | Web admin console (Flask) | [T] Integrity of the code and configuration of Web admin console (Flask) | HIGH | Open |  | as pre-mitigation |  |
| T-17 | Web admin console (Flask) | [T] Third-party software in Web admin console (Flask) is not traced to an SBOM | HIGH | Open |  | as pre-mitigation |  |
| T-107 | Device config (cgm.conf) | [T] Modification of Device config (cgm.conf) would go unnoticed | HIGH | Open |  | as pre-mitigation |  |
| T-206 | HTTP attack surface | [T] No end-to-end integrity on "HTTP attack surface" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-213 | Console session | [T] No end-to-end integrity on "Console session" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-222 | Bedside interaction | [T] No end-to-end integrity on "Bedside interaction" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-233 | HL7 v2 query / result (MLLP) | [T] No end-to-end integrity on "HL7 v2 query / result (MLLP)" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-260 | Forged-reading injection | [T] No end-to-end integrity on "Forged-reading injection" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-280 | BLE advertisement (RF) | [T] No end-to-end integrity on "BLE advertisement (RF)" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-285 | BLE advertisement (RF) | [T] "BLE advertisement (RF)" relies on the security of the wireless link alone | HIGH | Open |  | as pre-mitigation |  |
| T-289 | Rogue HL7 query | [T] No end-to-end integrity on "Rogue HL7 query" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-334 | Bedside annunciation | [T] No end-to-end integrity on "Bedside annunciation" across a trust boundary | HIGH | Open |  | as pre-mitigation |  |
| T-02 | Unauthenticated network client | [R] Actions by Unauthenticated network client are not attributable | HIGH | Open |  | as pre-mitigation |  |
| T-03 | Unauthenticated network client | [R] Anonymous actor touches sensitive data | HIGH | Open |  | as pre-mitigation |  |
| T-07 | Hospital LIS / EHR interface | [R] Actions by Hospital LIS / EHR interface are not attributable | HIGH | Open |  | as pre-mitigation |  |
| T-11 | Web admin console (Flask) | [R] Web admin console (Flask) keeps no security audit trail | HIGH | Open |  | as pre-mitigation |  |
| T-109 | Device config (cgm.conf) | [R] No access log for Device config (cgm.conf) | HIGH | Open |  | as pre-mitigation |  |
| T-147 | Visitor at the bedside | [R] Actions by Visitor at the bedside are not attributable | HIGH | Open |  | as pre-mitigation |  |
| T-148 | Visitor at the bedside | [R] Anonymous actor touches sensitive data | HIGH | Open |  | as pre-mitigation |  |
| T-143 | Device & broker credentials | [I] Confidentiality of the asset Device & broker credentials | HIGH | Open |  | as pre-mitigation |  |
| T-208 | HTTP attack surface | [I] Sensitive data leaves a trust boundary on "HTTP attack surface" | HIGH | Open |  | as pre-mitigation |  |
| T-215 | Console session | [I] Sensitive data leaves a trust boundary on "Console session" | HIGH | Open |  | as pre-mitigation |  |
| T-224 | Bedside interaction | [I] Sensitive data leaves a trust boundary on "Bedside interaction" | HIGH | Open |  | as pre-mitigation |  |
| T-235 | HL7 v2 query / result (MLLP) | [I] Sensitive data leaves a trust boundary on "HL7 v2 query / result (MLLP)" | HIGH | Open |  | as pre-mitigation |  |
| T-262 | Forged-reading injection | [I] Sensitive data leaves a trust boundary on "Forged-reading injection" | HIGH | Open |  | as pre-mitigation |  |
| T-282 | BLE advertisement (RF) | [I] Sensitive data leaves a trust boundary on "BLE advertisement (RF)" | HIGH | Open |  | as pre-mitigation |  |
| T-291 | Rogue HL7 query | [I] Sensitive data leaves a trust boundary on "Rogue HL7 query" | HIGH | Open |  | as pre-mitigation |  |
| T-336 | Bedside annunciation | [I] Sensitive data leaves a trust boundary on "Bedside annunciation" | HIGH | Open |  | as pre-mitigation |  |
| T-337 | Bedside annunciation | [I] Sensitive data moved by file share or physical transfer | HIGH | Open |  | as pre-mitigation |  |
| T-14 | Web admin console (Flask) | [D] Web admin console (Flask) has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-39 | MQTT broker (mosquitto) | [D] MQTT broker (mosquitto) has no protection against resource exhaustion | HIGH | Open |  | as pre-mitigation |  |
| T-142 | Hypo / hyper alarm path | [D] Availability of the asset Hypo / hyper alarm path | HIGH | Open |  | as pre-mitigation |  |
| T-145 | Device & broker credentials | [D] Availability of the asset Device & broker credentials | HIGH | Open |  | as pre-mitigation |  |
| T-209 | HTTP attack surface | [D] "HTTP attack surface" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-216 | Console session | [D] "Console session" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-225 | Bedside interaction | [D] "Bedside interaction" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-236 | HL7 v2 query / result (MLLP) | [D] "HL7 v2 query / result (MLLP)" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-292 | Rogue HL7 query | [D] "Rogue HL7 query" can be flooded | HIGH | Open |  | as pre-mitigation |  |
| T-22 | HL7 MLLP listener | [S] Clients cannot verify they are talking to the real HL7 MLLP listener | MEDIUM | Open |  | as pre-mitigation |  |
| T-33 | MQTT broker (mosquitto) | [S] Clients cannot verify they are talking to the real MQTT broker (mosquitto) | MEDIUM | Open |  | as pre-mitigation |  |
| T-55 | BLE advertiser (runs as root) | [S] Clients cannot verify they are talking to the real BLE advertiser (runs as root) | MEDIUM | Open |  | as pre-mitigation |  |
| T-69 | Bedside kiosk (Chromium / matchbox on DSI panel) | [S] Clients cannot verify they are talking to the real Bedside kiosk (Chromium / matchbox on DSI panel) | MEDIUM | Open |  | as pre-mitigation |  |
| T-150 | USB host ports (udev auto-mount) | [S] Clients cannot verify they are talking to the real USB host ports (udev auto-mount) | MEDIUM | Open |  | as pre-mitigation |  |
| T-168 | Bluetooth stack (BlueZ / bluetoothd, root) | [S] Clients cannot verify they are talking to the real Bluetooth stack (BlueZ / bluetoothd, root) | MEDIUM | Open |  | as pre-mitigation |  |
| T-188 | Touchscreen HMI (DSI panel + libinput) | [S] Clients cannot verify they are talking to the real Touchscreen HMI (DSI panel + libinput) | MEDIUM | Open |  | as pre-mitigation |  |
| T-24 | HL7 MLLP listener | [T] Integrity of the code and configuration of HL7 MLLP listener | MEDIUM | Open |  | as pre-mitigation |  |
| T-35 | MQTT broker (mosquitto) | [T] Integrity of the code and configuration of MQTT broker (mosquitto) | MEDIUM | Open |  | as pre-mitigation |  |
| T-42 | MQTT broker (mosquitto) | [T] Third-party software in MQTT broker (mosquitto) is not traced to an SBOM | MEDIUM | Open |  | as pre-mitigation |  |
| T-57 | BLE advertiser (runs as root) | [T] Integrity of the code and configuration of BLE advertiser (runs as root) | MEDIUM | Open |  | as pre-mitigation |  |
| T-71 | Bedside kiosk (Chromium / matchbox on DSI panel) | [T] Integrity of the code and configuration of Bedside kiosk (Chromium / matchbox on DSI panel) | MEDIUM | Open |  | as pre-mitigation |  |
| T-78 | Bedside kiosk (Chromium / matchbox on DSI panel) | [T] Third-party software in Bedside kiosk (Chromium / matchbox on DSI panel) is not traced to an SBOM | MEDIUM | Open |  | as pre-mitigation |  |
| T-98 | User store (cgm.db, SQLite) | [T] Modification of User store (cgm.db, SQLite) would go unnoticed | MEDIUM | Open |  | as pre-mitigation |  |
| T-116 | Glucose telemetry (MQTT glucose/#, retained) | [T] Modification of Glucose telemetry (MQTT glucose/#, retained) would go unnoticed | MEDIUM | Open |  | as pre-mitigation |  |
| T-128 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [T] Modification of Root filesystem / sudoers (/etc/sudoers.d, /root) would go unnoticed | MEDIUM | Open |  | as pre-mitigation |  |
| T-140 | Patient glucose data / PHI | [T] Integrity of the asset Patient glucose data / PHI | MEDIUM | Open |  | as pre-mitigation |  |
| T-152 | USB host ports (udev auto-mount) | [T] Integrity of the code and configuration of USB host ports (udev auto-mount) | MEDIUM | Open |  | as pre-mitigation |  |
| T-161 | USB host ports (udev auto-mount) | [T] Third-party software in USB host ports (udev auto-mount) is not traced to an SBOM | MEDIUM | Open |  | as pre-mitigation |  |
| T-170 | Bluetooth stack (BlueZ / bluetoothd, root) | [T] Integrity of the code and configuration of Bluetooth stack (BlueZ / bluetoothd, root) | MEDIUM | Open |  | as pre-mitigation |  |
| T-179 | Bluetooth stack (BlueZ / bluetoothd, root) | [T] Third-party software in Bluetooth stack (BlueZ / bluetoothd, root) is not traced to an SBOM | MEDIUM | Open |  | as pre-mitigation |  |
| T-190 | Touchscreen HMI (DSI panel + libinput) | [T] Integrity of the code and configuration of Touchscreen HMI (DSI panel + libinput) | MEDIUM | Open |  | as pre-mitigation |  |
| T-197 | Touchscreen HMI (DSI panel + libinput) | [T] Third-party software in Touchscreen HMI (DSI panel + libinput) is not traced to an SBOM | MEDIUM | Open |  | as pre-mitigation |  |
| T-304 | USB port access | [T] No end-to-end integrity on "USB port access" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-312 | Bluetooth pairing / GATT access | [T] No end-to-end integrity on "Bluetooth pairing / GATT access" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-318 | Bluetooth pairing / GATT access | [T] "Bluetooth pairing / GATT access" relies on the security of the wireless link alone | MEDIUM | Open |  | as pre-mitigation |  |
| T-320 | Unattended panel use | [T] No end-to-end integrity on "Unattended panel use" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-348 | Paired HID input | [T] "Paired HID input" relies on the security of the wireless link alone | MEDIUM | Open |  | as pre-mitigation |  |
| T-357 | Auto-mount + udev rule execution | [T] No end-to-end integrity on "Auto-mount + udev rule execution" across a trust boundary | MEDIUM | Open |  | as pre-mitigation |  |
| T-05 | Clinician / caregiver | [R] Actions by Clinician / caregiver are not attributable | MEDIUM | Open |  | as pre-mitigation |  |
| T-25 | HL7 MLLP listener | [R] HL7 MLLP listener keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-36 | MQTT broker (mosquitto) | [R] MQTT broker (mosquitto) keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-58 | BLE advertiser (runs as root) | [R] BLE advertiser (runs as root) keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-72 | Bedside kiosk (Chromium / matchbox on DSI panel) | [R] Bedside kiosk (Chromium / matchbox on DSI panel) keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-100 | User store (cgm.db, SQLite) | [R] No access log for User store (cgm.db, SQLite) | MEDIUM | Open |  | as pre-mitigation |  |
| T-117 | Glucose telemetry (MQTT glucose/#, retained) | [R] No access log for Glucose telemetry (MQTT glucose/#, retained) | MEDIUM | Open |  | as pre-mitigation |  |
| T-130 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [R] No access log for Root filesystem / sudoers (/etc/sudoers.d, /root) | MEDIUM | Open |  | as pre-mitigation |  |
| T-137 | CGM sensor + BLE gateway | [R] Actions by CGM sensor + BLE gateway are not attributable | MEDIUM | Open |  | as pre-mitigation |  |
| T-153 | USB host ports (udev auto-mount) | [R] USB host ports (udev auto-mount) keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-171 | Bluetooth stack (BlueZ / bluetoothd, root) | [R] Bluetooth stack (BlueZ / bluetoothd, root) keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-191 | Touchscreen HMI (DSI panel + libinput) | [R] Touchscreen HMI (DSI panel + libinput) keeps no security audit trail | MEDIUM | Open |  | as pre-mitigation |  |
| T-92 | Host shell (biomed via SSH) | [I] Leakage through errors, responses and telemetry from Host shell (biomed via SSH) | MEDIUM | Open |  | as pre-mitigation |  |
| T-138 | Patient glucose data / PHI | [I] Confidentiality of the asset Patient glucose data / PHI | MEDIUM | Open |  | as pre-mitigation |  |
| T-141 | Hypo / hyper alarm path | [I] Confidentiality of the asset Hypo / hyper alarm path | MEDIUM | Open |  | as pre-mitigation |  |
| T-306 | USB port access | [I] Sensitive data leaves a trust boundary on "USB port access" | MEDIUM | Open |  | as pre-mitigation |  |
| T-307 | USB port access | [I] Sensitive data moved by file share or physical transfer | MEDIUM | Open |  | as pre-mitigation |  |
| T-314 | Bluetooth pairing / GATT access | [I] Sensitive data leaves a trust boundary on "Bluetooth pairing / GATT access" | MEDIUM | Open |  | as pre-mitigation |  |
| T-322 | Unattended panel use | [I] Sensitive data leaves a trust boundary on "Unattended panel use" | MEDIUM | Open |  | as pre-mitigation |  |
| T-323 | Unattended panel use | [I] Sensitive data moved by file share or physical transfer | MEDIUM | Open |  | as pre-mitigation |  |
| T-354 | Removable-media config copy | [I] Sensitive data moved by file share or physical transfer | MEDIUM | Open |  | as pre-mitigation |  |
| T-359 | Auto-mount + udev rule execution | [I] Sensitive data leaves a trust boundary on "Auto-mount + udev rule execution" | MEDIUM | Open |  | as pre-mitigation |  |
| T-360 | Auto-mount + udev rule execution | [I] Sensitive data moved by file share or physical transfer | MEDIUM | Open |  | as pre-mitigation |  |
| T-28 | HL7 MLLP listener | [D] HL7 MLLP listener has no protection against resource exhaustion | MEDIUM | Open |  | as pre-mitigation |  |
| T-75 | Bedside kiosk (Chromium / matchbox on DSI panel) | [D] Bedside kiosk (Chromium / matchbox on DSI panel) has no protection against resource exhaustion | MEDIUM | Open |  | as pre-mitigation |  |
| T-139 | Patient glucose data / PHI | [D] Availability of the asset Patient glucose data / PHI | MEDIUM | Open |  | as pre-mitigation |  |
| T-156 | USB host ports (udev auto-mount) | [D] USB host ports (udev auto-mount) has no protection against resource exhaustion | MEDIUM | Open |  | as pre-mitigation |  |
| T-174 | Bluetooth stack (BlueZ / bluetoothd, root) | [D] Bluetooth stack (BlueZ / bluetoothd, root) has no protection against resource exhaustion | MEDIUM | Open |  | as pre-mitigation |  |
| T-194 | Touchscreen HMI (DSI panel + libinput) | [D] Touchscreen HMI (DSI panel + libinput) has no protection against resource exhaustion | MEDIUM | Open |  | as pre-mitigation |  |
| T-264 | Forged-reading injection | [D] Availability of "Forged-reading injection" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-283 | BLE advertisement (RF) | [D] "BLE advertisement (RF)" can be flooded | MEDIUM | Open |  | as pre-mitigation |  |
| T-297 | SSH foothold | [D] Availability of "SSH foothold" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-308 | USB port access | [D] "USB port access" can be flooded | MEDIUM | Open |  | as pre-mitigation |  |
| T-315 | Bluetooth pairing / GATT access | [D] "Bluetooth pairing / GATT access" can be flooded | MEDIUM | Open |  | as pre-mitigation |  |
| T-324 | Unattended panel use | [D] "Unattended panel use" can be flooded | MEDIUM | Open |  | as pre-mitigation |  |
| T-339 | Bedside annunciation | [D] Availability of "Bedside annunciation" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-361 | Auto-mount + udev rule execution | [D] "Auto-mount + udev rule execution" can be flooded | MEDIUM | Open |  | as pre-mitigation |  |
| T-13 | Web admin console (Flask) | [I] Leakage through errors, responses and telemetry from Web admin console (Flask) | MEDIUM | Open |  | as pre-mitigation |  |
| T-115 | Device config (cgm.conf) | [I] Sensitive data in Device config (cgm.conf) outlives the device's time in service | MEDIUM | Open |  | as pre-mitigation |  |
| T-61 | BLE advertiser (runs as root) | [D] BLE advertiser (runs as root) has no protection against resource exhaustion | MEDIUM | Open |  | as pre-mitigation |  |
| T-114 | Device config (cgm.conf) | [D] Resource exhaustion against Device config (cgm.conf) | MEDIUM | Open |  | as pre-mitigation |  |
| T-121 | Glucose telemetry (MQTT glucose/#, retained) | [D] Resource exhaustion against Glucose telemetry (MQTT glucose/#, retained) | MEDIUM | Open |  | as pre-mitigation |  |
| T-210 | HTTP attack surface | [D] Availability of "HTTP attack surface" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-217 | Console session | [D] Availability of "Console session" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-226 | Bedside interaction | [D] Availability of "Bedside interaction" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-237 | HL7 v2 query / result (MLLP) | [D] Availability of "HL7 v2 query / result (MLLP)" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-251 | Legitimate glucose publish | [D] Availability of "Legitimate glucose publish" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-258 | Retained telemetry | [D] Availability of "Retained telemetry" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-293 | Rogue HL7 query | [D] Availability of "Rogue HL7 query" as a dependency | MEDIUM | Open |  | as pre-mitigation |  |
| T-27 | HL7 MLLP listener | [I] Leakage through errors, responses and telemetry from HL7 MLLP listener | LOW | Open |  | as pre-mitigation |  |
| T-38 | MQTT broker (mosquitto) | [I] Leakage through errors, responses and telemetry from MQTT broker (mosquitto) | LOW | Open |  | as pre-mitigation |  |
| T-60 | BLE advertiser (runs as root) | [I] Leakage through errors, responses and telemetry from BLE advertiser (runs as root) | LOW | Open |  | as pre-mitigation |  |
| T-74 | Bedside kiosk (Chromium / matchbox on DSI panel) | [I] Leakage through errors, responses and telemetry from Bedside kiosk (Chromium / matchbox on DSI panel) | LOW | Open |  | as pre-mitigation |  |
| T-106 | User store (cgm.db, SQLite) | [I] Sensitive data in User store (cgm.db, SQLite) outlives the device's time in service | LOW | Open |  | as pre-mitigation |  |
| T-122 | Glucose telemetry (MQTT glucose/#, retained) | [I] Sensitive data in Glucose telemetry (MQTT glucose/#, retained) outlives the device's time in service | LOW | Open |  | as pre-mitigation |  |
| T-135 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [I] Sensitive data in Root filesystem / sudoers (/etc/sudoers.d, /root) outlives the device's time in service | LOW | Open |  | as pre-mitigation |  |
| T-155 | USB host ports (udev auto-mount) | [I] Leakage through errors, responses and telemetry from USB host ports (udev auto-mount) | LOW | Open |  | as pre-mitigation |  |
| T-173 | Bluetooth stack (BlueZ / bluetoothd, root) | [I] Leakage through errors, responses and telemetry from Bluetooth stack (BlueZ / bluetoothd, root) | LOW | Open |  | as pre-mitigation |  |
| T-180 | Bluetooth stack (BlueZ / bluetoothd, root) | [I] Keys held by Bluetooth stack (BlueZ / bluetoothd, root) can be read out of storage | LOW | Open |  | as pre-mitigation |  |
| T-193 | Touchscreen HMI (DSI panel + libinput) | [I] Leakage through errors, responses and telemetry from Touchscreen HMI (DSI panel + libinput) | LOW | Open |  | as pre-mitigation |  |
| T-105 | User store (cgm.db, SQLite) | [D] Resource exhaustion against User store (cgm.db, SQLite) | LOW | Open |  | as pre-mitigation |  |
| T-134 | Root filesystem / sudoers (/etc/sudoers.d, /root) | [D] Resource exhaustion against Root filesystem / sudoers (/etc/sudoers.d, /root) | LOW | Open |  | as pre-mitigation |  |
| T-242 | Login query | [D] Availability of "Login query" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-245 | Diagnostic export / config read | [D] Availability of "Diagnostic export / config read" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-248 | Console telemetry | [D] Availability of "Console telemetry" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-274 | Bedside display feed | [D] Availability of "Bedside display feed" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-284 | BLE advertisement (RF) | [D] Availability of "BLE advertisement (RF)" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-301 | Privilege escalation | [D] Availability of "Privilege escalation" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-309 | USB port access | [D] Availability of "USB port access" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-316 | Bluetooth pairing / GATT access | [D] Availability of "Bluetooth pairing / GATT access" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-325 | Unattended panel use | [D] Availability of "Unattended panel use" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-328 | Touch input / rendered display | [D] Availability of "Touch input / rendered display" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-346 | Paired HID input | [D] Availability of "Paired HID input" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-355 | Removable-media config copy | [D] Availability of "Removable-media config copy" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-362 | Auto-mount + udev rule execution | [D] Availability of "Auto-mount + udev rule execution" as a dependency | LOW | Open |  | as pre-mitigation |  |
| T-366 | HCI advertising control | [D] Availability of "HCI advertising control" as a dependency | LOW | Open |  | as pre-mitigation |  |

## 9. FDA premarket alignment

How this threat model lines up with FDA's "Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions" (February 2026). A reading aid for assembling a submission, not a finding of compliance.

### 9.1 Security objectives (section IV.B)

| Objective | Threats | Open |
| --- | --- | --- |
| Authenticity, which includes integrity | 163 | 161 |
| Authorization | 38 | 38 |
| Availability | 93 | 93 |
| Confidentiality | 69 | 68 |
| Secure and timely updatability and patchability | 22 | 22 |

### 9.2 Security control categories (section V.B.1, Appendix 1)

| Control category | Guidance | Threats | Open |
| --- | --- | --- | --- |
| Authentication | Appendix 1.A | 56 | 56 |
| Authorization | Appendix 1.B | 34 | 34 |
| Cryptography | Appendix 1.C | 58 | 57 |
| Code, data and execution integrity | Appendix 1.D | 58 | 56 |
| Confidentiality | Appendix 1.E | 34 | 34 |
| Event detection and logging | Appendix 1.F | 30 | 30 |
| Resiliency and recovery | Appendix 1.G | 93 | 93 |
| Firmware and software updates | Appendix 1.H | 22 | 22 |

### 9.3 Lifecycle coverage (section V.A.1)

| Stage | Threats | Considerations recorded |
| --- | --- | --- |
| Supply chain | 18 | Raspberry Pi OS, mosquitto, Flask, BlueZ and Chromium are all third-party. The lab image pins old versions on purpose, and there is no SBOM. |
| Manufacturing | 8 | Every appliance is flashed from one image: the same SSH password, broker credential and web admin account on each. |
| Deployment | 15 | Dropped onto the hospital or home network as it is. Nothing forces a credential change or closes unused services. |
| Interoperation | 44 | HL7 v2 over MLLP to the LIS / EHR, MQTT to subscribers, BLE to the sensor. |
| Maintenance and update | 16 | Patched by hand over SSH by biomed. There is no update server and nothing is signed. |
| Decommission | 4 | none recorded |

### 9.4 What this model states

| Expected of the threat model | Guidance | Status | Detail |
| --- | --- | --- | --- |
| Intended use | IV.B | Stated | Stated. |
| Environment of use | IV.B | Stated | Stated. |
| Assumptions about the system and its environment | V.A.1 | Stated | Stated. |
| Network assumed hostile | V.A.1 | Stated | Analysed on the assumption that an adversary can alter, drop and replay traffic. |
| Rationale for the threat modeling methodology | V.A.1 | Stated | Stated. |
| Trust boundaries and security context | V.B | Stated | 4 drawn. |
| Lifecycle risks beyond the design | V.A.1 | Stated | 6 of 6 lifecycle stages have a recorded consideration or a threat raised. |
| Risk acceptance criteria | V.A.2 | Stated | Residual risk up to "Medium" is acceptable. |
| Pre- and post-mitigation risk for every threat | V.A.2 | Partial | 3 of 385 threats have a recorded decision and residual risk; 382 are open. |
| Controls traced to test evidence | V.C | Partial | 1 mitigated threat has no verification evidence referenced. |
| Security risks traced into the safety risk assessment | V.A.2 | Missing | 23 breaks in the safety trace (section 5.2). |
| Multi-patient harm view | V.B.2(b) | Stated | 4 elements can affect multiple devices or patients at once. |
| Updatability and patchability view | V.B.2(c) | Stated | 4 code-carrying paths modelled. |
| Security use case views | V.B.2(d) | Partial | 6 use cases defined; 2 safety-relevant elements belong to none. |
| Software traced to the SBOM | V.A.4, Appendix 2 | Missing | 0 of 9 processes reference an SBOM entry. |

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
