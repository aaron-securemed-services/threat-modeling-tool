/* ---------------------------------------------------------------------------
 * stride.js - the STRIDE knowledge base and the rule engine that turns an
 * annotated diagram into findings.
 *
 * Methodology: STRIDE-per-element. Each element type is only analysed for the
 * STRIDE categories that can actually apply to it, and each category is checked
 * against the security categories the modeller answered in the properties
 * panel. Anything left unanswered is reported as a coverage gap rather than
 * silently assumed to be safe - that distinction is the main teaching point.
 * --------------------------------------------------------------------------- */
window.TM = window.TM || {};

(function (TM) {
  'use strict';

  /* ---------------------------------------------------------------------
   * The six categories
   * ------------------------------------------------------------------- */
  TM.STRIDE = {
    S: {
      key: 'S',
      name: 'Spoofing',
      property: 'Authentication',
      definition: 'Pretending to be something or someone else - a user, a process, a machine or a service.',
      question: 'Can an attacker claim to be this element, or claim to be someone talking to it?'
    },
    T: {
      key: 'T',
      name: 'Tampering',
      property: 'Integrity',
      definition: 'Modifying data or code without authorisation, in memory, on disk or on the wire.',
      question: 'Can an attacker change the data or the code, and would anyone notice?'
    },
    R: {
      key: 'R',
      name: 'Repudiation',
      property: 'Non-repudiation',
      definition: 'Claiming not to have performed an action, when the system cannot prove otherwise.',
      question: 'If someone did something harmful here, could we prove who did it?'
    },
    I: {
      key: 'I',
      name: 'Information disclosure',
      property: 'Confidentiality',
      definition: 'Exposing information to people who are not authorised to see it.',
      question: 'Who can see this data, and where else does a copy of it end up?'
    },
    D: {
      key: 'D',
      name: 'Denial of service',
      property: 'Availability',
      definition: 'Absorbing or destroying the resources needed to provide the service.',
      question: 'What happens if this is flooded, exhausted, deleted or slowed to a crawl?'
    },
    E: {
      key: 'E',
      name: 'Elevation of privilege',
      property: 'Authorisation',
      definition: 'Doing something you are not permitted to do, or gaining capabilities you were never granted.',
      question: 'Can a user or a caller do more here than they are entitled to?'
    }
  };

  TM.STRIDE_ORDER = ['S', 'T', 'R', 'I', 'D', 'E'];

  /**
   * STRIDE-per-element applicability. Trust boundaries are context rather than
   * an attack surface, so they are not analysed directly - they raise the risk
   * of the flows that cross them.
   */
  TM.APPLICABILITY = {
    entity: ['S', 'R'],
    process: ['S', 'T', 'R', 'I', 'D', 'E'],
    datastore: ['T', 'R', 'I', 'D'],
    flow: ['T', 'I', 'D'],
    asset: ['T', 'I', 'D'],
    boundary: []
  };

  /* ---------------------------------------------------------------------
   * Risk scale - the base ratings a rule may carry. How each of them turns
   * into a number and a level is decided by the scoring profile in force
   * (see TM.DEFAULT_SCORING and TM.validateScoring in model.js).
   * ------------------------------------------------------------------- */
  TM.RISK_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

  /* ---------------------------------------------------------------------
   * Small predicates over the annotated categories
   * ------------------------------------------------------------------- */
  function val(el, key) {
    return (el.props && el.props[key]) || '';
  }
  function unset(el, key) { return TM.isUnset(val(el, key)); }
  function is(el, key) {
    var wanted = Array.prototype.slice.call(arguments, 2);
    return wanted.indexOf(val(el, key)) !== -1;
  }
  /** Answered, and one of the listed weak values. */
  function weak(el, key) {
    var wanted = Array.prototype.slice.call(arguments, 2);
    return !unset(el, key) && wanted.indexOf(val(el, key)) !== -1;
  }
  /** Weak, or not answered at all - the common "no evidence of a control" test. */
  function weakOrUnset(el, key) {
    if (unset(el, key)) return true;
    var wanted = Array.prototype.slice.call(arguments, 2);
    return wanted.indexOf(val(el, key)) !== -1;
  }
  function sensitive(el) {
    return is(el, 'dataClassification', 'Confidential', 'Restricted (PII / PHI / PCI)');
  }
  function restricted(el) {
    return is(el, 'dataClassification', 'Restricted (PII / PHI / PCI)');
  }

  /* ---------------------------------------------------------------------
   * Rule catalogue
   *
   * { id, types, cat, test(el, ctx), title, threat, mitigations, risk }
   * `threat` may use {name} for the element label and {n} for a context noun.
   * ------------------------------------------------------------------- */
  var RULES = [

    /* ============================ ENTITY ============================== */
    {
      id: 'ent-s-noauth', types: ['entity'], cat: 'S', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'authentication', 'None / anonymous'); },
      title: 'No proof of identity for {name}',
      threat: 'Nothing establishes that a request really comes from {name}. An attacker on the network, or anyone who can reach the interface, can act as {name} and every downstream decision made about that identity is worthless.',
      mitigations: [
        'Require authentication before any state-changing or data-returning operation.',
        'Prefer federated identity (OIDC/SAML) or client certificates over hand-rolled schemes.',
        'Bind the session to the authenticated identity and re-check it on every request, not just at login.'
      ]
    },
    {
      id: 'ent-s-password-only', types: ['entity'], cat: 'S', risk: 'high',
      test: function (el) {
        return weak(el, 'authentication', 'Username + password') &&
          (is(el, 'entityKind', 'Privileged user / administrator') || sensitive(el));
      },
      title: 'Single-factor credentials for a high-value identity',
      threat: 'A stolen, phished, reused or brute-forced password is enough to fully impersonate {name}. Because this identity is privileged or reaches sensitive data, one credential compromise is one full breach.',
      mitigations: [
        'Require multi-factor authentication, phishing-resistant (WebAuthn/FIDO2) for administrators.',
        'Add credential-stuffing defences: breached-password checks, lockout or progressive delays.',
        'Alert on logins from new devices, locations or impossible travel.'
      ]
    },
    {
      id: 'ent-s-sharedsecret', types: ['entity'], cat: 'S', risk: 'medium',
      test: function (el) { return weak(el, 'authentication', 'Shared secret or API key'); },
      title: 'Shared secret identifies {name}',
      threat: 'Identity rests on a bearer secret. Anyone who obtains the key from source control, a log, a config file or a backup becomes {name}, and the theft leaves no trace.',
      mitigations: [
        'Move to short-lived tokens or mutual TLS so a leaked value expires quickly.',
        'Store keys in a secret manager, scope them narrowly, and support rotation without downtime.',
        'Scan repositories and logs for leaked keys.'
      ]
    },
    {
      id: 'ent-r-nolog', types: ['entity'], cat: 'R', risk: 'medium',
      test: function (el) { return weakOrUnset(el, 'logging', 'None', 'Errors only'); },
      title: 'Actions by {name} are not attributable',
      threat: 'There is no reliable record of what {name} did. {name} can deny an action, and an investigation after an incident cannot establish what happened or how far it went.',
      mitigations: [
        'Log authentication events and every security-relevant action with the actor identity, source and timestamp.',
        'Ship logs to append-only storage the actor cannot edit, and set a retention period that matches your obligations.',
        'Synchronise clocks (NTP) so events can be correlated across systems.'
      ]
    },
    {
      id: 'ent-r-untrusted-highvalue', types: ['entity'], cat: 'R', risk: 'medium',
      test: function (el) {
        return is(el, 'trustLevel', 'Untrusted (anonymous)') && sensitive(el);
      },
      title: 'Anonymous actor touches sensitive data',
      threat: '{name} is untrusted and unidentified, yet the interaction involves sensitive data. Nothing can be attributed to a specific person, so abuse is invisible and disputes are unresolvable.',
      mitigations: [
        'Require identification before sensitive data is reached, even if the rest of the flow stays anonymous.',
        'If anonymity is a requirement, minimise what sensitive data is exposed on the anonymous path.'
      ]
    },

    /* ============================ PROCESS ============================= */
    {
      id: 'proc-s-noauth', types: ['process'], cat: 'S', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'authentication', 'None / anonymous'); },
      title: '{name} accepts unauthenticated callers',
      threat: 'Any party that can reach {name} is treated as a legitimate caller. Attackers can invoke its functions directly, bypassing whatever front end normally sits in front of it.',
      mitigations: [
        'Authenticate every caller, including internal service-to-service calls.',
        'Use mutual TLS or signed service tokens between internal components.',
        'Do not rely on network position alone as proof of identity.'
      ]
    },
    {
      id: 'proc-s-impersonation', types: ['process'], cat: 'S', risk: 'medium',
      test: function (el, ctx) { return ctx.exposureScore >= 1 && !is(el, 'authentication', 'Client certificate (mTLS)'); },
      title: 'Clients cannot verify they are talking to the real {name}',
      threat: 'A rogue endpoint, DNS hijack or malicious proxy can pose as {name}. Callers would hand credentials and data to the impostor and receive attacker-controlled responses.',
      mitigations: [
        'Serve TLS with a certificate clients actually validate; pin or constrain the issuer where practical.',
        'Use mutual TLS or a service mesh identity for internal callers.',
        'Protect the name resolution path (DNSSEC, static service discovery, no user-controlled hostnames).'
      ]
    },
    {
      id: 'proc-t-input', types: ['process'], cat: 'T', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'inputValidation', 'None', 'Partial / deny-list'); },
      title: 'Untrusted input reaches {name} without strict validation',
      threat: 'Input crossing into {name} is not constrained to a known-good shape, so an attacker can bend the process into doing something else: injection into queries, commands or templates, deserialisation abuse, or corruption of the data it writes.',
      mitigations: [
        'Validate against an allow-list of type, length, format and range at the trust boundary.',
        'Use parameterised queries and safe APIs instead of building strings for SQL, shell or templates.',
        'Encode output for the context it lands in, and re-validate on the server even if the client already did.'
      ]
    },
    {
      id: 'proc-t-code', types: ['process'], cat: 'T', risk: 'medium',
      test: function (el, ctx) { return ctx.exposureScore >= 1 || is(el, 'privilege', 'Root / administrator', 'Elevated service account'); },
      title: 'Integrity of the code and configuration of {name}',
      threat: 'If an attacker can alter the binary, container image, dependency or configuration that {name} runs, every other control inside it is void. Supply-chain and deployment paths are part of this element\'s attack surface.',
      mitigations: [
        'Pin and verify dependencies; review lockfile changes.',
        'Sign build artefacts and verify signatures at deploy time; keep an immutable, reproducible image.',
        'Treat configuration as code with review and integrity checks; restrict who can deploy.'
      ]
    },
    {
      id: 'proc-r-nolog', types: ['process'], cat: 'R', risk: 'medium',
      test: function (el) { return weakOrUnset(el, 'logging', 'None', 'Errors only'); },
      title: '{name} keeps no security audit trail',
      threat: 'Actions taken by or through {name} cannot be reconstructed. Neither abuse by a legitimate user nor the blast radius of a compromise can be established after the fact.',
      mitigations: [
        'Log authentication, authorisation decisions, and every change to data or configuration.',
        'Record who, what, when, from where, and the outcome - and never the secret or the sensitive payload itself.',
        'Forward logs off the host to storage the process cannot rewrite.'
      ]
    },
    {
      id: 'proc-i-authz', types: ['process'], cat: 'I', risk: 'high',
      test: function (el) {
        return sensitive(el) && weakOrUnset(el, 'authorization', 'None', 'Shared credential for everyone', 'Simple ownership check');
      },
      title: 'Weak authorisation over sensitive data in {name}',
      threat: '{name} handles sensitive data without a robust access decision on each object and function. A caller can request another user\'s record by changing an identifier, or reach a function that was only ever meant for staff.',
      mitigations: [
        'Enforce deny-by-default authorisation on every request, checked server-side against the authenticated subject.',
        'Check object-level ownership, not just that the caller is logged in.',
        'Cover the negative cases in tests: another tenant\'s id, a guessed id, a removed role.'
      ]
    },
    {
      id: 'proc-i-verbose', types: ['process'], cat: 'I', risk: 'low',
      test: function (el, ctx) { return ctx.exposureScore >= 1; },
      title: 'Leakage through errors, responses and telemetry from {name}',
      threat: 'Stack traces, verbose errors, debug endpoints, over-broad API responses and detailed timing all hand an attacker internal detail about {name} - versions, paths, schema, and whether a given account exists.',
      mitigations: [
        'Return generic errors to callers and keep the detail in server-side logs.',
        'Disable debug endpoints and directory listings in production.',
        'Return only the fields the caller needs; do not filter sensitive fields in the client.'
      ]
    },
    {
      id: 'proc-i-logs-sensitive', types: ['process'], cat: 'I', risk: 'medium',
      test: function (el) {
        return restricted(el) && is(el, 'logging', 'Security events logged', 'Full audit trail, tamper-evident');
      },
      title: 'Regulated data may be copied into logs by {name}',
      threat: '{name} handles regulated data and logs heavily. Logs are usually held longer, replicated further and read by more people than the primary store, so they quietly become a second, less protected copy of the sensitive data.',
      mitigations: [
        'Redact or tokenise identifiers and payloads before they are written to logs.',
        'Apply the same classification, access control and retention to logs as to the primary store.',
        'Review log sinks (aggregators, crash reporters, APM vendors) as part of the data flow.'
      ]
    },
    {
      id: 'proc-d-noresil', types: ['process'], cat: 'D', risk: 'medium',
      test: function (el) { return weakOrUnset(el, 'resilience', 'None', 'Timeouts only'); },
      title: '{name} has no protection against resource exhaustion',
      threat: 'A flood of requests, an expensive query, a large upload or a slow dependency can consume all of the CPU, memory, connections or threads {name} has, taking it down for everyone.',
      mitigations: [
        'Apply rate limits and quotas per identity and per source, with timeouts on every outbound call.',
        'Bound request sizes, page sizes, recursion and query cost.',
        'Fail fast with circuit breakers and shed load rather than queueing indefinitely.'
      ]
    },
    {
      id: 'proc-e-privilege', types: ['process'], cat: 'E', risk: 'high',
      test: function (el) { return weak(el, 'privilege', 'Root / administrator'); },
      title: '{name} runs with administrative privilege',
      threat: 'Any code-execution or file-write bug in {name} immediately becomes full control of the host, because the process already holds every privilege the operating system can grant.',
      mitigations: [
        'Run as a dedicated unprivileged account with only the permissions the workload needs.',
        'Drop capabilities, use a read-only filesystem, and isolate with containers or sandboxing.',
        'Separate administrative functions into their own component with its own identity.'
      ]
    },
    {
      id: 'proc-e-authz', types: ['process'], cat: 'E', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'authorization', 'None', 'Shared credential for everyone'); },
      title: 'No effective authorisation model in {name}',
      threat: 'Once a caller is inside, nothing distinguishes what they may do from what an administrator may do. A normal user can reach privileged functions simply by calling them.',
      mitigations: [
        'Introduce roles or policies with deny-by-default, evaluated server-side.',
        'Separate administrative endpoints and require step-up authentication for them.',
        'Log every authorisation denial - a burst of denials is an attack in progress.'
      ]
    },
    {
      id: 'proc-e-elevated', types: ['process'], cat: 'E', risk: 'medium',
      test: function (el) { return weak(el, 'privilege', 'Elevated service account'); },
      title: '{name} holds a broadly privileged service account',
      threat: 'Compromising {name} yields whatever that shared service account can reach - typically far more than this component needs, and often across other systems that trust the same identity.',
      mitigations: [
        'Give the component its own identity scoped to exactly the resources and verbs it uses.',
        'Split high-privilege operations (schema changes, bulk export, key access) into a separate component or job.',
        'Review the account\'s permissions on a schedule and alert on privilege changes.'
      ]
    },
    {
      id: 'proc-e-objectlevel', types: ['process'], cat: 'E', risk: 'high',
      test: function (el) { return sensitive(el) && weak(el, 'authorization', 'Simple ownership check'); },
      title: 'Coarse authorisation in {name}',
      threat: 'A single ownership check does not cover the whole surface: administrative endpoints, bulk or search operations, indirect references, and newly added routes tend to be missed, letting an ordinary user reach data or functions meant for someone else.',
      mitigations: [
        'Centralise authorisation in one enforced layer rather than repeating ad-hoc checks per handler.',
        'Deny by default so a new route is unreachable until it is explicitly authorised.',
        'Test horizontal (another user\'s object) and vertical (an admin function) escalation explicitly.'
      ]
    },
    {
      id: 'proc-e-chain', types: ['process'], cat: 'E', risk: 'critical',
      test: function (el) {
        return weakOrUnset(el, 'inputValidation', 'None', 'Partial / deny-list') &&
          weak(el, 'privilege', 'Root / administrator', 'Elevated service account');
      },
      title: 'Injection into a privileged process',
      threat: 'Weak input handling combined with elevated privilege is the classic path to remote code execution: the attacker supplies the input, {name} executes it, and it executes as a privileged account.',
      mitigations: [
        'Fix both halves: strict allow-list validation and safe APIs, plus least privilege at runtime.',
        'Isolate the parsing or execution of untrusted content in a sandboxed, unprivileged worker.',
        'Add detection for anomalous child processes and outbound connections from this component.'
      ]
    },

    /* =========================== DATA STORE =========================== */
    {
      id: 'ds-t-integrity', types: ['datastore'], cat: 'T', risk: 'medium',
      test: function (el) { return weakOrUnset(el, 'integrity', 'None', 'Constraints / checksums'); },
      title: 'Modification of {name} would go unnoticed',
      threat: 'Nothing proves that the contents of {name} are what was written. An attacker with any write path - the application, the database account, a backup restore or the storage layer - can alter records silently.',
      mitigations: [
        'Record a signed hash or use append-only / WORM storage for records that must not change.',
        'Keep a separate change history rather than updating rows in place for critical records.',
        'Alert on direct writes that bypass the application path.'
      ]
    },
    {
      id: 'ds-t-write', types: ['datastore'], cat: 'T', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'authorization', 'None', 'Shared credential for everyone'); },
      title: 'Unrestricted write access to {name}',
      threat: 'Write access to {name} is not meaningfully constrained, so any component or person who reaches it can change or delete any record, regardless of what they were supposed to be able to do.',
      mitigations: [
        'Give each service its own database identity with only the tables and verbs it needs.',
        'Separate read-only and read-write credentials; keep schema-change rights out of the application account.',
        'Restrict network access to the store to the components that legitimately use it.'
      ]
    },
    {
      id: 'ds-r-nolog', types: ['datastore'], cat: 'R', risk: 'medium',
      test: function (el) { return weakOrUnset(el, 'logging', 'None', 'Errors only'); },
      title: 'No access log for {name}',
      threat: 'Reads and writes against {name} are not recorded, so a breach cannot be scoped: nobody can say which records were seen or altered, by whom, or when.',
      mitigations: [
        'Enable native database or object-store audit logging for reads as well as writes.',
        'Send audit records to a separate account or system so the same compromise cannot erase them.'
      ]
    },
    {
      id: 'ds-r-regulated', types: ['datastore'], cat: 'R', risk: 'high',
      test: function (el) { return restricted(el) && weakOrUnset(el, 'logging', 'None', 'Errors only', 'Security events logged'); },
      title: 'Regulated records in {name} without a full audit trail',
      threat: '{name} holds regulated personal data but cannot produce a tamper-evident record of who accessed which record. Beyond the security problem, this is usually a direct compliance failure and makes breach notification impossible to scope.',
      mitigations: [
        'Enable per-record access auditing with tamper-evident storage and defined retention.',
        'Review audit trails routinely rather than only after an incident.',
        'Map the retention period to the regulation that applies (e.g. HIPAA, GDPR).'
      ]
    },
    {
      id: 'ds-i-rest', types: ['datastore'], cat: 'I', risk: 'high',
      test: function (el) { return sensitive(el) && weakOrUnset(el, 'encryptionAtRest', 'None'); },
      title: 'Sensitive data stored unencrypted in {name}',
      threat: 'The contents of {name} are readable to anyone who obtains the underlying media, a snapshot, a backup file, or an over-privileged account - none of which requires breaking the application at all.',
      mitigations: [
        'Encrypt at rest with keys held in a managed KMS, separated from the data.',
        'Encrypt sensitive fields individually so a database dump alone is not enough.',
        'Cover snapshots, replicas and backups with the same protection.'
      ]
    },
    {
      id: 'ds-i-access', types: ['datastore'], cat: 'I', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'authentication', 'None / anonymous', 'Shared secret or API key'); },
      title: 'Weak access control on {name}',
      threat: 'Access to {name} depends on a shared or absent credential, so its whole contents are exposed to anyone who reaches it on the network or finds the credential in a config file, image layer or repository.',
      mitigations: [
        'Use per-service identities issued and rotated by the platform (IAM roles, workload identity).',
        'Deny public network access by default; require private networking or an explicit allow-list.',
        'Check object-storage buckets and shares for anonymous or over-broad grants.'
      ]
    },
    {
      id: 'ds-i-client', types: ['datastore'], cat: 'I', risk: 'high',
      test: function (el) { return sensitive(el) && is(el, 'storeKind', 'Browser cookie / local storage'); },
      title: 'Sensitive data held on the client in {name}',
      threat: 'Data stored in the browser is readable by any script on the page, by browser extensions, and by anyone with access to the device. It also survives logout unless it is explicitly cleared.',
      mitigations: [
        'Keep sensitive data server-side and hand the client only an opaque session reference.',
        'Use HttpOnly, Secure, SameSite cookies for session material; never localStorage for tokens.',
        'Set a short lifetime and clear client-side state on logout.'
      ]
    },
    {
      id: 'ds-i-backup', types: ['datastore'], cat: 'I', risk: 'medium',
      test: function (el) {
        return sensitive(el) && !is(el, 'backup', 'None') && !unset(el, 'backup') &&
          weakOrUnset(el, 'encryptionAtRest', 'None', 'Full-disk / volume');
      },
      title: 'Backups of {name} are a second copy of the sensitive data',
      threat: 'Backups and snapshots of {name} carry the same sensitive contents but usually live somewhere with looser access control, longer retention and less monitoring than the primary store.',
      mitigations: [
        'Encrypt backups with their own keys and restrict who can restore them.',
        'Apply the same classification and retention rules to backups as to production data.',
        'Audit restore operations - a restore is an easy way to exfiltrate a whole database.'
      ]
    },
    {
      id: 'ds-d-backup', types: ['datastore'], cat: 'D', risk: 'high',
      test: function (el) { return weakOrUnset(el, 'backup', 'None', 'Backups, never tested'); },
      title: 'Loss of {name} may be unrecoverable',
      threat: 'Deletion or corruption of {name} - by ransomware, a bad migration, or an angry account with delete rights - has no proven recovery path. Untested backups routinely turn out to be unusable at exactly the wrong moment.',
      mitigations: [
        'Keep offline or immutable copies that the production credentials cannot delete.',
        'Restore-test on a schedule and record the achieved recovery time.',
        'Enable soft delete / versioning and require approval for bulk deletes.'
      ]
    },
    {
      id: 'ds-d-exhaust', types: ['datastore'], cat: 'D', risk: 'low',
      test: function () { return true; },
      title: 'Resource exhaustion against {name}',
      threat: 'Unbounded growth, expensive queries, connection-pool exhaustion or lock contention can make {name} unavailable without any need to break into it.',
      mitigations: [
        'Set quotas, growth alerts and retention/archival policies.',
        'Bound query cost and result size; add timeouts and connection limits.'
      ]
    },

    /* ============================= FLOW =============================== */
    {
      id: 'flow-t-cleartext', types: ['flow'], cat: 'T', risk: 'high',
      test: function (el) {
        return weakOrUnset(el, 'encryptionInTransit', 'None (cleartext)') ||
          is(el, 'protocol', 'HTTP (cleartext)', 'FTP / Telnet (cleartext)');
      },
      title: 'Traffic on "{name}" can be altered in transit',
      threat: 'The flow is not cryptographically protected, so anyone positioned on the path - a compromised hop, a rogue wifi access point, a malicious proxy - can modify requests and responses as they pass.',
      mitigations: [
        'Require TLS 1.2+ with certificate validation; redirect and HSTS any cleartext port.',
        'Use mutual TLS where both ends are services you control.',
        'Reject downgrade to plaintext rather than falling back to it.'
      ]
    },
    {
      id: 'flow-t-nointegrity', types: ['flow'], cat: 'T', risk: 'medium',
      test: function (el, ctx) { return ctx.crossings.length > 0 && weakOrUnset(el, 'flowIntegrity', 'None', 'Transport (TLS) only'); },
      title: 'No end-to-end integrity on "{name}" across a trust boundary',
      threat: 'The flow crosses a trust boundary with only hop-by-hop protection. Any intermediary that terminates TLS - a load balancer, gateway, proxy or SaaS relay - can alter the message and the receiver cannot tell.',
      mitigations: [
        'Sign messages or use a MAC so the receiver can verify the original sender.',
        'Validate signed tokens at the destination rather than trusting a header added by a proxy.',
        'Re-authorise at the destination instead of assuming the gateway did it.'
      ]
    },
    {
      id: 'flow-i-cleartext', types: ['flow'], cat: 'I', risk: 'high',
      test: function (el) {
        return weakOrUnset(el, 'encryptionInTransit', 'None (cleartext)') ||
          is(el, 'protocol', 'HTTP (cleartext)', 'FTP / Telnet (cleartext)', 'Email / SMTP');
      },
      title: 'Data on "{name}" is exposed in transit',
      threat: 'Everything carried by this flow - credentials, tokens, records - is readable to anyone who can observe the path, and a passive capture leaves no trace at either end.',
      mitigations: [
        'Encrypt in transit end to end; treat internal networks as hostile too.',
        'Keep secrets out of URLs and query strings, which are logged by every intermediary.',
        'For email or other store-and-forward transports, encrypt the payload itself rather than trusting the channel.'
      ]
    },
    {
      id: 'flow-i-crossing', types: ['flow'], cat: 'I', risk: 'medium',
      test: function (el, ctx) { return ctx.crossings.length > 0 && sensitive(el); },
      title: 'Sensitive data leaves a trust boundary on "{name}"',
      threat: 'This flow moves sensitive data across {n}. Once it is on the other side, the controls, retention rules and monitoring on this side no longer apply, and you are relying on someone else\'s.',
      mitigations: [
        'Minimise the payload: send identifiers or aggregates instead of full records where possible.',
        'Mask, tokenise or redact fields the far side does not need.',
        'Record the transfer, and confirm the receiving side\'s controls contractually and technically.'
      ]
    },
    {
      id: 'flow-i-physical', types: ['flow'], cat: 'I', risk: 'medium',
      test: function (el) { return sensitive(el) && is(el, 'protocol', 'Physical / manual transfer', 'SMB / NFS file share'); },
      title: 'Sensitive data moved by file share or physical transfer',
      threat: 'Bulk copies of sensitive data made by hand or over a file share tend to escape access control entirely: media is lost, shares are over-shared, and nobody can say where the copies ended up.',
      mitigations: [
        'Replace manual transfer with an authenticated, logged interface.',
        'Encrypt media and files at rest, and track custody.',
        'Set an expiry on the copy and verify deletion.'
      ]
    },
    {
      id: 'flow-d-flood', types: ['flow'], cat: 'D', risk: 'medium',
      test: function (el, ctx) { return ctx.exposureScore >= 1 && weakOrUnset(el, 'throttling', 'None', 'Timeouts only'); },
      title: '"{name}" can be flooded',
      threat: 'The flow crosses into untrusted territory with no throttling, so an attacker can generate traffic on it faster than the receiving side can absorb, denying service to legitimate callers.',
      mitigations: [
        'Rate limit per identity and per source at the boundary, before the expensive work happens.',
        'Set timeouts and retry budgets with backoff and jitter so retries do not amplify the flood.',
        'Put a CDN or scrubbing service in front of internet-facing entry points.'
      ]
    },
    {
      id: 'flow-d-dependency', types: ['flow'], cat: 'D', risk: 'low',
      test: function () { return true; },
      title: 'Availability of "{name}" as a dependency',
      threat: 'If this flow stops working - the far side is down, slow, rate limiting you, or the certificate expires - what happens to the caller? Silent hangs propagate outages far beyond the failed component.',
      mitigations: [
        'Set aggressive timeouts and a circuit breaker; define the degraded behaviour explicitly.',
        'Monitor certificate expiry and dependency health as first-class alerts.',
        'Queue or cache where eventual processing is acceptable.'
      ]
    },

    /* ============================= ASSET ============================== */
    {
      id: 'asset-i-protect', types: ['asset'], cat: 'I', risk: 'medium',
      test: function (el) { return sensitive(el); },
      title: 'Confidentiality of the asset {name}',
      threat: '{name} is a protected asset carrying sensitive value. Every element that stores, carries or can reach it inherits its classification - and it is usually the elements nobody thought of (exports, reports, caches, test data) that expose it.',
      mitigations: [
        'Trace every element that touches this asset and confirm each one carries the same classification.',
        'Look for the secondary copies: exports, analytics, test fixtures, screenshots, support tooling.',
        'Define who is allowed to see it and review that list.'
      ]
    },
    {
      id: 'asset-i-credential', types: ['asset'], cat: 'I', risk: 'high',
      test: function (el) { return is(el, 'assetKind', 'Credential / secret'); },
      title: 'Exposure of the secret {name}',
      threat: 'Secrets leak through source control, build logs, container images, environment dumps, error pages and backups. A leaked secret hands over every privilege it grants, and its use by an attacker is indistinguishable from legitimate use.',
      mitigations: [
        'Hold secrets in a managed secret store; inject at runtime, never bake into images or repos.',
        'Rotate on a schedule and immediately on suspicion; make rotation cheap enough to actually do.',
        'Scan repositories, logs and images for secret material continuously.'
      ]
    },
    {
      id: 'asset-d-avail', types: ['asset'], cat: 'D', risk: 'medium',
      test: function (el) { return is(el, 'criticality', 'High', 'Critical (safety / life)'); },
      title: 'Availability of the asset {name}',
      threat: 'This asset is business- or safety-critical. Loss of access to it - destruction, encryption by ransomware, or an outage of whatever provides it - is a top-level business consequence, not just a technical one.',
      mitigations: [
        'Define the acceptable downtime and data loss (RTO/RPO) and test against them.',
        'Keep an independent recovery path that a single compromise cannot reach.',
        'Document the manual fallback that runs while the asset is unavailable.'
      ]
    },
    {
      id: 'asset-t-integrity', types: ['asset'], cat: 'T', risk: 'medium',
      test: function (el) { return is(el, 'assetKind', 'Information', 'Physical'); },
      title: 'Integrity of the asset {name}',
      threat: 'If {name} can be altered without detection, decisions made from it are wrong in a way nobody notices. Corruption of a valuable record is often more damaging, and much harder to spot, than its disclosure.',
      mitigations: [
        'Establish an authoritative source and reconcile copies against it.',
        'Keep a tamper-evident history of changes with attribution.'
      ]
    }
  ];

  /* ---------------------------------------------------------------------
   * Cross-element rules: a missing control on a flow is usually a threat
   * against the element on the receiving end, so those findings are attached
   * there instead of to the line.
   * ------------------------------------------------------------------- */
  var FLOW_RULES = [
    {
      id: 'x-flow-s-noauth', cat: 'S', risk: 'high',
      targets: ['process', 'datastore'],
      test: function (flow) { return weakOrUnset(flow, 'authentication', 'None / anonymous'); },
      title: 'Unauthenticated inbound flow "{flow}"',
      threat: 'Requests arriving over "{flow}" from {source} carry no proof of who sent them. {name} therefore cannot distinguish a legitimate caller from anyone else who can reach that interface.',
      mitigations: [
        'Authenticate the flow itself: mutual TLS, a signed service token or a request signature.',
        'Reject requests whose identity cannot be verified rather than defaulting to a shared identity.',
        'Do not treat "it came from inside the network" as authentication.'
      ]
    },
    {
      id: 'x-flow-e-crossing', cat: 'E', risk: 'high',
      targets: ['process', 'datastore'],
      test: function (flow, ctx) {
        return ctx.crossings.length > 0 && weakOrUnset(flow, 'authorization', 'None', 'Shared credential for everyone');
      },
      title: 'Privilege crosses a trust boundary into {name}',
      threat: '"{flow}" enters {name} across {n} without an authorisation decision of its own. Whatever the caller can request, {name} will perform - so the trust of the far side becomes the trust of this side.',
      mitigations: [
        'Re-authorise at the boundary: the receiving element makes its own decision from the caller identity.',
        'Grant the calling identity the narrowest set of operations that flow actually needs.',
        'Treat everything arriving from across the boundary as untrusted input as well.'
      ]
    }
  ];

  /* ---------------------------------------------------------------------
   * Context: exposure and impact multipliers derived from the diagram
   * ------------------------------------------------------------------- */
  function impactScore(el) {
    switch (val(el, 'dataClassification')) {
      case 'Restricted (PII / PHI / PCI)': return 2;
      case 'Confidential': return 2;
      case 'Internal': return 1;
      case 'Public': return 0;
      default: return 1; /* unknown - assume moderate, and flag the gap */
    }
  }

  function exposureScoreFor(model, el) {
    if (el.type === 'process') {
      switch (val(el, 'exposure')) {
        case 'Internet-facing': return 2;
        case 'Partner / DMZ': return 2;
        case 'Internal network': return 0;
        case 'Isolated / offline': return 0;
        default: break;
      }
    }
    if (el.type === 'entity') {
      if (is(el, 'trustLevel', 'Untrusted (anonymous)')) return 2;
      if (is(el, 'trustLevel', 'Semi-trusted (authenticated)')) return 1;
      if (is(el, 'entityKind', 'External system', 'Third-party service')) return 2;
    }
    if (el.type === 'flow') {
      var crossings = TM.boundariesCrossed(model, el);
      if (!crossings.length) return 0;
      var perimeter = crossings.some(function (b) {
        return is(b, 'boundaryKind', 'Internet / DMZ perimeter', 'Third-party or vendor', 'Tenant / customer');
      });
      return perimeter ? 2 : 1;
    }
    /* Nodes inherit exposure from the flows that reach them. */
    var touching = TM.flowsFor(model, el.id);
    var score = 0;
    touching.forEach(function (f) {
      if (TM.boundariesCrossed(model, f).length) score = Math.max(score, 1);
      var other = TM.nodeById(model, f.from === el.id ? f.to : f.from);
      if (other && other.type === 'entity' && is(other, 'trustLevel', 'Untrusted (anonymous)')) score = 2;
    });
    return score;
  }

  function buildContext(model, el) {
    var crossings = el.type === 'flow' ? TM.boundariesCrossed(model, el) : [];
    return {
      model: model,
      crossings: crossings,
      crossingNames: crossings.map(function (b) { return TM.label(b); }),
      impact: impactScore(el),
      exposureScore: exposureScoreFor(model, el),
      isAsset: !!el.isAsset
    };
  }

  /** Which context factors apply to this threat, by profile key. */
  function contextFactors(el, ctx, cat) {
    return {
      aggravators: {
        sensitiveData: ctx.impact >= 2,
        externalExposure: ctx.exposureScore >= 2,
        markedAsset: !!ctx.isAsset,
        safetyCriticalDoS: cat === 'D' && is(el, 'criticality', 'Critical (safety / life)')
      },
      mitigators: {
        publicData: ctx.impact === 0,
        lowAvailabilityNeed: cat === 'D' && is(el, 'criticality', 'Low')
      }
    };
  }

  /**
   * The severity of one finding.
   *
   * A user-entered CVSS v4.0 assessment wins when the profile says so;
   * otherwise the rule's base rating is scored through the profile: base
   * points, plus per-category points, plus points for aggravating context,
   * minus points for mitigating context.
   */
  function severityFor(profile, rule, el, ctx, cat, assessment) {
    if (assessment && profile.cvss && profile.cvss.useWhenPresent) {
      return {
        label: assessment.severity,
        color: TM.CVSS4.color(assessment.severity),
        score: assessment.score,
        sort: 100 + assessment.score,   /* scored threats sort above modelled ones of equal weight */
        source: 'CVSS 4.0',
        vector: assessment.vector,
        rationale: assessment.rationale || ''
      };
    }

    var base = profile.ruleScores && profile.ruleScores[rule.id] !== undefined
      ? profile.ruleScores[rule.id]
      : (profile.baseScores[rule.risk] !== undefined ? profile.baseScores[rule.risk] : 3);

    var score = base;
    var applied = { aggravators: [], mitigators: [] };

    /* Teaching prompts stay informational however bad the surroundings are. */
    if (rule.risk !== 'info' || profile.ruleScores[rule.id] !== undefined) {
      score += (profile.categoryPoints && profile.categoryPoints[cat]) || 0;
      var factors = contextFactors(el, ctx, cat);
      TM.SCORING_AGGRAVATORS.forEach(function (k) {
        if (!factors.aggravators[k]) return;
        score += profile.aggravatorPoints[k] || 0;
        applied.aggravators.push(k);
      });
      TM.SCORING_MITIGATORS.forEach(function (k) {
        if (!factors.mitigators[k]) return;
        score -= profile.mitigatorPoints[k] || 0;
        applied.mitigators.push(k);
      });
    }

    var level = TM.levelForScore(profile, score);
    return {
      label: level.label,
      color: level.color,
      score: Math.round(score * 100) / 100,
      sort: score,
      source: 'model',
      applied: applied
    };
  }

  function fill(text, el, ctx, extra) {
    var out = text.replace(/\{name\}/g, TM.label(el));
    out = out.replace(/\{n\}/g, ctx.crossingNames.length
      ? 'the trust boundary "' + ctx.crossingNames.join('" / "') + '"'
      : 'a trust boundary');
    if (extra) {
      Object.keys(extra).forEach(function (k) {
        out = out.replace(new RegExp('\\{' + k + '\\}', 'g'), extra[k]);
      });
    }
    return out;
  }

  /* ---------------------------------------------------------------------
   * Analysis
   * ------------------------------------------------------------------- */

  /**
   * Run the rule engine over a model.
   * @returns {{findings: Array, coverage: Array, gaps: Array, stats: Object}}
   */
  TM.analyze = function (model) {
    var findings = [];
    var gaps = [];
    var seq = 0;
    var profile = TM.scoringOf(model);
    var assessments = model.assessments || {};

    function assessmentFor(elementId, ruleId) {
      return assessments[TM.assessmentKey(elementId, ruleId)] || null;
    }

    var elements = model.nodes.filter(function (n) { return n.type !== 'boundary'; })
      .concat(model.flows);

    elements.forEach(function (el) {
      var ctx = buildContext(model, el);
      var applicable = TM.APPLICABILITY[el.type] || [];

      RULES.forEach(function (rule) {
        if (rule.types.indexOf(el.type) === -1) return;
        if (applicable.indexOf(rule.cat) === -1) return;
        var hit;
        try { hit = rule.test(el, ctx); } catch (e) { hit = false; }
        if (!hit) return;
        seq += 1;
        var assessment = assessmentFor(el.id, rule.id);
        findings.push({
          ref: 'T-' + pad(seq),
          ruleId: rule.id,
          elementId: el.id,
          elementType: el.type,
          elementLabel: TM.label(el),
          category: rule.cat,
          title: fill(rule.title, el, ctx),
          threat: fill(rule.threat, el, ctx),
          mitigations: rule.mitigations.slice(),
          baseRisk: rule.risk,
          severity: severityFor(profile, rule, el, ctx, rule.cat, assessment),
          cvss: assessment,
          existingControls: (el.existingControls || '').trim(),
          crossings: ctx.crossingNames.slice()
        });
      });

      /* Coverage gaps: categories the modeller has not answered. */
      var unanswered = TM.fieldsFor(el.type).filter(function (f) {
        return f.type !== 'text' && TM.isUnset(val(el, f.key));
      }).map(function (f) { return f.label; });
      if (unanswered.length) {
        gaps.push({
          elementId: el.id,
          elementLabel: TM.label(el),
          elementType: el.type,
          fields: unanswered,
          noDescription: !(el.description || '').trim()
        });
      }
    });

    /* Flow-derived findings attached to the receiving element. */
    model.flows.forEach(function (flow) {
      var ctx = buildContext(model, flow);
      var target = TM.nodeById(model, flow.to);
      var source = TM.nodeById(model, flow.from);
      if (!target || !source) return;
      FLOW_RULES.forEach(function (rule) {
        if (rule.targets.indexOf(target.type) === -1) return;
        if ((TM.APPLICABILITY[target.type] || []).indexOf(rule.cat) === -1) return;
        var hit;
        try { hit = rule.test(flow, ctx); } catch (e) { hit = false; }
        if (!hit) return;
        seq += 1;
        var extra = { flow: TM.label(flow), source: TM.label(source) };
        /* Keyed on the flow as well, so one rule can fire once per inbound flow. */
        var xRuleId = rule.id + ':' + flow.id;
        var xAssessment = assessmentFor(target.id, xRuleId);
        findings.push({
          ref: 'T-' + pad(seq),
          ruleId: xRuleId,
          elementId: target.id,
          elementType: target.type,
          elementLabel: TM.label(target),
          category: rule.cat,
          title: fill(rule.title, target, ctx, extra),
          threat: fill(rule.threat, target, ctx, extra),
          mitigations: rule.mitigations.slice(),
          baseRisk: rule.risk,
          severity: severityFor(profile, rule, target, ctx, rule.cat, xAssessment),
          cvss: xAssessment,
          existingControls: (target.existingControls || '').trim(),
          via: TM.label(flow),
          crossings: ctx.crossingNames.slice()
        });
      });
    });

    /* Model-level observations. */
    var notes = [];
    if (!model.nodes.some(function (n) { return n.type === 'boundary'; })) {
      notes.push('No trust boundary is drawn. STRIDE gets most of its value from what crosses a boundary - add at least one (internet edge, machine boundary, tenant, third party) and the flows crossing it will be analysed more strictly.');
    }
    var orphans = model.nodes.filter(function (n) {
      return n.type !== 'boundary' && n.type !== 'asset' && !TM.flowsFor(model, n.id).length;
    });
    if (orphans.length) {
      notes.push('Not connected by any data flow: ' + orphans.map(TM.label).join(', ') +
        '. An element with no flows has no attack surface in the diagram - either connect it or remove it.');
    }
    if (!model.flows.length && model.nodes.length) {
      notes.push('The diagram has no data flows yet. Threats live on the interactions, so the report will stay thin until the flows are drawn.');
    }

    /* Coverage matrix: element x STRIDE with finding counts. */
    var coverage = elements.map(function (el) {
      var row = { elementId: el.id, label: TM.label(el), type: el.type, cells: {} };
      TM.STRIDE_ORDER.forEach(function (c) {
        var applicable = (TM.APPLICABILITY[el.type] || []).indexOf(c) !== -1;
        var count = findings.filter(function (f) {
          return f.elementId === el.id && f.category === c;
        }).length;
        row.cells[c] = { applicable: applicable, count: count };
      });
      return row;
    });

    /* Severity levels present, highest first - the profile's own levels plus
       any CVSS band that only appears on a scored threat. */
    var levelIndex = {};
    profile.levels.forEach(function (lv) {
      levelIndex[lv.label] = { label: lv.label, color: lv.color, sort: lv.min, count: 0 };
    });
    var stats = { total: findings.length, byCategory: {}, byLevel: {}, scored: 0 };
    TM.STRIDE_ORDER.forEach(function (c) { stats.byCategory[c] = 0; });
    findings.forEach(function (f) {
      var label = f.severity.label;
      if (!levelIndex[label]) {
        levelIndex[label] = { label: label, color: f.severity.color, sort: f.severity.sort, count: 0 };
      }
      levelIndex[label].count += 1;
      stats.byCategory[f.category] += 1;
      if (f.cvss) stats.scored += 1;
    });
    stats.levels = Object.keys(levelIndex).map(function (k) { return levelIndex[k]; })
      .sort(function (a, b) { return b.sort - a.sort; });
    stats.levels.forEach(function (lv) { stats.byLevel[lv.label] = lv.count; });
    stats.elements = elements.length;
    stats.boundaries = model.nodes.filter(function (n) { return n.type === 'boundary'; }).length;
    stats.flows = model.flows.length;
    stats.assets = model.nodes.filter(function (n) { return n.type === 'asset' || n.isAsset; }).length;

    findings.sort(function (a, b) {
      var d = b.severity.sort - a.severity.sort;
      if (d) return d;
      return TM.STRIDE_ORDER.indexOf(a.category) - TM.STRIDE_ORDER.indexOf(b.category);
    });

    return {
      findings: findings, gaps: gaps, notes: notes, coverage: coverage,
      stats: stats, profile: profile
    };
  };

  function pad(n) { return (n < 10 ? '0' : '') + n; }

  /** Every rule id, so a scoring profile's overrides can be checked for typos. */
  TM.RULE_IDS = RULES.map(function (r) { return r.id; })
    .concat(FLOW_RULES.map(function (r) { return r.id; }));

  /** Rule metadata for the scoring editor: id, element types, category, base. */
  TM.ruleCatalogue = function () {
    return RULES.map(function (r) {
      return { id: r.id, types: r.types.slice(), category: r.cat, base: r.risk, title: r.title };
    }).concat(FLOW_RULES.map(function (r) {
      return { id: r.id, types: r.targets.slice(), category: r.cat, base: r.risk, title: r.title };
    }));
  };

  /** Exposed for the properties panel: which letters apply to a type. */
  TM.applicableCategories = function (type) {
    return (TM.APPLICABILITY[type] || []).map(function (k) { return TM.STRIDE[k]; });
  };

})(window.TM);
