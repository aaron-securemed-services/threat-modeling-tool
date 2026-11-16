/* ---------------------------------------------------------------------------
 * model.js - the threat model data structure, the category (field) catalogue
 * that every element can be annotated with, and load/save helpers.
 *
 * Everything hangs off the global `TM` namespace; the app is deliberately
 * build-free so it can be opened straight from disk in a classroom.
 * --------------------------------------------------------------------------- */
window.TM = window.TM || {};

(function (TM) {
  'use strict';

  TM.SCHEMA_VERSION = 1;

  /* ---------------------------------------------------------------------
   * Element types - these mirror the diagram legend.
   * ------------------------------------------------------------------- */
  TM.TYPES = {
    entity: {
      key: 'entity',
      label: 'Entity',
      article: 'an',
      shape: 'Sharp-cornered rectangle',
      legend: 'People, systems or components within the architectural system interface diagram.',
      defaultSize: { w: 160, h: 70 },
      defaultTitle: 'New entity'
    },
    process: {
      key: 'process',
      label: 'Process',
      article: 'a',
      shape: 'Circle or oval',
      legend: 'Any running code: compiled programs, scripts, shell commands, SQL, stored procedures, etc.',
      defaultSize: { w: 170, h: 90 },
      defaultTitle: 'New process'
    },
    datastore: {
      key: 'datastore',
      label: 'Data store',
      article: 'a',
      shape: 'Open-ended rectangle with solid lines top and bottom',
      legend: 'A data storage location: files, databases, shared memory, cloud storage, cookies, etc.',
      defaultSize: { w: 170, h: 72 },
      defaultTitle: 'New data store'
    },
    boundary: {
      key: 'boundary',
      label: 'Trust boundary',
      article: 'a',
      shape: 'Rectangle with red dashed outline',
      legend: 'A boundary of trust between different elements of the diagram.',
      defaultSize: { w: 380, h: 260 },
      defaultTitle: 'New trust boundary'
    },
    asset: {
      key: 'asset',
      label: 'Asset',
      article: 'an',
      shape: 'Triangle',
      legend: 'An asset we are protecting - informational or physical.',
      defaultSize: { w: 90, h: 78 },
      defaultTitle: 'New asset'
    },
    flow: {
      key: 'flow',
      label: 'Data flow',
      article: 'a',
      shape: 'Line with arrows',
      legend: 'Interactions between processes and data movement between entities. Arrows show direction.',
      defaultTitle: 'New data flow'
    }
  };

  /* Node types that live on the canvas as boxes (i.e. everything but flows). */
  TM.NODE_TYPES = ['boundary', 'entity', 'process', 'datastore', 'asset'];

  /* ---------------------------------------------------------------------
   * Patient safety
   *
   * A security threat to a medical device matters because of what it can do
   * to the patient. These are the safety-relevant functions an element can
   * carry; they decide which safety hazards are analysed for it, and they are
   * what the report traces back to the safety risk management file
   * (ISO 14971) so a security finding can be reconciled with a hazard.
   * ------------------------------------------------------------------- */
  TM.SAFETY_FUNCTIONS = [
    {
      key: 'control',
      label: 'Controls or actuates therapy / diagnosis',
      short: 'Device control',
      help: 'Issues, carries or executes commands that act on the patient: dose, rate, energy, motion, stimulation, imaging exposure.',
      harm: 'Unintended, altered or withheld therapy delivered to the patient.'
    },
    {
      key: 'alarm',
      label: 'Generates, carries or displays alarms',
      short: 'Alarms',
      help: 'Alarm conditions, thresholds, annunciation or escalation to a clinician.',
      harm: 'A real alarm is missed or suppressed, or false alarms drive alarm fatigue and unnecessary intervention.'
    },
    {
      key: 'safetyStop',
      label: 'Implements a safety stop, interlock or limit',
      short: 'Safety stop',
      help: 'Hard or soft limits, dose caps, watchdogs, emergency stop, fail-safe state, interlocks.',
      harm: 'The protective function does not engage, or engages when it should not, removing the last barrier before harm.'
    },
    {
      key: 'clinicalData',
      label: 'Produces clinical data used for decisions',
      short: 'Clinical data',
      help: 'Measurements, images, results or records a clinician acts on.',
      harm: 'A clinical decision is made on wrong, stale or missing data.'
    },
    {
      key: 'careDelivery',
      label: 'Needed for timely care delivery',
      short: 'Care delivery',
      help: 'Loss of this element delays or prevents treatment even though nothing is directly actuated.',
      harm: 'Care is delayed or cannot be delivered.'
    }
  ];

  TM.safetyFunction = function (key) {
    for (var i = 0; i < TM.SAFETY_FUNCTIONS.length; i++) {
      if (TM.SAFETY_FUNCTIONS[i].key === key) return TM.SAFETY_FUNCTIONS[i];
    }
    return null;
  };

  /** The safety functions an element declares. */
  TM.safetyFunctionsOf = function (el) {
    var v = el && el.props && el.props.safetyFunctions;
    return Array.isArray(v) ? v.filter(function (k) { return !!TM.safetyFunction(k); }) : [];
  };

  TM.hasSafetyRole = function (el) {
    return TM.safetyFunctionsOf(el).length > 0;
  };

  /** The security use cases an element is tagged with, as a clean list. */
  TM.useCasesOf = function (el) {
    var raw = String((el && el.props && el.props.useCases) || '');
    var seen = {}, out = [];
    raw.split(/[,;\n]/).forEach(function (part) {
      var name = part.trim().replace(/\s+/g, ' ');
      var k = name.toLowerCase();
      if (!name || seen[k]) return;
      seen[k] = true;
      out.push(name);
    });
    return out;
  };

  /** ISO 14971-style severity of harm, least to most severe. */
  TM.HARM_SEVERITY = [
    'None (no patient harm credible)',
    'Negligible — inconvenience or temporary discomfort',
    'Minor — temporary injury, no professional intervention',
    'Serious — injury needing professional intervention',
    'Critical — permanent impairment or life-threatening injury',
    'Catastrophic — patient death'
  ];

  /** Points a severity of harm contributes when scoring a safety threat. */
  TM.HARM_SEVERITY_POINTS = {
    'None (no patient harm credible)': 0,
    'Negligible — inconvenience or temporary discomfort': 0,
    'Minor — temporary injury, no professional intervention': 0.5,
    'Serious — injury needing professional intervention': 1,
    'Critical — permanent impairment or life-threatening injury': 1.5,
    'Catastrophic — patient death': 2
  };

  /* ---------------------------------------------------------------------
   * FDA premarket cybersecurity guidance
   *
   * "Cybersecurity in Medical Devices: Quality Management System
   * Considerations and Content of Premarket Submissions" (February 2026).
   * These tables are the vocabulary the report uses to show how a model
   * lines up with it. Section numbers are the guidance's own.
   * ------------------------------------------------------------------- */
  TM.FDA = {
    TITLE: 'Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions',
    ISSUED: 'February 2026',

    /* Section IV.B - what the design has to provide. */
    OBJECTIVES: [
      { key: 'authenticity', label: 'Authenticity, which includes integrity' },
      { key: 'authorization', label: 'Authorization' },
      { key: 'availability', label: 'Availability' },
      { key: 'confidentiality', label: 'Confidentiality' },
      { key: 'updatability', label: 'Secure and timely updatability and patchability' }
    ],

    /* Section V.B.1 and Appendix 1 - the control categories FDA expects
       requirements, implementation and test evidence for. */
    CONTROLS: [
      { key: 'authn', label: 'Authentication', ref: 'Appendix 1.A' },
      { key: 'authz', label: 'Authorization', ref: 'Appendix 1.B' },
      { key: 'crypto', label: 'Cryptography', ref: 'Appendix 1.C' },
      { key: 'integrity', label: 'Code, data and execution integrity', ref: 'Appendix 1.D' },
      { key: 'confidentiality', label: 'Confidentiality', ref: 'Appendix 1.E' },
      { key: 'logging', label: 'Event detection and logging', ref: 'Appendix 1.F' },
      { key: 'resilience', label: 'Resiliency and recovery', ref: 'Appendix 1.G' },
      { key: 'update', label: 'Firmware and software updates', ref: 'Appendix 1.H' }
    ],

    /* Section V.A.1 - the parts of the lifecycle a threat model should capture
       because a safety risk assessment tends to overlook them. */
    LIFECYCLE: [
      { key: 'supplyChain', label: 'Supply chain', prompt: 'Third-party and open-source components, build and signing infrastructure, suppliers.' },
      { key: 'manufacturing', label: 'Manufacturing', prompt: 'Key and credential provisioning, debug and test access, what leaves the factory enabled.' },
      { key: 'deployment', label: 'Deployment', prompt: 'Installation into the least secure network expected, default configuration and credentials, hardening.' },
      { key: 'interoperation', label: 'Interoperation', prompt: 'Other devices and accessories, healthcare infrastructure, general-purpose platforms, shared protocols.' },
      { key: 'maintenance', label: 'Maintenance and update', prompt: 'Patching, servicing, remote support, end of support of the device and of its components.' },
      { key: 'decommission', label: 'Decommission', prompt: 'Sanitising data and credentials at disposal, resale, return or repair; revoking the device identity.' }
    ],

    /* Section V.B.2 - the security architecture views. */
    VIEWS: [
      { key: 'global', label: 'Global system view', ref: 'V.B.2(a)' },
      { key: 'multiPatient', label: 'Multi-patient harm view', ref: 'V.B.2(b)' },
      { key: 'update', label: 'Updatability and patchability view', ref: 'V.B.2(c)' },
      { key: 'useCase', label: 'Security use case views', ref: 'V.B.2(d)' }
    ]
  };

  function byKey(list, key) {
    for (var i = 0; i < list.length; i++) if (list[i].key === key) return list[i];
    return null;
  }
  TM.FDA.objective = function (key) { return byKey(TM.FDA.OBJECTIVES, key); };
  TM.FDA.control = function (key) { return byKey(TM.FDA.CONTROLS, key); };
  TM.FDA.lifecycle = function (key) { return byKey(TM.FDA.LIFECYCLE, key); };

  /* The network assumption a model is analysed under (section V.A.1). */
  TM.NETWORK_HOSTILE = 'Hostile — an adversary can alter, drop and replay traffic';
  TM.NETWORK_TRUSTED = 'Trusted — internal networks are assumed benign';
  TM.NETWORK_ASSUMPTIONS = [TM.NETWORK_HOSTILE, TM.NETWORK_TRUSTED];

  /** True unless the model explicitly says internal networks are trusted. */
  TM.assumesHostileNetwork = function (model) {
    return !(model && model.meta && model.meta.networkAssumption === TM.NETWORK_TRUSTED);
  };

  /* The scale-of-compromise answers (section V.B.2(b)). */
  TM.SCOPE_SINGLE = 'Single device / single patient';
  TM.SCOPE_MULTI = 'Multiple devices or patients at once';

  /* ---------------------------------------------------------------------
   * Category catalogue.
   *
   * Each field: { key, label, help, type, options[], default, appliesTo[] }
   * The first option of a select is always the "unknown / not set" value so a
   * freshly drawn diagram reports honestly instead of pretending it is secure.
   * ------------------------------------------------------------------- */
  var UNSET = '— not set —';

  TM.FIELDS = [
    /* ---- shared ---- */
    {
      key: 'dataClassification',
      label: 'Data classification',
      group: 'Data',
      help: 'Sensitivity of the data this element holds, handles or carries. Drives the impact half of the risk rating.',
      options: [UNSET, 'Public', 'Internal', 'Confidential', 'Restricted (PII / PHI / PCI)'],
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },
    {
      key: 'criticality',
      label: 'Availability need',
      group: 'Data',
      help: 'How much the business hurts if this element is unavailable.',
      options: [UNSET, 'Low', 'Medium', 'High', 'Critical (safety / life)'],
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },

    /* ---- patient safety (medical device context) ---- */
    {
      key: 'safetyFunctions',
      label: 'Safety-relevant functions',
      group: 'Patient safety',
      type: 'multi',
      help: 'What this element does that can reach the patient. Tick everything that applies — each one is analysed for the safety hazards a security compromise could create.',
      options: TM.SAFETY_FUNCTIONS.map(function (f) {
        return { value: f.key, label: f.label, help: f.help };
      }),
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },
    {
      key: 'harmSeverity',
      label: 'Worst-case severity of harm',
      group: 'Patient safety',
      help: 'If a compromise here reaches the patient, how bad is the worst credible outcome? Use the same scale as your safety risk management file.',
      options: [UNSET].concat(TM.HARM_SEVERITY),
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },
    {
      key: 'softwareSafetyClass',
      label: 'Software safety class (IEC 62304)',
      group: 'Patient safety',
      help: 'The class assigned to this software item, if it is software.',
      options: [UNSET, 'Not software', 'Class A — no injury possible', 'Class B — non-serious injury possible', 'Class C — death or serious injury possible'],
      appliesTo: ['process', 'datastore', 'flow']
    },
    {
      key: 'safetyFileRef',
      label: 'Safety file reference',
      group: 'Patient safety',
      type: 'text',
      help: 'Hazard, hazardous situation or risk control IDs in the safety risk management file (e.g. HAZ-014, RC-032). Printed in the traceability matrix.',
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },
    {
      key: 'safetyNotes',
      label: 'Hazardous situation',
      group: 'Patient safety',
      type: 'textarea',
      help: 'In your own words: how does a compromise of this element reach the patient? Quoted in the safety traceability matrix.',
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },

    {
      key: 'harmScope',
      label: 'Scale of compromise',
      group: 'Patient safety',
      help: 'If this element is compromised, is one device and one patient affected, or many at once? Shared servers, update infrastructure, fleet-wide credentials and anything every device talks to are "multiple". Feeds the multi-patient harm view.',
      options: [UNSET, TM.SCOPE_SINGLE, TM.SCOPE_MULTI],
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    },
    /* ---- entity ---- */
    {
      key: 'entityKind',
      label: 'Entity kind',
      group: 'Classification',
      help: 'What sort of actor this is.',
      options: [UNSET, 'Human user', 'Privileged user / administrator', 'External system', 'Third-party service', 'Device / sensor', 'Internal component', 'Other medical device / accessory', 'Healthcare infrastructure (EHR, PACS, network)', 'General-purpose computing platform', 'Manufacturer infrastructure (update / cloud server)'],
      appliesTo: ['entity']
    },
    {
      key: 'trustLevel',
      label: 'Trust level',
      group: 'Classification',
      help: 'How much this actor is trusted before any control is applied.',
      options: [UNSET, 'Untrusted (anonymous)', 'Semi-trusted (authenticated)', 'Trusted (internal / managed)'],
      appliesTo: ['entity']
    },

    /* ---- process ---- */
    {
      key: 'exposure',
      label: 'Exposure',
      group: 'Classification',
      help: 'Where this runs and who can reach it.',
      options: [UNSET, 'Internet-facing', 'Partner / DMZ', 'Internal network', 'Isolated / offline'],
      appliesTo: ['process']
    },
    {
      key: 'privilege',
      label: 'Runtime privilege',
      group: 'Classification',
      help: 'The privilege the code itself runs with.',
      options: [UNSET, 'Least privilege', 'Elevated service account', 'Root / administrator'],
      appliesTo: ['process']
    },
    {
      key: 'inputValidation',
      label: 'Input validation',
      group: 'Controls',
      help: 'How untrusted input reaching this process is handled.',
      options: [UNSET, 'None', 'Partial / deny-list', 'Strict allow-list + output encoding'],
      appliesTo: ['process']
    },
    {
      key: 'resilience',
      label: 'Availability controls',
      group: 'Controls',
      help: 'Protection against resource exhaustion and flooding.',
      options: [UNSET, 'None', 'Timeouts only', 'Rate limiting / quotas', 'Rate limiting + autoscaling / WAF'],
      appliesTo: ['process']
    },

    {
      key: 'softwareOrigin',
      label: 'Software origin',
      group: 'Software supply chain and updates',
      help: 'Who wrote the software this process runs. Third-party and open-source components carry risks the manufacturer inherits and has to track.',
      options: [UNSET, 'Proprietary (manufacturer-developed)', 'Commercial off-the-shelf', 'Open source', 'Mixed — includes third-party components'],
      appliesTo: ['process']
    },
    {
      key: 'componentSupport',
      label: 'Component support status',
      group: 'Software supply chain and updates',
      help: 'Whether the software, and the components it is built from, still receive security fixes.',
      options: [UNSET, 'Actively maintained', 'No longer maintained (end of support)', 'Abandoned / unknown'],
      appliesTo: ['process']
    },
    {
      key: 'sbomRef',
      label: 'SBOM reference',
      group: 'Software supply chain and updates',
      type: 'text',
      help: 'The SBOM document and component entries this process traces to (e.g. SBOM-IP-2200 #14-22).',
      appliesTo: ['process']
    },
    {
      key: 'updateMechanism',
      label: 'Update mechanism',
      group: 'Software supply chain and updates',
      help: 'How this software is patched once the device is in the field.',
      options: [UNSET, 'Not updatable in the field', 'Unauthenticated (unsigned image, file, USB or service tool)', 'Signed updates, no rollback protection', 'Signed updates with rollback protection'],
      appliesTo: ['process']
    },
    {
      key: 'keyManagement',
      label: 'Keys and credentials held',
      group: 'Controls',
      help: 'How the secrets this process relies on are provisioned and stored. A secret that is the same on every device turns one compromised device into all of them.',
      options: [UNSET, 'No keys or credentials held', 'Hardcoded, default or shared across devices', 'Unique per device, stored in software', 'Unique per device, hardware-protected (secure element / TPM / HSM)'],
      appliesTo: ['process']
    },

    /* ---- data store ---- */
    {
      key: 'storeKind',
      label: 'Store kind',
      group: 'Classification',
      help: 'What kind of storage this is.',
      options: [UNSET, 'Relational database', 'NoSQL / document store', 'File share', 'Object / blob storage', 'Cache / in-memory', 'Message queue', 'Browser cookie / local storage', 'Backup / archive', 'Physical media / paper'],
      appliesTo: ['datastore']
    },
    {
      key: 'encryptionAtRest',
      label: 'Encryption at rest',
      group: 'Controls',
      options: [UNSET, 'None', 'Full-disk / volume', 'Field or column level', 'Field level + managed KMS / HSM'],
      appliesTo: ['datastore']
    },
    {
      key: 'integrity',
      label: 'Integrity controls',
      group: 'Controls',
      help: 'What stops silent modification of stored data. A CRC or plain checksum detects noise, not an attacker.',
      options: [UNSET, 'None', 'Constraints / checksums', 'Signed or immutable (WORM)'],
      appliesTo: ['datastore']
    },
    {
      key: 'backup',
      label: 'Backup / recovery',
      group: 'Controls',
      options: [UNSET, 'None', 'Backups, never tested', 'Tested backups with retention'],
      appliesTo: ['datastore']
    },

    /* ---- flow ---- */
    {
      key: 'protocol',
      label: 'Protocol',
      group: 'Classification',
      help: 'The transport this flow uses.',
      options: [UNSET, 'HTTPS / TLS', 'HTTP (cleartext)', 'gRPC over TLS', 'SQL / database protocol', 'AMQP / Kafka / queue', 'MQTT', 'HL7 / DICOM / FHIR', 'SMB / NFS file share', 'SFTP / SSH', 'FTP / Telnet (cleartext)', 'Email / SMTP', 'Bluetooth / BLE', 'NFC / RFID / proprietary RF', 'USB / serial', 'Physical / manual transfer', 'Other'],
      appliesTo: ['flow']
    },
    {
      key: 'protocolDetail',
      label: 'Protocol detail',
      group: 'Classification',
      type: 'text',
      help: 'Version, port, channel or frequency, and the cipher or key length where one applies (e.g. TLS 1.3, tcp/8883, ECDHE-P256 + AES-256-GCM).',
      appliesTo: ['flow']
    },
    {
      key: 'carries',
      label: 'Carries',
      group: 'Classification',
      type: 'multi',
      help: 'What moves along this path. Code and commands need stronger protection than data: the receiver acts on them.',
      options: [
        { value: 'data', label: 'Data', help: 'Measurements, records, telemetry, logs.' },
        { value: 'code', label: 'Code', help: 'Software, firmware, configuration or scripts the receiver loads or executes.' },
        { value: 'commands', label: 'Commands', help: 'Instructions that change what the receiver does.' }
      ],
      appliesTo: ['flow']
    },
    {
      key: 'interfaceState',
      label: 'Interface state',
      group: 'Classification',
      help: 'Whether this path is part of normal use. Service, debug and dormant interfaces are attack surface too, and are the ones most often forgotten.',
      options: [UNSET, 'In use for the intended use', 'Service / maintenance only', 'Debug / test interface', 'Built in but unused / dormant'],
      appliesTo: ['flow']
    },
    {
      key: 'encryptionInTransit',
      label: 'Encryption in transit',
      group: 'Controls',
      options: [UNSET, 'None (cleartext)', 'TLS (server authenticated)', 'Mutual TLS', 'Message-level encryption'],
      appliesTo: ['flow']
    },
    {
      key: 'flowIntegrity',
      label: 'Message integrity',
      group: 'Controls',
      help: 'What proves the message was not altered in flight.',
      options: [UNSET, 'None', 'Transport (TLS) only', 'Message signature / MAC'],
      appliesTo: ['flow']
    },
    {
      key: 'replayProtection',
      label: 'Replay protection',
      group: 'Controls',
      help: 'What stops a captured message being sent again later.',
      options: [UNSET, 'None', 'Timestamp or sequence number', 'Cryptographic nonce / session-bound', 'Not applicable — not a replayable channel'],
      appliesTo: ['flow']
    },
    {
      key: 'throttling',
      label: 'Throttling',
      group: 'Controls',
      help: 'Whether this flow can be flooded.',
      options: [UNSET, 'None', 'Timeouts only', 'Rate limited / throttled'],
      appliesTo: ['flow']
    },

    /* ---- asset ---- */
    {
      key: 'assetKind',
      label: 'Asset kind',
      group: 'Classification',
      options: [UNSET, 'Information', 'Credential / secret', 'Physical', 'Service / capability', 'Reputation / compliance'],
      appliesTo: ['asset']
    },
    {
      key: 'owner',
      label: 'Owner',
      group: 'Classification',
      help: 'Team or person accountable for this asset.',
      type: 'text',
      appliesTo: ['asset', 'process', 'datastore', 'entity']
    },

    /* ---- boundary ---- */
    {
      key: 'boundaryKind',
      label: 'Boundary kind',
      group: 'Classification',
      options: [UNSET, 'Internet / DMZ perimeter', 'Network segment', 'Machine / process boundary', 'Container or VM', 'Privilege level', 'Tenant / customer', 'Third-party or vendor', 'Physical / facility'],
      appliesTo: ['boundary']
    },

    /* ---- controls shared by process / datastore / flow / entity ---- */
    {
      key: 'authentication',
      label: 'Authentication',
      group: 'Controls',
      help: 'How the identity of the caller (or user) is proven.',
      options: [UNSET, 'None / anonymous', 'Shared secret or API key', 'Username + password', 'Session token / JWT', 'SSO / federated', 'Multi-factor', 'Client certificate (mTLS)'],
      appliesTo: ['entity', 'process', 'datastore', 'flow']
    },
    {
      key: 'authorization',
      label: 'Authorization',
      group: 'Controls',
      help: 'How access decisions are made once identity is known.',
      options: [UNSET, 'None', 'Shared credential for everyone', 'Simple ownership check', 'Role-based (RBAC)', 'Attribute / policy based, deny by default'],
      appliesTo: ['process', 'datastore', 'flow']
    },
    {
      key: 'logging',
      label: 'Logging / audit',
      group: 'Controls',
      help: 'Evidence available after the fact. Drives the Repudiation analysis.',
      options: [UNSET, 'None', 'Errors only', 'Security events logged', 'Full audit trail, tamper-evident'],
      appliesTo: ['entity', 'process', 'datastore', 'flow']
    },

    /* ---- architecture views ---- */
    {
      key: 'useCases',
      label: 'Security use cases',
      group: 'Architecture views',
      type: 'text',
      help: 'The clinical or operational use cases this element takes part in, comma separated (e.g. Programming, Alarming, Software update). The report builds one security use case view per name.',
      appliesTo: ['entity', 'process', 'datastore', 'flow', 'asset']
    }
  ];

  /** All field definitions that apply to a given element type. */
  TM.fieldsFor = function (type) {
    return TM.FIELDS.filter(function (f) { return f.appliesTo.indexOf(type) !== -1; });
  };

  TM.fieldDef = function (key) {
    for (var i = 0; i < TM.FIELDS.length; i++) {
      if (TM.FIELDS[i].key === key) return TM.FIELDS[i];
    }
    return null;
  };

  TM.UNSET = UNSET;

  /** True when a category has not been answered yet. */
  TM.isUnset = function (value) {
    if (Array.isArray(value)) return value.length === 0;
    return value === undefined || value === null || value === '' || value === UNSET;
  };

  /* ---------------------------------------------------------------------
   * Model construction
   * ------------------------------------------------------------------- */
  var idCounter = 0;
  TM.newId = function (prefix) {
    idCounter += 1;
    return (prefix || 'el') + '-' + Date.now().toString(36) + '-' + idCounter.toString(36);
  };

  TM.emptyModel = function () {
    return {
      schemaVersion: TM.SCHEMA_VERSION,
      meta: {
        name: '',
        system: '',
        author: '',
        date: new Date().toISOString().slice(0, 10),
        scope: '',
        /* The safety risk management file this security analysis feeds. */
        safetyDoc: '',
        safetyDocRef: '',
        intendedUse: '',
        /* What FDA asks a threat model to state (section V.A.1). */
        environment: '',
        assumptions: '',
        networkAssumption: TM.NETWORK_HOSTILE,
        methodologyRationale: '',
        acceptanceCriteria: '',
        acceptableResidual: '',
        /* Lifecycle notes, keyed by TM.FDA.LIFECYCLE */
        lifecycle: {}
      },
      nodes: [],
      flows: [],
      /* null = use the built-in qualitative scale */
      scoring: null,
      /* per-threat CVSS assessments, keyed "<elementId>::<ruleId>" */
      assessments: {},
      /* per-threat risk treatment (control, residual risk, evidence), same keys */
      treatments: {}
    };
  };

  TM.makeNode = function (type, x, y) {
    var def = TM.TYPES[type];
    var size = def.defaultSize;
    return {
      id: TM.newId(type),
      type: type,
      x: Math.round(x - size.w / 2),
      y: Math.round(y - size.h / 2),
      w: size.w,
      h: size.h,
      title: def.defaultTitle,
      description: '',
      isAsset: false,
      existingControls: '',
      props: {}
    };
  };

  TM.makeFlow = function (fromId, toId) {
    return {
      id: TM.newId('flow'),
      type: 'flow',
      from: fromId,
      to: toId,
      bidirectional: false,
      title: 'New data flow',
      description: '',
      isAsset: false,
      existingControls: '',
      props: {}
    };
  };

  /* ---------------------------------------------------------------------
   * Lookup + geometry helpers shared by the diagram and the report
   * ------------------------------------------------------------------- */
  TM.nodeById = function (model, id) {
    for (var i = 0; i < model.nodes.length; i++) {
      if (model.nodes[i].id === id) return model.nodes[i];
    }
    return null;
  };

  TM.elementById = function (model, id) {
    var n = TM.nodeById(model, id);
    if (n) return n;
    for (var i = 0; i < model.flows.length; i++) {
      if (model.flows[i].id === id) return model.flows[i];
    }
    return null;
  };

  TM.label = function (el) {
    if (!el) return '(missing element)';
    var t = (el.title || '').trim();
    return t || ('Untitled ' + TM.TYPES[el.type].label.toLowerCase());
  };

  TM.center = function (node) {
    return { x: node.x + node.w / 2, y: node.y + node.h / 2 };
  };

  /** The trust boundaries whose rectangle contains the centre of `node`. */
  TM.boundariesContaining = function (model, node) {
    if (!node) return [];
    var c = TM.center(node);
    return model.nodes.filter(function (b) {
      return b.type === 'boundary' &&
        c.x >= b.x && c.x <= b.x + b.w &&
        c.y >= b.y && c.y <= b.y + b.h;
    });
  };

  /**
   * Trust boundaries that a flow crosses: any boundary containing exactly one
   * of the two endpoints. Crossing a boundary is what makes a flow interesting,
   * so this is computed from geometry rather than asked of the user.
   */
  TM.boundariesCrossed = function (model, flow) {
    var from = TM.nodeById(model, flow.from);
    var to = TM.nodeById(model, flow.to);
    if (!from || !to) return [];
    var a = TM.boundariesContaining(model, from).map(function (b) { return b.id; });
    var b = TM.boundariesContaining(model, to).map(function (x) { return x.id; });
    var crossed = [];
    model.nodes.forEach(function (n) {
      if (n.type !== 'boundary') return;
      var inA = a.indexOf(n.id) !== -1;
      var inB = b.indexOf(n.id) !== -1;
      if (inA !== inB) crossed.push(n);
    });
    return crossed;
  };

  /** Flows touching a node, in either direction. */
  TM.flowsFor = function (model, nodeId) {
    return model.flows.filter(function (f) { return f.from === nodeId || f.to === nodeId; });
  };

  /* ---------------------------------------------------------------------
   * Severity scoring profiles
   *
   * Every rule carries a base rating; the engine turns that into a number,
   * adds points for aggravating diagram context, subtracts points for
   * mitigating context, and maps the result onto a named level. All of those
   * numbers live in a profile, so an organisation can import its own scale
   * instead of arguing with the built-in one.
   * ------------------------------------------------------------------- */
  TM.DEFAULT_SCORING = {
    name: 'Built-in qualitative scale',
    description: 'Rule base rating adjusted by the diagram context.',
    levels: [
      { label: 'Info', color: '#7d8ba6', min: 0 },
      { label: 'Low', color: '#3f9c63', min: 2 },
      { label: 'Medium', color: '#cbb01f', min: 3 },
      { label: 'High', color: '#e07b1a', min: 4 },
      { label: 'Critical', color: '#c62828', min: 5.5 }
    ],
    baseScores: { info: 1, low: 2, medium: 3, high: 4, critical: 6 },
    ruleScores: {},
    categoryPoints: { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 },
    aggravatorPoints: {
      patientSafety: 0.5,        /* the threat can reach the patient */
      sensitiveData: 0.5,        /* confidential or regulated data */
      externalExposure: 0.5,     /* internet / anonymous facing, or an external boundary crossing */
      markedAsset: 0.5,          /* the element is flagged as an asset */
      safetyCriticalDoS: 0.5,    /* availability threat against a safety-critical element */
      multiPatientHarm: 0.5      /* a compromise reaches many devices or patients at once */
    },
    mitigatorPoints: {
      publicData: 0.5,
      lowAvailabilityNeed: 0.5
    },
    /* Extra points for a patient-safety threat, by worst-case severity of harm. */
    harmSeverityPoints: null,    /* filled from TM.HARM_SEVERITY_POINTS below */
    cvss: { useWhenPresent: true }
  };
  TM.DEFAULT_SCORING.harmSeverityPoints = TM.HARM_SEVERITY_POINTS;

  var AGGRAVATORS = ['patientSafety', 'sensitiveData', 'externalExposure', 'markedAsset', 'safetyCriticalDoS', 'multiPatientHarm'];
  var MITIGATORS = ['publicData', 'lowAvailabilityNeed'];

  function isNum(v) { return typeof v === 'number' && isFinite(v); }

  /**
   * Validate and fill in a user-supplied scoring profile.
   * @returns {{profile: Object|null, errors: string[]}}
   */
  TM.validateScoring = function (raw) {
    var errors = [];
    var warnings = [];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { profile: null, errors: ['The profile must be a JSON object.'], warnings: warnings };
    }
    var d = TM.DEFAULT_SCORING;
    var p = {
      name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : 'Custom scale',
      description: typeof raw.description === 'string' ? raw.description : '',
      levels: [],
      baseScores: {},
      ruleScores: {},
      categoryPoints: {},
      aggravatorPoints: {},
      mitigatorPoints: {},
      cvss: { useWhenPresent: true }
    };

    /* levels */
    if (!Array.isArray(raw.levels) || raw.levels.length < 2) {
      errors.push('"levels" must be an array of at least two levels, each { label, color, min }.');
    } else {
      raw.levels.forEach(function (lv, i) {
        if (!lv || typeof lv !== 'object') { errors.push('Level ' + (i + 1) + ' is not an object.'); return; }
        if (typeof lv.label !== 'string' || !lv.label.trim()) { errors.push('Level ' + (i + 1) + ' needs a "label".'); return; }
        if (!isNum(lv.min)) { errors.push('Level "' + lv.label + '" needs a numeric "min".'); return; }
        var color = typeof lv.color === 'string' && /^#[0-9a-fA-F]{3,8}$/.test(lv.color.trim())
          ? lv.color.trim() : '#7d8ba6';
        if (typeof lv.color === 'string' && color !== lv.color.trim()) {
          errors.push('Level "' + lv.label + '" has an invalid colour; expected a hex value like #c62828.');
        }
        p.levels.push({ label: lv.label.trim(), color: color, min: lv.min });
      });
      p.levels.sort(function (a, b) { return a.min - b.min; });
      for (var i = 1; i < p.levels.length; i++) {
        if (p.levels[i].min === p.levels[i - 1].min) {
          errors.push('Levels "' + p.levels[i - 1].label + '" and "' + p.levels[i].label + '" share the same "min" value.');
        }
      }
    }

    /* base scores */
    ['info', 'low', 'medium', 'high', 'critical'].forEach(function (k) {
      var v = raw.baseScores && raw.baseScores[k];
      if (v === undefined) { p.baseScores[k] = d.baseScores[k]; return; }
      if (!isNum(v)) { errors.push('baseScores.' + k + ' must be a number.'); p.baseScores[k] = d.baseScores[k]; return; }
      p.baseScores[k] = v;
    });

    /* per-rule overrides */
    if (raw.ruleScores !== undefined) {
      if (!raw.ruleScores || typeof raw.ruleScores !== 'object') {
        errors.push('"ruleScores" must be an object of ruleId -> number.');
      } else {
        Object.keys(raw.ruleScores).forEach(function (k) {
          if (!isNum(raw.ruleScores[k])) { errors.push('ruleScores.' + k + ' must be a number.'); return; }
          p.ruleScores[k] = raw.ruleScores[k];
        });
      }
    }

    /* per-category points */
    TM.STRIDE_ORDER.forEach(function (c) {
      var v = raw.categoryPoints && raw.categoryPoints[c];
      if (v === undefined) { p.categoryPoints[c] = 0; return; }
      if (!isNum(v)) { errors.push('categoryPoints.' + c + ' must be a number.'); p.categoryPoints[c] = 0; return; }
      p.categoryPoints[c] = v;
    });

    /* context points */
    AGGRAVATORS.forEach(function (k) {
      var v = raw.aggravatorPoints && raw.aggravatorPoints[k];
      if (v === undefined) { p.aggravatorPoints[k] = d.aggravatorPoints[k]; return; }
      if (!isNum(v)) { errors.push('aggravatorPoints.' + k + ' must be a number.'); p.aggravatorPoints[k] = d.aggravatorPoints[k]; return; }
      p.aggravatorPoints[k] = v;
    });
    MITIGATORS.forEach(function (k) {
      var v = raw.mitigatorPoints && raw.mitigatorPoints[k];
      if (v === undefined) { p.mitigatorPoints[k] = d.mitigatorPoints[k]; return; }
      if (!isNum(v)) { errors.push('mitigatorPoints.' + k + ' must be a number.'); p.mitigatorPoints[k] = d.mitigatorPoints[k]; return; }
      p.mitigatorPoints[k] = v;
    });

    /* severity-of-harm weighting */
    p.harmSeverityPoints = {};
    TM.HARM_SEVERITY.forEach(function (level) {
      var v = raw.harmSeverityPoints && raw.harmSeverityPoints[level];
      if (v === undefined) { p.harmSeverityPoints[level] = TM.HARM_SEVERITY_POINTS[level]; return; }
      if (!isNum(v)) {
        errors.push('harmSeverityPoints["' + level + '"] must be a number.');
        p.harmSeverityPoints[level] = TM.HARM_SEVERITY_POINTS[level];
        return;
      }
      p.harmSeverityPoints[level] = v;
    });
    if (raw.harmSeverityPoints && typeof raw.harmSeverityPoints === 'object') {
      Object.keys(raw.harmSeverityPoints).forEach(function (k) {
        if (TM.HARM_SEVERITY.indexOf(k) === -1) {
          warnings.push('harmSeverityPoints["' + k + '"] is not one of the severity-of-harm levels, so it will be ignored.');
        }
      });
    }

    if (raw.cvss && typeof raw.cvss === 'object' && raw.cvss.useWhenPresent !== undefined) {
      p.cvss.useWhenPresent = !!raw.cvss.useWhenPresent;
    }

    /* An unknown rule id is a typo worth surfacing, but not a reason to
       reject an otherwise valid profile. */
    Object.keys(p.ruleScores).forEach(function (id) {
      if (TM.RULE_IDS && TM.RULE_IDS.indexOf(id) === -1) {
        warnings.push('ruleScores."' + id + '" does not match any rule id, so it will have no effect.');
      }
    });

    return { profile: errors.length ? null : p, errors: errors, warnings: warnings };
  };

  /** The profile in force for a model. */
  TM.scoringOf = function (model) {
    return (model && model.scoring) || TM.DEFAULT_SCORING;
  };

  /** Map a numeric score onto the highest level whose threshold it reaches. */
  TM.levelForScore = function (profile, score) {
    var levels = profile.levels;
    var chosen = levels[0];
    for (var i = 0; i < levels.length; i++) {
      if (score >= levels[i].min) chosen = levels[i];
    }
    return chosen;
  };

  TM.SCORING_AGGRAVATORS = AGGRAVATORS;
  TM.SCORING_MITIGATORS = MITIGATORS;

  /* ---------------------------------------------------------------------
   * CVSS v4.0
   *
   * The vector is validated in full; the score itself is entered by the user
   * from the official calculator at
   * https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator - this tool does not
   * reimplement the CVSS scoring tables.
   * ------------------------------------------------------------------- */
  var CVSS4_METRICS = {
    /* Base - all mandatory */
    AV: { name: 'Attack Vector', values: ['N', 'A', 'L', 'P'], required: true },
    AC: { name: 'Attack Complexity', values: ['L', 'H'], required: true },
    AT: { name: 'Attack Requirements', values: ['N', 'P'], required: true },
    PR: { name: 'Privileges Required', values: ['N', 'L', 'H'], required: true },
    UI: { name: 'User Interaction', values: ['N', 'P', 'A'], required: true },
    VC: { name: 'Vulnerable System Confidentiality', values: ['H', 'L', 'N'], required: true },
    VI: { name: 'Vulnerable System Integrity', values: ['H', 'L', 'N'], required: true },
    VA: { name: 'Vulnerable System Availability', values: ['H', 'L', 'N'], required: true },
    SC: { name: 'Subsequent System Confidentiality', values: ['H', 'L', 'N'], required: true },
    SI: { name: 'Subsequent System Integrity', values: ['H', 'L', 'N'], required: true },
    SA: { name: 'Subsequent System Availability', values: ['H', 'L', 'N'], required: true },
    /* Threat */
    E: { name: 'Exploit Maturity', values: ['X', 'A', 'P', 'U'] },
    /* Environmental */
    CR: { name: 'Confidentiality Requirement', values: ['X', 'H', 'M', 'L'] },
    IR: { name: 'Integrity Requirement', values: ['X', 'H', 'M', 'L'] },
    AR: { name: 'Availability Requirement', values: ['X', 'H', 'M', 'L'] },
    MAV: { name: 'Modified Attack Vector', values: ['X', 'N', 'A', 'L', 'P'] },
    MAC: { name: 'Modified Attack Complexity', values: ['X', 'L', 'H'] },
    MAT: { name: 'Modified Attack Requirements', values: ['X', 'N', 'P'] },
    MPR: { name: 'Modified Privileges Required', values: ['X', 'N', 'L', 'H'] },
    MUI: { name: 'Modified User Interaction', values: ['X', 'N', 'P', 'A'] },
    MVC: { name: 'Modified Vulnerable System Confidentiality', values: ['X', 'H', 'L', 'N'] },
    MVI: { name: 'Modified Vulnerable System Integrity', values: ['X', 'H', 'L', 'N'] },
    MVA: { name: 'Modified Vulnerable System Availability', values: ['X', 'H', 'L', 'N'] },
    MSC: { name: 'Modified Subsequent System Confidentiality', values: ['X', 'H', 'L', 'N'] },
    MSI: { name: 'Modified Subsequent System Integrity', values: ['X', 'S', 'H', 'L', 'N'] },
    MSA: { name: 'Modified Subsequent System Availability', values: ['X', 'S', 'H', 'L', 'N'] },
    /* Supplemental */
    S: { name: 'Safety', values: ['X', 'N', 'P'] },
    AU: { name: 'Automatable', values: ['X', 'N', 'Y'] },
    R: { name: 'Recovery', values: ['X', 'A', 'U', 'I'] },
    V: { name: 'Value Density', values: ['X', 'D', 'C'] },
    RE: { name: 'Vulnerability Response Effort', values: ['X', 'L', 'M', 'H'] },
    U: { name: 'Provider Urgency', values: ['X', 'Clear', 'Green', 'Amber', 'Red'] }
  };

  TM.CVSS4 = {
    CALCULATOR_URL: 'https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator',
    METRICS: CVSS4_METRICS,

    /**
     * Validate a CVSS:4.0 vector string.
     * @returns {{ok: boolean, metrics: Object, errors: string[], vector: string}}
     */
    parse: function (input) {
      var errors = [];
      var vector = String(input || '').trim().replace(/\s+/g, '');
      var metrics = {};
      if (!vector) return { ok: false, metrics: metrics, errors: ['Enter a CVSS v4.0 vector string.'], vector: vector };

      var parts = vector.split('/');
      if (parts[0] !== 'CVSS:4.0') {
        return { ok: false, metrics: metrics, errors: ['A CVSS v4.0 vector must start with "CVSS:4.0/".'], vector: vector };
      }
      for (var i = 1; i < parts.length; i++) {
        var seg = parts[i];
        if (!seg) continue;
        var idx = seg.indexOf(':');
        if (idx === -1) { errors.push('"' + seg + '" is not a metric:value pair.'); continue; }
        var key = seg.slice(0, idx);
        var value = seg.slice(idx + 1);
        var def = CVSS4_METRICS[key];
        if (!def) { errors.push('Unknown metric "' + key + '".'); continue; }
        if (metrics[key] !== undefined) { errors.push('Metric "' + key + '" appears more than once.'); continue; }
        if (def.values.indexOf(value) === -1) {
          errors.push('"' + value + '" is not valid for ' + key + ' (' + def.name + '). Expected one of: ' + def.values.join(', ') + '.');
          continue;
        }
        metrics[key] = value;
      }
      Object.keys(CVSS4_METRICS).forEach(function (key) {
        if (CVSS4_METRICS[key].required && metrics[key] === undefined) {
          errors.push('Missing mandatory base metric ' + key + ' (' + CVSS4_METRICS[key].name + ').');
        }
      });
      return { ok: errors.length === 0, metrics: metrics, errors: errors, vector: vector };
    },

    /** Qualitative severity band for a CVSS v4.0 numeric score. */
    band: function (score) {
      var s = Number(score);
      if (!isFinite(s) || s < 0 || s > 10) return null;
      if (s === 0) return 'None';
      if (s < 4) return 'Low';
      if (s < 7) return 'Medium';
      if (s < 9) return 'High';
      return 'Critical';
    },

    BAND_COLORS: {
      None: '#7d8ba6', Low: '#3f9c63', Medium: '#cbb01f', High: '#e07b1a', Critical: '#c62828'
    },

    color: function (bandName) {
      return TM.CVSS4.BAND_COLORS[bandName] || '#7d8ba6';
    },

    /**
     * Validate a user-entered assessment (vector + score).
     * @returns {{ok: boolean, assessment: Object|null, errors: string[]}}
     */
    makeAssessment: function (vector, score, rationale) {
      var parsed = TM.CVSS4.parse(vector);
      var errors = parsed.errors.slice();
      var s = Number(String(score).trim());
      if (String(score).trim() === '' || !isFinite(s)) {
        errors.push('Enter the base score from the calculator, between 0.0 and 10.0.');
      } else if (s < 0 || s > 10) {
        errors.push('A CVSS score must be between 0.0 and 10.0.');
      }
      if (errors.length) return { ok: false, assessment: null, errors: errors };
      return {
        ok: true,
        errors: [],
        assessment: {
          vector: parsed.vector,
          score: Math.round(s * 10) / 10,
          severity: TM.CVSS4.band(s),
          rationale: String(rationale || '').trim(),
          updated: new Date().toISOString().slice(0, 10)
        }
      };
    }
  };

  /* ---------------------------------------------------------------------
   * Risk treatment
   *
   * The engine rates a threat as it stands on the diagram: the pre-mitigation
   * risk. A treatment records what was decided about it - the control, the
   * residual (post-mitigation) risk, the reasoning and the evidence - which is
   * what a cybersecurity risk assessment has to show (FDA section V.A.2).
   * ------------------------------------------------------------------- */
  TM.TREATMENT_OPEN = 'Open';
  TM.TREATMENT_STATUSES = [
    { label: 'Mitigated by design', needs: 'control' },
    { label: 'Mitigated by compensating control', needs: 'control' },
    { label: 'Transferred to the user (disclosed in labeling)', needs: 'rationale' },
    { label: 'Accepted', needs: 'rationale' },
    { label: 'Not applicable', needs: 'rationale' }
  ];

  TM.treatmentStatus = function (label) {
    for (var i = 0; i < TM.TREATMENT_STATUSES.length; i++) {
      if (TM.TREATMENT_STATUSES[i].label === label) return TM.TREATMENT_STATUSES[i];
    }
    return null;
  };

  /**
   * Validate a user-entered treatment.
   * @param levels the severity level labels of the scoring profile in force
   * @returns {{ok: boolean, treatment: Object|null, errors: string[]}}
   */
  TM.makeTreatment = function (raw, levels) {
    raw = raw || {};
    var errors = [];
    var status = TM.treatmentStatus(String(raw.status || '').trim());
    var control = String(raw.control || '').trim();
    var rationale = String(raw.rationale || '').trim();
    var evidence = String(raw.evidence || '').trim();
    var residual = String(raw.residual || '').trim();

    if (!status) {
      errors.push('Choose what was decided about this threat.');
    } else {
      if (status.needs === 'control' && !control) {
        errors.push('Name the control or security requirement that mitigates it.');
      }
      if (status.needs === 'rationale' && !rationale) {
        errors.push('Give the rationale: "' + status.label + '" is a decision somebody has to be able to defend.');
      }
      if (status.label !== 'Not applicable' && !residual) {
        errors.push('Rate the residual risk that remains after this decision.');
      }
    }
    if (residual && levels && levels.indexOf(residual) === -1) {
      errors.push('"' + residual + '" is not a level of the severity scale in force.');
    }
    if (errors.length) return { ok: false, treatment: null, errors: errors };
    return {
      ok: true,
      errors: [],
      treatment: {
        status: status.label,
        control: control,
        residual: status.label === 'Not applicable' ? '' : residual,
        rationale: rationale,
        evidence: evidence,
        updated: new Date().toISOString().slice(0, 10)
      }
    };
  };

  /** Key under which a threat's CVSS assessment is stored. */
  TM.assessmentKey = function (elementId, ruleId) {
    return elementId + '::' + ruleId;
  };

  /* ---------------------------------------------------------------------
   * Serialisation
   * ------------------------------------------------------------------- */
  TM.serialize = function (model) {
    return JSON.stringify(model, null, 2);
  };

  /** Parse + repair a saved model. Throws on structurally invalid input. */
  TM.deserialize = function (text) {
    var raw = JSON.parse(text);
    if (!raw || typeof raw !== 'object') throw new Error('Not a threat model file.');
    if (!Array.isArray(raw.nodes) || !Array.isArray(raw.flows)) {
      throw new Error('File is missing the nodes/flows arrays.');
    }
    var model = TM.emptyModel();
    model.meta = Object.assign(model.meta, raw.meta || {});
    if (TM.NETWORK_ASSUMPTIONS.indexOf(model.meta.networkAssumption) === -1) {
      model.meta.networkAssumption = TM.NETWORK_HOSTILE;
    }
    if (!model.meta.lifecycle || typeof model.meta.lifecycle !== 'object') model.meta.lifecycle = {};

    if (raw.scoring) {
      var checked = TM.validateScoring(raw.scoring);
      /* A broken profile in a file must not stop the model from opening. */
      model.scoring = checked.profile;
      model.scoringErrors = checked.errors;
    }
    if (raw.assessments && typeof raw.assessments === 'object') {
      Object.keys(raw.assessments).forEach(function (key) {
        var a = raw.assessments[key];
        if (!a || typeof a !== 'object') return;
        var made = TM.CVSS4.makeAssessment(a.vector, a.score, a.rationale);
        if (made.ok) {
          made.assessment.updated = str(a.updated) || made.assessment.updated;
          model.assessments[key] = made.assessment;
        }
      });
    }
    if (raw.treatments && typeof raw.treatments === 'object') {
      Object.keys(raw.treatments).forEach(function (key) {
        var t = raw.treatments[key];
        if (!t || typeof t !== 'object' || !TM.treatmentStatus(t.status)) return;
        /* Kept as written: a residual level that a later change of scoring
           profile no longer defines is still the decision that was recorded. */
        model.treatments[key] = {
          status: t.status,
          control: str(t.control), residual: str(t.residual),
          rationale: str(t.rationale), evidence: str(t.evidence),
          updated: str(t.updated)
        };
      });
    }
    model.nodes = raw.nodes.filter(function (n) {
      return n && TM.TYPES[n.type] && TM.NODE_TYPES.indexOf(n.type) !== -1;
    }).map(function (n) {
      return {
        id: n.id || TM.newId(n.type),
        type: n.type,
        x: num(n.x, 40), y: num(n.y, 40),
        w: num(n.w, TM.TYPES[n.type].defaultSize.w),
        h: num(n.h, TM.TYPES[n.type].defaultSize.h),
        title: str(n.title), description: str(n.description),
        isAsset: !!n.isAsset,
        existingControls: str(n.existingControls),
        props: n.props && typeof n.props === 'object' ? n.props : {}
      };
    });
    var ids = model.nodes.map(function (n) { return n.id; });
    model.flows = raw.flows.filter(function (f) {
      return f && ids.indexOf(f.from) !== -1 && ids.indexOf(f.to) !== -1;
    }).map(function (f) {
      return {
        id: f.id || TM.newId('flow'),
        type: 'flow',
        from: f.from, to: f.to,
        bidirectional: !!f.bidirectional,
        title: str(f.title), description: str(f.description),
        isAsset: !!f.isAsset,
        existingControls: str(f.existingControls),
        props: f.props && typeof f.props === 'object' ? f.props : {}
      };
    });
    return model;
  };

  function num(v, fallback) { var n = Number(v); return isFinite(n) ? n : fallback; }
  function str(v) { return typeof v === 'string' ? v : ''; }

  /* ---------------------------------------------------------------------
   * Undo / redo - snapshot based, which is plenty for diagram-sized models.
   * ------------------------------------------------------------------- */
  TM.History = function (limit) {
    this.limit = limit || 60;
    this.past = [];
    this.future = [];
  };
  TM.History.prototype.push = function (model) {
    this.past.push(TM.serialize(model));
    if (this.past.length > this.limit) this.past.shift();
    this.future.length = 0;
  };
  TM.History.prototype.undo = function (current) {
    if (!this.past.length) return null;
    this.future.push(TM.serialize(current));
    return TM.deserialize(this.past.pop());
  };
  TM.History.prototype.redo = function (current) {
    if (!this.future.length) return null;
    this.past.push(TM.serialize(current));
    return TM.deserialize(this.future.pop());
  };
  TM.History.prototype.canUndo = function () { return this.past.length > 0; };
  TM.History.prototype.canRedo = function () { return this.future.length > 0; };

})(window.TM);
