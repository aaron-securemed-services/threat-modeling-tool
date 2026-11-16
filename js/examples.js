/* ---------------------------------------------------------------------------
 * examples.js - the worked examples a student can pick from the toolbar.
 *
 * Each entry builds a *fresh* model every time it is chosen, so loading the
 * same example twice never hands back the copy the last load was edited into.
 * Add an example by writing a builder and calling register() at the bottom of
 * this file; the picker in the toolbar is generated from the registry.
 * --------------------------------------------------------------------------- */
(function (TM) {
  'use strict';

  /* The example the tool opens with when there is nothing to restore. */
  TM.DEFAULT_EXAMPLE = 'infusion-pump';

  TM.EXAMPLES = [];

  function register(id, label, summary, build) {
    TM.EXAMPLES.push({ id: id, label: label, summary: summary, build: build });
  }

  TM.example = function (id) {
    for (var i = 0; i < TM.EXAMPLES.length; i++) {
      if (TM.EXAMPLES[i].id === id) return TM.EXAMPLES[i];
    }
    return null;
  };

  /** A fresh copy of one example, or null if the id is not registered. */
  TM.buildExample = function (id) {
    var ex = TM.example(id);
    return ex ? ex.build() : null;
  };

  /* ---------------------------------------------------------------------
   * 1. Connected infusion pump - deliberately imperfect so the generated
   * report has something to say in every STRIDE category and in all three
   * patient-safety classes: device control, alarms and safety stops.
   * ------------------------------------------------------------------- */
  function infusionPumpModel() {
    var m = TM.emptyModel();
    m.meta = {
      name: 'Connected infusion pump (worked example)',
      system: 'Large-volume infusion pump with hospital connectivity and a vendor cloud service',
      author: 'Teaching example',
      date: new Date().toISOString().slice(0, 10),
      intendedUse: 'Continuous and bolus intravenous delivery of medication to adult and paediatric inpatients, ' +
        'programmed at the bedside or by auto-programming from the EHR, under the supervision of clinical staff.',
      scope: 'In scope: the pump controller and its dose-limit interlock, the alarm path to the nurse call system, ' +
        'the hospital gateway, the drug library service and the vendor telemetry cloud. Out of scope: the EHR itself, ' +
        'hospital network infrastructure, and physical security of the ward.',
      safetyDoc: 'Infusion Pump Risk Management File (ISO 14971)',
      safetyDocRef: 'RMF-IP-2200 rev C',
      /* What FDA asks a threat model to state: environment, assumptions,
         why this method, how risk is accepted, and the lifecycle. */
      environment: 'Acute-care wards and intensive care. The pump joins the hospital\'s clinical Wi-Fi alongside ' +
        'other vendors\' devices and general IT. The hospital runs that network, not the manufacturer, and ' +
        'segmentation cannot be relied on. Pumps move between wards and are within reach of patients and visitors.',
      networkAssumption: TM.NETWORK_HOSTILE,
      assumptions: 'The hospital network is hostile. Clinical staff follow the programming workflow but cannot detect ' +
        'a value altered in transit. The EHR and the nurse call system belong to other manufacturers and are treated ' +
        'as untrusted peers. A visitor can reach the pump\'s ports unobserved for minutes at a time.',
      methodologyRationale: 'STRIDE per element on a data flow diagram. The pump\'s cybersecurity risks arise at its ' +
        'interfaces, and a per-element sweep gives a coverage argument a reviewer can follow and repeat. Each ' +
        'safety-relevant function is also analysed for the hazard a compromise creates, so the result feeds the ' +
        'ISO 14971 file. STRIDE does not rank attacker effort, so exploitability is added per threat with CVSS v4.0.',
      acceptableResidual: 'Medium',
      acceptanceCriteria: 'Scored before mitigation by the model, and after mitigation by the security and safety ' +
        'leads together. Residual Medium or below is acceptable. High needs sign-off against clinical benefit. ' +
        'Critical is not acceptable. Every threat with a path to patient harm is carried into RMF-IP-2200 by its ' +
        'SEC-HAZ reference.',
      lifecycle: {
        supplyChain: 'Pump firmware builds on a commercial RTOS and an open-source TLS library. The hospital gateway ' +
          'ships on a commercial OS image. One SBOM per release (SBOM-IP-2200).',
        manufacturing: 'Every pump leaves the factory with the same service password and the same gateway key.',
        deployment: 'Commissioned by hospital biomed onto the clinical Wi-Fi. Nothing forces the service password to change.',
        interoperation: 'EHR auto-programming through the hospital gateway, and nurse call integration. Both are ' +
          'other manufacturers\' systems.',
        maintenance: 'Firmware and drug libraries come from the vendor fleet service through the hospital gateway, ' +
          'or are installed locally by a service technician from a file share.'
        /* decommission: deliberately not considered yet - the report says so */
      }
    };

    function node(type, x, y, w, h, title, description, props, isAsset) {
      var n = TM.makeNode(type, x + w / 2, y + h / 2);
      n.w = w; n.h = h; n.x = x; n.y = y;
      n.title = title;
      n.description = description || '';
      n.props = props || {};
      n.isAsset = !!isAsset;
      m.nodes.push(n);
      return n;
    }
    function flow(from, to, title, description, props, bidi) {
      var f = TM.makeFlow(from.id, to.id);
      f.title = title;
      f.description = description || '';
      f.props = props || {};
      f.bidirectional = !!bidi;
      m.flows.push(f);
      return f;
    }

    /* ---- trust boundaries ---- */
    node('boundary', 40, 60, 420, 560, 'Pump enclosure (device)',
      'The physical device: firmware, actuator and local user interface.',
      { boundaryKind: 'Machine / process boundary' });
    node('boundary', 500, 60, 400, 560, 'Hospital network',
      'The clinical network the pump joins over Wi-Fi.',
      { boundaryKind: 'Network segment' });
    node('boundary', 940, 60, 340, 560, 'Vendor cloud',
      'Manufacturer-operated telemetry and fleet management service.',
      { boundaryKind: 'Third-party or vendor' });

    /* ---- inside the pump ---- */
    var pumpCtl = node('process', 90, 140, 190, 96, 'Pump controller',
      'Firmware that computes and drives the infusion rate.', {
        safetyFunctions: ['control'],
        harmSeverity: 'Catastrophic — patient death',
        softwareSafetyClass: 'Class C — death or serious injury possible',
        safetyFileRef: 'HAZ-001, HAZ-004, RC-011',
        safetyNotes: 'Over-infusion of a high-alert medication. The controller drives the actuator directly, so any ' +
          'altered rate or programme becomes delivered therapy within one pump cycle.',
        exposure: 'Internal network',
        privilege: 'Elevated service account',
        inputValidation: 'Partial / deny-list',
        resilience: 'Timeouts only',
        authentication: 'Shared secret or API key',
        authorization: 'Simple ownership check',
        logging: 'Errors only',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Critical (safety / life)',
        owner: 'Device firmware team'
      }, true);

    var interlock = node('process', 90, 290, 190, 88, 'Dose limit interlock',
      'Independent hard-limit check before actuation.', {
        safetyFunctions: ['safetyStop'],
        harmSeverity: 'Catastrophic — patient death',
        softwareSafetyClass: 'Class C — death or serious injury possible',
        safetyFileRef: 'RC-011, RC-012',
        safetyNotes: 'This is the last barrier between a wrong programmed dose and the patient. If its limits are ' +
          'widened, or it does not get to run, nothing else stops an unsafe infusion.',
        exposure: 'Internal network',
        privilege: 'Least privilege',
        inputValidation: 'Partial / deny-list',
        resilience: 'None',
        authentication: 'None / anonymous',
        authorization: 'Shared credential for everyone',
        logging: 'None',
        dataClassification: 'Internal',
        criticality: 'Critical (safety / life)',
        owner: 'Device firmware team'
      }, true);

    var alarmMgr = node('process', 90, 430, 190, 88, 'Alarm manager',
      'Detects alarm conditions and annunciates locally and remotely.', {
        safetyFunctions: ['alarm'],
        harmSeverity: 'Critical — permanent impairment or life-threatening injury',
        softwareSafetyClass: 'Class C — death or serious injury possible',
        safetyFileRef: 'HAZ-007',
        safetyNotes: 'Occlusion, air-in-line and infusion-complete alarms. A suppressed alarm means deterioration ' +
          'goes unnoticed; injected false alarms cause alarm fatigue on the ward.',
        exposure: 'Internal network',
        privilege: 'Least privilege',
        inputValidation: 'None',
        resilience: 'None',
        authentication: 'None / anonymous',
        authorization: 'None',
        logging: 'Errors only',
        dataClassification: 'Confidential',
        criticality: 'Critical (safety / life)',
        owner: 'Device firmware team'
      });

    var drugLib = node('datastore', 90, 540, 190, 66, 'Drug library (on device)',
      'Dose limits and concentrations per medication.', {
        safetyFunctions: ['safetyStop'],
        harmSeverity: 'Catastrophic — patient death',
        softwareSafetyClass: 'Class C — death or serious injury possible',
        safetyFileRef: 'RC-012',
        safetyNotes: 'The limits the interlock enforces. Tampering here silently widens what the pump will accept ' +
          'as a legitimate dose.',
        storeKind: 'File share',
        encryptionAtRest: 'None',
        integrity: 'None',
        backup: 'Tested backups with retention',
        authentication: 'Shared secret or API key',
        authorization: 'Shared credential for everyone',
        logging: 'None',
        dataClassification: 'Internal',
        criticality: 'Critical (safety / life)',
        owner: 'Pharmacy informatics'
      }, true);

    /* ---- clinical users ---- */
    var nurse = node('entity', 540, 140, 170, 74, 'Nurse (bedside)',
      'Programmes the infusion at the pump and responds to alarms.', {
        safetyFunctions: ['control', 'careDelivery'],
        harmSeverity: 'Serious — injury needing professional intervention',
        safetyFileRef: 'HAZ-002',
        safetyNotes: 'Use error and spoofed identity both end in a wrong programme reaching the pump.',
        entityKind: 'Human user',
        trustLevel: 'Semi-trusted (authenticated)',
        authentication: 'Username + password',
        logging: 'Errors only',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'High',
        owner: 'Clinical engineering'
      });

    var biomed = node('entity', 540, 250, 170, 74, 'Biomed / service tech',
      'Services the pump and updates the drug library.', {
        safetyFunctions: ['safetyStop'],
        harmSeverity: 'Catastrophic — patient death',
        safetyFileRef: 'HAZ-009',
        safetyNotes: 'Holds the credentials that can change dose limits and disable interlocks.',
        entityKind: 'Privileged user / administrator',
        trustLevel: 'Semi-trusted (authenticated)',
        authentication: 'Shared secret or API key',
        logging: 'None',
        dataClassification: 'Internal',
        criticality: 'High',
        owner: 'Clinical engineering'
      });

    /* ---- hospital network ---- */
    var gateway = node('process', 540, 370, 190, 92, 'Hospital gateway',
      'Bridges pumps to hospital systems and the vendor cloud.', {
        safetyFunctions: ['control', 'alarm', 'careDelivery'],
        harmSeverity: 'Critical — permanent impairment or life-threatening injury',
        softwareSafetyClass: 'Class B — non-serious injury possible',
        safetyFileRef: 'HAZ-004, HAZ-007',
        safetyNotes: 'Carries auto-programming orders towards the pump and alarms away from it. A compromise here ' +
          'reaches every pump on the ward at once.',
        exposure: 'Internal network',
        privilege: 'Elevated service account',
        inputValidation: 'None',
        resilience: 'None',
        authentication: 'None / anonymous',
        authorization: 'None',
        logging: 'Errors only',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Critical (safety / life)',
        owner: 'Hospital IT'
      });

    var nurseCall = node('process', 540, 500, 190, 88, 'Nurse call system',
      'Escalates device alarms to staff handsets.', {
        safetyFunctions: ['alarm', 'careDelivery'],
        harmSeverity: 'Critical — permanent impairment or life-threatening injury',
        softwareSafetyClass: 'Class B — non-serious injury possible',
        safetyFileRef: 'HAZ-007, RC-021',
        safetyNotes: 'The remote half of the alarm path. If alarms are delayed or lost here, the bedside alarm is ' +
          'the only remaining barrier.',
        exposure: 'Internal network',
        privilege: 'Least privilege',
        inputValidation: 'Partial / deny-list',
        resilience: 'Timeouts only',
        authentication: 'Shared secret or API key',
        authorization: 'Role-based (RBAC)',
        logging: 'Security events logged',
        dataClassification: 'Confidential',
        criticality: 'Critical (safety / life)',
        owner: 'Hospital IT'
      });

    /* ---- vendor cloud ---- */
    var cloud = node('process', 980, 190, 190, 92, 'Vendor fleet service',
      'Telemetry, drug library distribution and firmware updates.', {
        safetyFunctions: ['safetyStop', 'control'],
        harmSeverity: 'Catastrophic — patient death',
        softwareSafetyClass: 'Class C — death or serious injury possible',
        safetyFileRef: 'HAZ-011',
        safetyNotes: 'Distributes the drug library and firmware to the whole fleet. A compromise is a fleet-wide ' +
          'safety event, not a single-device one.',
        exposure: 'Internet-facing',
        privilege: 'Elevated service account',
        inputValidation: 'Partial / deny-list',
        resilience: 'Rate limiting / quotas',
        authentication: 'Session token / JWT',
        authorization: 'Role-based (RBAC)',
        logging: 'Security events logged',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'High',
        owner: 'Vendor cloud team'
      });

    var telemetry = node('datastore', 980, 350, 190, 66, 'Telemetry & event store',
      'Infusion events, alarms and device logs.', {
        safetyFunctions: ['clinicalData'],
        harmSeverity: 'Minor — temporary injury, no professional intervention',
        softwareSafetyClass: 'Class A — no injury possible',
        safetyFileRef: 'HAZ-013',
        storeKind: 'Object / blob storage',
        encryptionAtRest: 'Full-disk / volume',
        integrity: 'None',
        backup: 'Backups, never tested',
        authentication: 'Session token / JWT',
        authorization: 'Role-based (RBAC)',
        logging: 'Errors only',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Medium',
        owner: 'Vendor cloud team'
      });

    var patient = node('asset', 990, 480, 100, 86, 'Patient',
      '', {
        safetyFunctions: ['control', 'careDelivery'],
        harmSeverity: 'Catastrophic — patient death',
        safetyFileRef: 'RMF-IP-2200',
        safetyNotes: 'The asset every other control exists to protect.',
        assetKind: 'Physical',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Critical (safety / life)',
        owner: 'Clinical service'
      }, true);
    void patient;

    /* ---- flows ---- */
    flow(nurse, pumpCtl, 'Programme infusion', 'Rate, dose and duration entered at the bedside.', {
      safetyFunctions: ['control'],
      harmSeverity: 'Catastrophic — patient death',
      softwareSafetyClass: 'Class C — death or serious injury possible',
      safetyFileRef: 'HAZ-002',
      protocol: 'Other',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'Username + password',
      authorization: 'Simple ownership check',
      logging: 'Errors only',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'Critical (safety / life)'
    });

    flow(gateway, pumpCtl, 'Auto-programming order', 'Pharmacy order pushed to the pump from the EHR.', {
      safetyFunctions: ['control'],
      harmSeverity: 'Catastrophic — patient death',
      softwareSafetyClass: 'Class C — death or serious injury possible',
      safetyFileRef: 'HAZ-004',
      protocol: 'HTTP (cleartext)',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'None / anonymous',
      authorization: 'None',
      logging: 'None',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'Critical (safety / life)'
    });

    flow(gateway, pumpCtl, 'Firmware and library push', 'Firmware images and drug libraries relayed from the vendor to each pump.', {
      safetyFunctions: ['control', 'safetyStop'],
      harmSeverity: 'Catastrophic — patient death',
      softwareSafetyClass: 'Class C — death or serious injury possible',
      safetyFileRef: 'HAZ-011',
      safetyNotes: 'Whatever arrives here becomes the software that drives the pump and the limits that constrain it.',
      protocol: 'HTTP (cleartext)',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'Shared secret or API key',
      authorization: 'Shared credential for everyone',
      logging: 'Errors only',
      dataClassification: 'Internal',
      criticality: 'Critical (safety / life)'
    });

    flow(pumpCtl, interlock, 'Requested rate check', 'Every programmed rate is checked against the hard limits.', {
      safetyFunctions: ['safetyStop'],
      harmSeverity: 'Catastrophic — patient death',
      safetyFileRef: 'RC-011',
      protocol: 'Other',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'None / anonymous',
      authorization: 'None',
      logging: 'None',
      dataClassification: 'Internal',
      criticality: 'Critical (safety / life)'
    }, true);

    flow(drugLib, interlock, 'Dose limits', 'Limits the interlock enforces.', {
      safetyFunctions: ['safetyStop'],
      harmSeverity: 'Catastrophic — patient death',
      safetyFileRef: 'RC-012',
      protocol: 'Other',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'Timeouts only',
      authentication: 'None / anonymous',
      authorization: 'None',
      logging: 'None',
      dataClassification: 'Internal',
      criticality: 'Critical (safety / life)'
    });

    flow(pumpCtl, alarmMgr, 'Alarm conditions', 'Occlusion, air-in-line, battery and completion events.', {
      safetyFunctions: ['alarm'],
      harmSeverity: 'Critical — permanent impairment or life-threatening injury',
      safetyFileRef: 'HAZ-007',
      protocol: 'Other',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'None / anonymous',
      authorization: 'None',
      logging: 'Errors only',
      dataClassification: 'Confidential',
      criticality: 'Critical (safety / life)'
    });

    flow(alarmMgr, nurseCall, 'Remote alarm escalation', 'Alarms forwarded to staff handsets.', {
      safetyFunctions: ['alarm'],
      harmSeverity: 'Critical — permanent impairment or life-threatening injury',
      safetyFileRef: 'HAZ-007, RC-021',
      protocol: 'HTTP (cleartext)',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'Shared secret or API key',
      authorization: 'None',
      logging: 'Errors only',
      dataClassification: 'Confidential',
      criticality: 'Critical (safety / life)'
    });

    flow(biomed, drugLib, 'Drug library update', 'Service tooling writes new dose limits to the pump.', {
      safetyFunctions: ['safetyStop'],
      harmSeverity: 'Catastrophic — patient death',
      safetyFileRef: 'HAZ-009',
      protocol: 'SMB / NFS file share',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'Shared secret or API key',
      authorization: 'Shared credential for everyone',
      logging: 'None',
      dataClassification: 'Internal',
      criticality: 'High'
    });

    flow(cloud, gateway, 'Drug library & firmware distribution', 'Fleet-wide updates pushed to the hospital.', {
      safetyFunctions: ['safetyStop', 'control'],
      harmSeverity: 'Catastrophic — patient death',
      softwareSafetyClass: 'Class C — death or serious injury possible',
      safetyFileRef: 'HAZ-011',
      protocol: 'HTTPS / TLS',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'Timeouts only',
      authentication: 'Shared secret or API key',
      authorization: 'Shared credential for everyone',
      logging: 'Security events logged',
      dataClassification: 'Internal',
      criticality: 'High'
    });

    flow(gateway, cloud, 'Device telemetry', 'Infusion and alarm events sent to the vendor.', {
      safetyFunctions: ['clinicalData'],
      harmSeverity: 'Minor — temporary injury, no professional intervention',
      safetyFileRef: 'HAZ-013',
      protocol: 'HTTPS / TLS',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'Timeouts only',
      authentication: 'Shared secret or API key',
      authorization: 'Role-based (RBAC)',
      logging: 'Errors only',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'Medium'
    });

    flow(cloud, telemetry, 'Store events', 'Telemetry written to the event store.', {
      protocol: 'HTTPS / TLS',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'Rate limited / throttled',
      authentication: 'Session token / JWT',
      authorization: 'Role-based (RBAC)',
      logging: 'Errors only',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'Medium'
    });

    flow(alarmMgr, nurse, 'Bedside annunciation', 'Audible and visual alarm at the pump.', {
      safetyFunctions: ['alarm'],
      harmSeverity: 'Critical — permanent impairment or life-threatening injury',
      safetyFileRef: 'RC-021',
      protocol: 'Physical / manual transfer',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'Timeouts only',
      authentication: 'None / anonymous',
      authorization: 'None',
      logging: 'None',
      dataClassification: 'Confidential',
      criticality: 'Critical (safety / life)'
    });

    /* ---- FDA premarket categories -------------------------------------
     * Scale of compromise and security use cases for every element; origin,
     * support, SBOM, update mechanism and keys for software; what each path
     * carries and whether it can be replayed. Kept apart from the security
     * controls above so the two layers can be read separately.
     * ----------------------------------------------------------------- */
    var ONE = TM.SCOPE_SINGLE, MANY = TM.SCOPE_MULTI;
    var FIRMWARE = 'SBOM-IP-2200 §1 (pump firmware)';
    var UNSIGNED = 'Unauthenticated (unsigned image, file, USB or service tool)';
    var NO_REPLAY = 'Not applicable — not a replayable channel';
    var IN_USE = 'In use for the intended use';

    annotate(m, {
      'Pump controller': {
        harmScope: ONE, useCases: 'Programming, Delivering therapy, Software update',
        softwareOrigin: 'Mixed — includes third-party components', componentSupport: 'Actively maintained',
        sbomRef: FIRMWARE, updateMechanism: UNSIGNED,
        keyManagement: 'Hardcoded, default or shared across devices'
      },
      'Dose limit interlock': {
        harmScope: ONE, useCases: 'Delivering therapy, Drug library update',
        softwareOrigin: 'Proprietary (manufacturer-developed)', componentSupport: 'Actively maintained',
        sbomRef: FIRMWARE, updateMechanism: UNSIGNED, keyManagement: 'No keys or credentials held'
      },
      'Alarm manager': {
        harmScope: ONE, useCases: 'Alarming',
        softwareOrigin: 'Proprietary (manufacturer-developed)', componentSupport: 'Actively maintained',
        sbomRef: FIRMWARE, updateMechanism: UNSIGNED,
        keyManagement: 'Hardcoded, default or shared across devices'
      },
      'Hospital gateway': {
        harmScope: MANY, useCases: 'Programming, Alarming, Software update, Telemetry',
        softwareOrigin: 'Mixed — includes third-party components',
        componentSupport: 'No longer maintained (end of support)',
        updateMechanism: 'Signed updates, no rollback protection',
        keyManagement: 'Unique per device, stored in software'
      },
      /* A hospital system: the manufacturer cannot say how it is updated or
         keyed, and the report lists those as open questions. */
      'Nurse call system': {
        harmScope: MANY, useCases: 'Alarming',
        softwareOrigin: 'Commercial off-the-shelf', componentSupport: 'Actively maintained',
        sbomRef: 'Not part of the device (hospital system)'
      },
      'Vendor fleet service': {
        harmScope: MANY, useCases: 'Software update, Drug library update, Telemetry',
        softwareOrigin: 'Mixed — includes third-party components', componentSupport: 'Actively maintained',
        sbomRef: 'SBOM-FLEET-12', updateMechanism: 'Signed updates with rollback protection',
        keyManagement: 'Unique per device, stored in software'
      },
      'Drug library (on device)': { harmScope: ONE, useCases: 'Delivering therapy, Drug library update' },
      'Telemetry & event store': { harmScope: MANY, useCases: 'Telemetry' },
      'Nurse (bedside)': { harmScope: ONE, useCases: 'Programming, Alarming' },
      'Biomed / service tech': { harmScope: MANY, useCases: 'Drug library update, Software update' },
      'Patient': { harmScope: ONE, useCases: 'Delivering therapy' },

      'Programme infusion': {
        harmScope: ONE, useCases: 'Programming', carries: ['commands'], interfaceState: IN_USE,
        replayProtection: NO_REPLAY, protocolDetail: 'Front-panel keypad and touchscreen'
      },
      'Auto-programming order': {
        harmScope: MANY, useCases: 'Programming', carries: ['commands'], interfaceState: IN_USE,
        replayProtection: 'None', protocolDetail: 'HTTP/1.1, tcp/8080, JSON order'
      },
      'Firmware and library push': {
        harmScope: MANY, useCases: 'Software update, Drug library update', carries: ['code'], interfaceState: IN_USE,
        replayProtection: 'None', protocolDetail: 'HTTP/1.1, tcp/8080, image pulled on notification'
      },
      'Requested rate check': {
        harmScope: ONE, useCases: 'Delivering therapy', carries: ['data'], interfaceState: IN_USE,
        replayProtection: NO_REPLAY, protocolDetail: 'In-process call'
      },
      'Dose limits': {
        harmScope: ONE, useCases: 'Delivering therapy', carries: ['data'], interfaceState: IN_USE,
        replayProtection: NO_REPLAY, protocolDetail: 'File read at start-up and on change'
      },
      'Alarm conditions': {
        harmScope: ONE, useCases: 'Alarming', carries: ['data'], interfaceState: IN_USE,
        replayProtection: NO_REPLAY, protocolDetail: 'In-process message queue'
      },
      'Remote alarm escalation': {
        harmScope: ONE, useCases: 'Alarming', carries: ['data'], interfaceState: IN_USE,
        replayProtection: 'None', protocolDetail: 'HTTP/1.1, tcp/8081'
      },
      'Drug library update': {
        harmScope: ONE, useCases: 'Drug library update', carries: ['code'],
        interfaceState: 'Service / maintenance only', replayProtection: 'None', protocolDetail: 'SMB 2, tcp/445'
      },
      'Drug library & firmware distribution': {
        harmScope: MANY, useCases: 'Software update, Drug library update', carries: ['code'], interfaceState: IN_USE,
        replayProtection: 'Timestamp or sequence number', protocolDetail: 'TLS 1.2, tcp/443'
      },
      'Device telemetry': {
        harmScope: MANY, useCases: 'Telemetry', carries: ['data'], interfaceState: IN_USE,
        replayProtection: 'Timestamp or sequence number', protocolDetail: 'TLS 1.2, tcp/443'
      },
      'Store events': {
        harmScope: MANY, useCases: 'Telemetry', carries: ['data'], interfaceState: IN_USE,
        replayProtection: 'Timestamp or sequence number', protocolDetail: 'TLS 1.2, tcp/443'
      },
      'Bedside annunciation': {
        harmScope: ONE, useCases: 'Alarming', carries: ['data'], interfaceState: IN_USE,
        replayProtection: NO_REPLAY, protocolDetail: 'Audible and visual alarm at the pump'
      }
    });

    /* ---- risk treatment: a few threats decided, the rest left open ----
     * Enough to show pre- and post-mitigation risk side by side, a residual
     * above the acceptance threshold, and a mitigation with no evidence yet.
     * ----------------------------------------------------------------- */
    treat(m, 'Pump controller', 'safe-control-s', {
      status: 'Mitigated by design', residual: 'Medium',
      control: 'SR-021 therapy commands signed by the gateway and verified at the pump; SR-022 confirmation at the pump for any rate increase',
      rationale: 'A spoofed command is rejected at the pump. What remains is a compromised gateway signing key.',
      evidence: 'TC-SEC-041; PT-2026-02 §5.1'
    });
    treat(m, 'Dose limit interlock', 'safe-stop-t', {
      status: 'Mitigated by design', residual: 'High',
      control: 'SR-030 absolute hard limit in firmware that no drug library entry can widen',
      rationale: 'Library tampering is bounded by the firmware limit, but soft limits can still be widened until the signed drug library ships in release 2.1.',
      evidence: ''
    });
    treat(m, 'Alarm manager', 'safe-alarm-d', {
      status: 'Mitigated by compensating control', residual: 'Medium',
      control: 'Audible and visual annunciation at the pump does not depend on the network path',
      rationale: 'Remote escalation can still be blocked; the bedside alarm cannot.',
      evidence: 'TC-ALM-112'
    });
    treat(m, 'Hospital gateway', 'proc-e-unsupported', {
      status: 'Transferred to the user (disclosed in labeling)', residual: 'High',
      control: '',
      rationale: 'The gateway OS image is past end of support. Hospitals are told to isolate it on its own VLAN (IFU §9.3) until the 3.0 image ships.',
      evidence: ''
    });
    treat(m, 'Nurse (bedside)', 'ent-r-nolog', {
      status: 'Accepted', residual: 'Low',
      control: '',
      rationale: 'Programming at the bedside is attributed through the ward\'s medication administration record rather than by the pump.',
      evidence: ''
    });

    return m;
  }

  /** Merge extra categories into the elements of `model`, looked up by title. */
  function annotate(model, byTitle) {
    model.nodes.concat(model.flows).forEach(function (el) {
      var extra = byTitle[el.title];
      if (!extra) return;
      Object.keys(extra).forEach(function (k) { el.props[k] = extra[k]; });
    });
  }

  /** Record a risk treatment against one threat, by element title and rule id. */
  function treat(model, title, ruleId, t) {
    var el = model.nodes.concat(model.flows).filter(function (e) { return e.title === title; })[0];
    if (!el) return;
    t.updated = model.meta.date;
    model.treatments[TM.assessmentKey(el.id, ruleId)] = t;
  }

  /* ---------------------------------------------------------------------
   * 2. CGM lab - the deliberately vulnerable GlucoSense CGM-3000 appliance
   * from CGM-LAB-INT, threat modelled as students are asked to do it, so a
   * finished reference exists to compare their own model against.
   *
   * Held as data rather than as a builder because it is a saved model:
   * examples/cgm-lab.json is the same model as a file students can open,
   * save and diff. Keep the two in step when either changes.
   * ------------------------------------------------------------------- */
  var CGM_LAB = {
    "schemaVersion": 1,
    "meta": {
      "name": "CGM lab — GlucoSense CGM-3000 (worked example)",
      "system": "Continuous glucose monitoring appliance: a wearable BLE sensor, an MQTT telemetry backbone, an HL7 clinical interface, and a web + bedside-kiosk console, all on one Raspberry Pi with its USB ports, Bluetooth radio and touchscreen live at the bedside.",
      "author": "SecureMED teaching example (CGM-LAB-INT)",
      "date": "2026-08-29",
      "scope": "In scope: the appliance's web/kiosk console, HL7 listener, MQTT broker and telemetry, BLE advertiser, on-device config and user store, the host privilege model, and the Pi's physical interfaces — USB host ports, the on-board Bluetooth controller and the bedside touchscreen panel. Out of scope: the physical sensor hardware and adhesive, the upstream hospital EHR/LIS itself, the lab network fabric, and any real patient.",
      "safetyDoc": "CGM-3000 Risk Management File (ISO 14971)",
      "safetyDocRef": "RMF-CGM-3000 rev A",
      "intendedUse": "A continuous glucose monitor tracks a patient's interstitial glucose every few minutes and streams it to a display and to the clinical record. Patients and clinicians rely on it for two things: hypo/hyper ALARMS that warn of a dangerous low or high, and the glucose trend used to decide insulin dosing (including automated-delivery loops). A missed low-glucose alarm or a falsely reassuring reading can lead to severe, un-treated hypoglycaemia — seizure, coma or death. This lab is a deliberately vulnerable simulation (GlucoSense CGM-3000) that teaches students to find and fix the flaws that would let an attacker read, forge or suppress that safety-critical data.",
      "environment": "A hospital bedside or a patient's home. The appliance sits on whatever network it is given, with its USB ports, Bluetooth radio and touchscreen within reach of anyone at the bedside. In the lab it is on a shared classroom network that every student can reach.",
      "assumptions": "The network and the radio environment are hostile: any student on the lab network, and anyone within Bluetooth range, is a potential adversary. Nobody watches the bedside continuously. Clinicians act on what the display shows and cannot tell a forged reading from a real one. The Raspberry Pi OS and its packages are as shipped in the lab image.",
      "networkAssumption": "Hostile — an adversary can alter, drop and replay traffic",
      "methodologyRationale": "STRIDE per element. The lab's flaws are interface flaws (an unauthenticated broker, a cleartext console, an open HL7 listener) and a per-element sweep finds those systematically. The physical interfaces are drawn as elements so the same method covers them. Findings a student confirms by exploiting them are scored with CVSS v4.0.",
      "acceptanceCriteria": "Teaching criteria: residual Medium or below is acceptable; High and Critical have to be mitigated before the appliance could be considered for clinical use. Every threat to the alarm path is carried into the hazard analysis by its SEC-HAZ reference.",
      "acceptableResidual": "Medium",
      "lifecycle": {
        "supplyChain": "Raspberry Pi OS, mosquitto, Flask, BlueZ and Chromium are all third-party. The lab image pins old versions on purpose, and there is no SBOM.",
        "manufacturing": "Every appliance is flashed from one image: the same SSH password, broker credential and web admin account on each.",
        "deployment": "Dropped onto the hospital or home network as it is. Nothing forces a credential change or closes unused services.",
        "interoperation": "HL7 v2 over MLLP to the LIS / EHR, MQTT to subscribers, BLE to the sensor.",
        "maintenance": "Patched by hand over SSH by biomed. There is no update server and nothing is signed."
      }
    },
    "nodes": [
      {
        "id": "boundary-cgm-net",
        "type": "boundary",
        "x": 40,
        "y": 40,
        "w": 360,
        "h": 740,
        "title": "Untrusted lab network + BLE RF",
        "description": "Any peer on the isolated lab LAN, and the radio space around the appliance. No control is applied here.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "boundaryKind": "Internet / DMZ perimeter"
        }
      },
      {
        "id": "boundary-cgm-appliance",
        "type": "boundary",
        "x": 440,
        "y": 40,
        "w": 900,
        "h": 800,
        "title": "GlucoSense CGM-3000 appliance (Raspberry Pi 5)",
        "description": "The device under test. All lab services bind 0.0.0.0 with no host firewall, and its physical interfaces — USB ports, Bluetooth radio and touch panel — are live at the bedside.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "boundaryKind": "Physical / facility"
        }
      },
      {
        "id": "boundary-cgm-host",
        "type": "boundary",
        "x": 440,
        "y": 900,
        "w": 560,
        "h": 150,
        "title": "Host OS / root (SSH)",
        "description": "The Linux host the services run on. Root is the crown jewel (SEC-HAZ-009).",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "boundaryKind": "Privilege level"
        }
      },
      {
        "id": "entity-attacker",
        "type": "entity",
        "x": 90,
        "y": 120,
        "w": 160,
        "h": 70,
        "title": "Unauthenticated network client",
        "description": "Any device on the lab LAN, and the student's Kali box. Anonymous until it defeats a control.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "entityKind": "External system",
          "trustLevel": "Untrusted (anonymous)",
          "authentication": "None / anonymous",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Low",
          "harmScope": "Single device / single patient"
        }
      },
      {
        "id": "entity-clinician",
        "type": "entity",
        "x": 90,
        "y": 300,
        "w": 160,
        "h": 70,
        "title": "Clinician / caregiver",
        "description": "Reads glucose and hypo/hyper alarms on the console and bedside kiosk, and acts on them.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "entityKind": "Human user",
          "trustLevel": "Semi-trusted (authenticated)",
          "authentication": "Username + password",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "clinicalData",
            "alarm"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "safetyFileRef": "SEC-HAZ-004",
          "safetyNotes": "The clinician doses insulin and responds to lows based on what the console/kiosk shows. Wrong or missing readings and suppressed alarms lead to a wrong or withheld clinical decision.",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming"
        }
      },
      {
        "id": "entity-ehr",
        "type": "entity",
        "x": 90,
        "y": 480,
        "w": 160,
        "h": 70,
        "title": "Hospital LIS / EHR interface",
        "description": "Upstream clinical system that queries the CGM over HL7 v2 (MLLP) for glucose results.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "entityKind": "External system",
          "trustLevel": "Semi-trusted (authenticated)",
          "authentication": "None / anonymous",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Multiple devices or patients at once",
          "useCases": "Reporting results to the EHR"
        }
      },
      {
        "id": "process-web",
        "type": "process",
        "x": 500,
        "y": 110,
        "w": 190,
        "h": 92,
        "title": "Web admin console (Flask)",
        "description": "Login, /admin maintenance token, /admin/export diagnostic download, and /kiosk/unlock. TCP 8080. Surfaces 1-4 and 8.",
        "isAsset": false,
        "existingControls": "SQLite-backed login with a STRONG admin password, a server-side kiosk PIN, and a 5-failure/5-min login lockout. But: the SQL is string-built (SQLi auth bypass), /admin/export joins the path with no containment (traversal leaks cgm.conf), the lockout is keyed on the spoofable X-Forwarded-For header, and app.secret_key is a rockyou word (forgeable session -> IDOR on /patient/1001-1005).",
        "props": {
          "exposure": "Internet-facing",
          "privilege": "Least privilege",
          "inputValidation": "None",
          "resilience": "Timeouts only",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Device web team",
          "safetyFunctions": [
            "clinicalData"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-002, RC-021",
          "safetyNotes": "The console is where a clinician reads glucose trends and acknowledges alarms; a compromise that alters what it shows biases a dosing decision.",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Device administration",
          "softwareOrigin": "Mixed — includes third-party components",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "Hardcoded, default or shared across devices"
        }
      },
      {
        "id": "process-hl7",
        "type": "process",
        "x": 780,
        "y": 110,
        "w": 190,
        "h": 92,
        "title": "HL7 MLLP listener",
        "description": "Answers a well-formed QRY^Q01 for a known MRN with an ORU^R01 (PHI). Serial in MSH-3; flag in NTE. TCP 2575. Surface 5.",
        "isAsset": false,
        "existingControls": "Requires a properly MLLP-framed QRY^Q01 naming a valid MRN and NAKs the rest. But input SHAPE is not access control: no authentication, no TLS, no peer allow-list -> any HL7 speaker gets PHI, and MSH-3 leaks the BLE XOR key.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Least privilege",
          "inputValidation": "Partial / deny-list",
          "resilience": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "owner": "Clinical interfaces team",
          "safetyFunctions": [
            "clinicalData"
          ],
          "harmSeverity": "Minor — temporary injury, no professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-005",
          "safetyNotes": "Discloses per-patient glucose results and the device serial to any HL7 speaker; wrong or leaked results can misinform a downstream clinical decision.",
          "harmScope": "Single device / single patient",
          "useCases": "Reporting results to the EHR",
          "softwareOrigin": "Proprietary (manufacturer-developed)",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "No keys or credentials held"
        }
      },
      {
        "id": "process-mqtt",
        "type": "process",
        "x": 1060,
        "y": 110,
        "w": 190,
        "h": 92,
        "title": "MQTT broker (mosquitto)",
        "description": "Telemetry backbone. glucose/# carries readings + alarm state; cgm/service/# holds a retained capture flag. TCP 1883. Surface 6.",
        "isAsset": false,
        "existingControls": "allow_anonymous false + a password + a per-topic ACL (least privilege attempted). But the password (glucose123) leaks via the config traversal and is weak; the ACL grants cgmpub WRITE on glucose/# with no READ -> eavesdrop denied but forged-reading INJECTION allowed; and cgm/service/# is readable, exposing a retained flag.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Least privilege",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "owner": "Telemetry team",
          "safetyFunctions": [
            "control",
            "alarm",
            "clinicalData"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "softwareSafetyClass": "Class C — death or serious injury possible",
          "safetyFileRef": "SEC-HAZ-001, RC-011, RC-012",
          "safetyNotes": "A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment.",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring, Alarming",
          "softwareOrigin": "Open source",
          "componentSupport": "No longer maintained (end of support)",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "Hardcoded, default or shared across devices"
        }
      },
      {
        "id": "process-ble",
        "type": "process",
        "x": 500,
        "y": 470,
        "w": 180,
        "h": 92,
        "title": "BLE advertiser (runs as root)",
        "description": "Non-connectable LE broadcast, company id 0xFFFF, carrying XOR-obfuscated manufacturer data. Surface 7.",
        "isAsset": false,
        "existingControls": "Payload is XOR'd rather than sent in the clear. But the key IS the device serial (low-entropy, static) which leaks from HL7 MSH-3 and cgm.conf -> trivially reversible. Obfuscation, not encryption. Service unit runs as root.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Root / administrator",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Low",
          "owner": "Firmware team",
          "safetyFunctions": [
            "clinicalData"
          ],
          "harmSeverity": "Minor — temporary injury, no professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-007",
          "safetyNotes": "Broadcasts patient-linked data over the air. Confidentiality only here, but the process runs as root, so its compromise is a host compromise (CWE-250).",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring",
          "softwareOrigin": "Proprietary (manufacturer-developed)",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "No keys or credentials held"
        }
      },
      {
        "id": "process-kiosk",
        "type": "process",
        "x": 770,
        "y": 470,
        "w": 180,
        "h": 92,
        "title": "Bedside kiosk (Chromium / matchbox on DSI panel)",
        "description": "Full-screen bedside display of glucose + alarms; unlock via POST /kiosk/unlock. Owns tty1. Surface 8.",
        "isAsset": false,
        "existingControls": "PIN check is server-side now (not in the page source). But /kiosk/unlock has no rate limit, lockout or delay -> all 10,000 four-digit PINs in seconds, and it returns the flag with no session.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Least privilege",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Device web team",
          "safetyFunctions": [
            "alarm",
            "clinicalData",
            "careDelivery"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-008",
          "safetyNotes": "The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside.",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming",
          "softwareOrigin": "Open source",
          "componentSupport": "No longer maintained (end of support)",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "No keys or credentials held"
        }
      },
      {
        "id": "process-host",
        "type": "process",
        "x": 500,
        "y": 925,
        "w": 190,
        "h": 90,
        "title": "Host shell (biomed via SSH)",
        "description": "SSH foothold + local privilege escalation to root. Surface 9.",
        "isAsset": false,
        "existingControls": "biomed was removed from the sudo group. But its password is a rockyou word (sunshine, dictionary-crackable over password-auth SSH) and there is a NOPASSWD sudo rule on /usr/bin/awk (GTFOBins) -> instant root.",
        "props": {
          "exposure": "Internet-facing",
          "privilege": "Least privilege",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Platform team",
          "harmScope": "Multiple devices or patients at once",
          "useCases": "Device administration, Software update",
          "softwareOrigin": "Open source",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "Hardcoded, default or shared across devices"
        }
      },
      {
        "id": "datastore-userdb",
        "type": "datastore",
        "x": 500,
        "y": 280,
        "w": 190,
        "h": 76,
        "title": "User store (cgm.db, SQLite)",
        "description": "Seeded username/role/password rows queried by the login. Surface 1.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "storeKind": "Relational database",
          "encryptionAtRest": "None",
          "integrity": "Constraints / checksums",
          "backup": "None",
          "authentication": "Shared secret or API key",
          "authorization": "Shared credential for everyone",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Device web team",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration"
        }
      },
      {
        "id": "datastore-conf",
        "type": "datastore",
        "x": 780,
        "y": 280,
        "w": 190,
        "h": 76,
        "title": "Device config (cgm.conf)",
        "description": "Holds the MQTT credentials, the device serial (BLE key) and a maintenance token. World-readable, one dir above the report root. Surface 3.",
        "isAsset": true,
        "existingControls": "",
        "props": {
          "storeKind": "File share",
          "encryptionAtRest": "None",
          "integrity": "None",
          "backup": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Firmware team",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration"
        }
      },
      {
        "id": "datastore-glucose",
        "type": "datastore",
        "x": 1060,
        "y": 280,
        "w": 190,
        "h": 76,
        "title": "Glucose telemetry (MQTT glucose/#, retained)",
        "description": "Per-patient readings and alarm state. A forged retained message persists to later subscribers.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "storeKind": "Message queue",
          "encryptionAtRest": "None",
          "integrity": "None",
          "backup": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "owner": "Telemetry team",
          "safetyFunctions": [
            "clinicalData",
            "alarm"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "softwareSafetyClass": "Class C — death or serious injury possible",
          "safetyFileRef": "SEC-HAZ-001, RC-011",
          "safetyNotes": "The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low.",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring, Alarming"
        }
      },
      {
        "id": "datastore-root",
        "type": "datastore",
        "x": 760,
        "y": 932,
        "w": 200,
        "h": 80,
        "title": "Root filesystem / sudoers (/etc/sudoers.d, /root)",
        "description": "The NOPASSWD sudoers drop-in and /root/flag.txt (mode 600). Surface 9.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "storeKind": "File share",
          "encryptionAtRest": "None",
          "integrity": "None",
          "backup": "None",
          "authentication": "None / anonymous",
          "authorization": "Shared credential for everyone",
          "logging": "Errors only",
          "dataClassification": "Confidential",
          "criticality": "High",
          "owner": "Platform team",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration, Software update"
        }
      },
      {
        "id": "entity-sensor",
        "type": "entity",
        "x": 1060,
        "y": 460,
        "w": 180,
        "h": 70,
        "title": "CGM sensor + BLE gateway",
        "description": "The wearable sensor front end that publishes legitimate glucose readings and alarm state onto glucose/#.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "entityKind": "Device / sensor",
          "trustLevel": "Trusted (internal / managed)",
          "authentication": "Username + password",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "clinicalData",
            "alarm"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "safetyFileRef": "SEC-HAZ-001",
          "safetyNotes": "Source of truth for glucose and alarms; the value a forged reading has to be told apart from.",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring"
        }
      },
      {
        "id": "asset-phi",
        "type": "asset",
        "x": 1290,
        "y": 120,
        "w": 96,
        "h": 82,
        "title": "Patient glucose data / PHI",
        "description": "Per-patient readings, MRNs and demographics across HL7, MQTT and BLE.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "assetKind": "Information",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Privacy officer",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Reporting results to the EHR"
        }
      },
      {
        "id": "asset-alarm",
        "type": "asset",
        "x": 1290,
        "y": 280,
        "w": 96,
        "h": 82,
        "title": "Hypo / hyper alarm path",
        "description": "The end-to-end path that turns a real low or high into an alarm the clinician sees and acts on.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "assetKind": "Service / capability",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "owner": "Clinical safety officer",
          "safetyFunctions": [
            "alarm",
            "control"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "safetyFileRef": "SEC-HAZ-001, RC-012",
          "safetyNotes": "If a real hypoglycaemia alarm is suppressed (by a forged reading or a frozen display), the last warning before harm is gone.",
          "harmScope": "Single device / single patient",
          "useCases": "Alarming"
        }
      },
      {
        "id": "asset-creds",
        "type": "asset",
        "x": 1290,
        "y": 440,
        "w": 96,
        "h": 82,
        "title": "Device & broker credentials",
        "description": "MQTT creds, Flask session secret, device serial, biomed SSH password.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "assetKind": "Credential / secret",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Platform team",
          "harmScope": "Multiple devices or patients at once",
          "useCases": "Device administration"
        }
      },
      {
        "id": "boundary-cgm-bedside",
        "type": "boundary",
        "x": 1060,
        "y": 900,
        "w": 340,
        "h": 180,
        "title": "Unattended bedside (physical access)",
        "description": "The patient bay itself. Anyone who can walk up to the appliance can touch its screen, plug into its ports and stand inside Bluetooth range, usually unobserved.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "boundaryKind": "Physical / facility"
        }
      },
      {
        "id": "entity-physical",
        "type": "entity",
        "x": 1130,
        "y": 955,
        "w": 160,
        "h": 70,
        "title": "Visitor at the bedside",
        "description": "A visitor, a patient, a cleaner or a contractor: unauthenticated, unsupervised, and alone with the device for minutes at a time.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "entityKind": "Human user",
          "trustLevel": "Untrusted (anonymous)",
          "authentication": "None / anonymous",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Low",
          "harmScope": "Single device / single patient"
        }
      },
      {
        "id": "process-usb",
        "type": "process",
        "x": 500,
        "y": 660,
        "w": 190,
        "h": 92,
        "title": "USB host ports (udev auto-mount)",
        "description": "The Pi's four USB-A ports, live and unblanked at the bedside. udev auto-mounts any removable volume and the kernel binds any device that enumerates as a keyboard. Physical surface — not one of the numbered lab surfaces.",
        "isAsset": false,
        "existingControls": "The enclosure is closed with two screws. Nothing else: no port blockers, no USB device authorisation (usbguard) or HID allow-list, no encryption on the SD card to stop offline imaging, and the mount helper runs from a root udev rule.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Root / administrator",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "owner": "Platform team",
          "safetyFunctions": [
            "alarm",
            "careDelivery"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "softwareSafetyClass": "Class C — death or serious injury possible",
          "safetyFileRef": "SEC-HAZ-010",
          "safetyNotes": "A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack.",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration",
          "softwareOrigin": "Open source",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "No keys or credentials held"
        }
      },
      {
        "id": "process-bt",
        "type": "process",
        "x": 760,
        "y": 660,
        "w": 200,
        "h": 92,
        "title": "Bluetooth stack (BlueZ / bluetoothd, root)",
        "description": "The Pi's on-board controller and the BlueZ daemon: discoverable and pairable in the lab image, and the same radio the BLE advertiser broadcasts on. Physical / RF surface — not one of the numbered lab surfaces.",
        "isAsset": false,
        "existingControls": "Nothing hardens it. bluetoothd runs as root over D-Bus, the controller is left discoverable, pairing is Just Works with no confirmation on the panel, and no allow-list limits which HID or GATT peer may connect — so hcitool, bluetoothctl and gatttool from any laptop in range all reach it.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Root / administrator",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "owner": "Firmware team",
          "safetyFunctions": [
            "clinicalData",
            "alarm"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "softwareSafetyClass": "Class C — death or serious injury possible",
          "safetyFileRef": "SEC-HAZ-011",
          "safetyNotes": "A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates.",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring",
          "softwareOrigin": "Open source",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "Unique per device, stored in software"
        }
      },
      {
        "id": "process-touch",
        "type": "process",
        "x": 1040,
        "y": 660,
        "w": 200,
        "h": 92,
        "title": "Touchscreen HMI (DSI panel + libinput)",
        "description": "The 7-inch bedside touch panel: the only thing the clinician actually looks at, and the input device for the kiosk session on tty1. Physical surface — not one of the numbered lab surfaces.",
        "isAsset": false,
        "existingControls": "None worth the name. The panel has no screen lock and no inactivity timeout, so any touch goes straight into the kiosk; long-press and multi-touch still reach the Chromium context menu and the on-screen keyboard, which makes the panel a general purpose input device rather than a fixed display.",
        "props": {
          "exposure": "Internal network",
          "privilege": "Least privilege",
          "inputValidation": "None",
          "resilience": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "owner": "Device web team",
          "safetyFunctions": [
            "alarm",
            "clinicalData",
            "careDelivery"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-012",
          "safetyNotes": "This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay.",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming",
          "softwareOrigin": "Open source",
          "componentSupport": "Actively maintained",
          "updateMechanism": "Unauthenticated (unsigned image, file, USB or service tool)",
          "keyManagement": "No keys or credentials held"
        }
      }
    ],
    "flows": [
      {
        "id": "flow-att-web",
        "type": "flow",
        "from": "entity-attacker",
        "to": "process-web",
        "bidirectional": true,
        "title": "HTTP attack surface",
        "description": "SQLi login, cookie forgery + IDOR, path traversal, rate-limit bypass, kiosk unlock.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "HTTP (cleartext)",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "harmScope": "Single device / single patient",
          "carries": [
            "data",
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "HTTP/1.1, tcp/5000"
        }
      },
      {
        "id": "flow-clin-web",
        "type": "flow",
        "from": "entity-clinician",
        "to": "process-web",
        "bidirectional": true,
        "title": "Console session",
        "description": "Clinician reviews glucose/alarms and administers the device.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "HTTP (cleartext)",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Role-based (RBAC)",
          "logging": "Security events logged",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "clinicalData"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "safetyFileRef": "SEC-HAZ-002",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Device administration",
          "carries": [
            "data",
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "HTTP/1.1, tcp/5000"
        }
      },
      {
        "id": "flow-clin-kiosk",
        "type": "flow",
        "from": "entity-clinician",
        "to": "process-kiosk",
        "bidirectional": true,
        "title": "Bedside interaction",
        "description": "Clinician glances at the kiosk and unlocks it at the bedside.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "HTTP (cleartext)",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "alarm",
            "clinicalData"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "safetyFileRef": "SEC-HAZ-008",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming",
          "carries": [
            "data",
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "HTTP/1.1 on localhost, kiosk browser"
        }
      },
      {
        "id": "flow-ehr-hl7",
        "type": "flow",
        "from": "entity-ehr",
        "to": "process-hl7",
        "bidirectional": true,
        "title": "HL7 v2 query / result (MLLP)",
        "description": "QRY^Q01 in, ORU^R01 with PHI out. Cleartext, unauthenticated.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "HL7 / DICOM / FHIR",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "clinicalData"
          ],
          "harmSeverity": "Minor — temporary injury, no professional intervention",
          "safetyFileRef": "SEC-HAZ-005",
          "harmScope": "Single device / single patient",
          "useCases": "Reporting results to the EHR",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "HL7 v2 over MLLP, tcp/2575"
        }
      },
      {
        "id": "flow-web-userdb",
        "type": "flow",
        "from": "process-web",
        "to": "datastore-userdb",
        "bidirectional": true,
        "title": "Login query",
        "description": "String-built SELECT against the user table (SQLi).",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "SQL / database protocol",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Shared secret or API key",
          "authorization": "Shared credential for everyone",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "SQLite file access"
        }
      },
      {
        "id": "flow-web-conf",
        "type": "flow",
        "from": "process-web",
        "to": "datastore-conf",
        "bidirectional": true,
        "title": "Diagnostic export / config read",
        "description": "/admin/export joins the filename with no containment -> traversal.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Other",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration",
          "carries": [
            "data"
          ],
          "interfaceState": "Service / maintenance only",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "Local file read"
        }
      },
      {
        "id": "flow-web-mqtt",
        "type": "flow",
        "from": "process-web",
        "to": "process-mqtt",
        "bidirectional": true,
        "title": "Console telemetry",
        "description": "Console reads current glucose/alarm state to display.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "MQTT",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "MQTT 3.1.1, tcp/1883"
        }
      },
      {
        "id": "flow-sensor-mqtt",
        "type": "flow",
        "from": "entity-sensor",
        "to": "process-mqtt",
        "bidirectional": false,
        "title": "Legitimate glucose publish",
        "description": "Real readings + alarm state onto glucose/<patient>.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "MQTT",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "safetyFunctions": [
            "clinicalData",
            "alarm"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "safetyFileRef": "SEC-HAZ-001",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring, Alarming",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "MQTT 3.1.1, tcp/1883, topic glucose/#"
        }
      },
      {
        "id": "flow-mqtt-glucose",
        "type": "flow",
        "from": "process-mqtt",
        "to": "datastore-glucose",
        "bidirectional": true,
        "title": "Retained telemetry",
        "description": "Broker persists the latest retained reading/alarm per topic.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "MQTT",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring, Alarming",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "Retained messages on glucose/#"
        }
      },
      {
        "id": "flow-att-mqtt",
        "type": "flow",
        "from": "entity-attacker",
        "to": "process-mqtt",
        "bidirectional": true,
        "title": "Forged-reading injection",
        "description": "With the leaked cred: WRITE glucose/# (forge 'IN_RANGE') and READ cgm/service/# (flag). READ glucose/# denied.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "MQTT",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "safetyFunctions": [
            "control",
            "alarm",
            "clinicalData"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "safetyFileRef": "SEC-HAZ-001, RC-011, RC-012",
          "harmScope": "Single device / single patient",
          "carries": [
            "data",
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "MQTT 3.1.1, tcp/1883"
        }
      },
      {
        "id": "flow-mqtt-kiosk",
        "type": "flow",
        "from": "process-mqtt",
        "to": "process-kiosk",
        "bidirectional": false,
        "title": "Bedside display feed",
        "description": "Glucose + alarm state pushed to the kiosk.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "MQTT",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "alarm",
            "clinicalData"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "safetyFileRef": "SEC-HAZ-008",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "MQTT 3.1.1 subscription"
        }
      },
      {
        "id": "flow-ble-att",
        "type": "flow",
        "from": "process-ble",
        "to": "entity-attacker",
        "bidirectional": false,
        "title": "BLE advertisement (RF)",
        "description": "Non-connectable broadcast of XOR-obfuscated manufacturer data (company id 0xFFFF).",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Bluetooth / BLE",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Low",
          "safetyFunctions": [
            "clinicalData"
          ],
          "harmSeverity": "Minor — temporary injury, no professional intervention",
          "safetyFileRef": "SEC-HAZ-007",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "BLE advertising, 2.4 GHz channels 37-39"
        }
      },
      {
        "id": "flow-att-hl7",
        "type": "flow",
        "from": "entity-attacker",
        "to": "process-hl7",
        "bidirectional": true,
        "title": "Rogue HL7 query",
        "description": "Any HL7 speaker crafts a valid QRY^Q01 and receives PHI + serial.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "HL7 / DICOM / FHIR",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Single device / single patient",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "None",
          "protocolDetail": "HL7 v2 over MLLP, tcp/2575"
        }
      },
      {
        "id": "flow-att-host",
        "type": "flow",
        "from": "entity-attacker",
        "to": "process-host",
        "bidirectional": true,
        "title": "SSH foothold",
        "description": "Password-auth SSH; biomed's password is dictionary-crackable.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "SFTP / SSH",
          "encryptionInTransit": "TLS (server authenticated)",
          "flowIntegrity": "Transport (TLS) only",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "harmScope": "Multiple devices or patients at once",
          "useCases": "Device administration, Software update",
          "carries": [
            "commands",
            "code"
          ],
          "interfaceState": "Service / maintenance only",
          "replayProtection": "Cryptographic nonce / session-bound",
          "protocolDetail": "SSH-2, tcp/22"
        }
      },
      {
        "id": "flow-host-root",
        "type": "flow",
        "from": "process-host",
        "to": "datastore-root",
        "bidirectional": true,
        "title": "Privilege escalation",
        "description": "NOPASSWD sudo on /usr/bin/awk (GTFOBins) spawns a root shell.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Other",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "Shared credential for everyone",
          "logging": "Errors only",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "harmScope": "Single device / single patient",
          "useCases": "Device administration, Software update",
          "carries": [
            "commands",
            "code"
          ],
          "interfaceState": "Service / maintenance only",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "sudo on the local host"
        }
      },
      {
        "id": "flow-phys-usb",
        "type": "flow",
        "from": "entity-physical",
        "to": "process-usb",
        "bidirectional": true,
        "title": "USB port access",
        "description": "BadUSB keystroke injection, auto-mounted mass storage, a bootable stick, and imaging the SD card off the device.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Physical / manual transfer",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Single device / single patient",
          "carries": [
            "data",
            "code"
          ],
          "interfaceState": "Built in but unused / dormant",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "USB host ports: mass storage and HID"
        }
      },
      {
        "id": "flow-phys-bt",
        "type": "flow",
        "from": "entity-physical",
        "to": "process-bt",
        "bidirectional": true,
        "title": "Bluetooth pairing / GATT access",
        "description": "Just Works pairing of an HID keyboard, GATT enumeration of the advertiser, and RF flooding of the controller — all from outside the bay.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Bluetooth / BLE",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Single device / single patient",
          "carries": [
            "data",
            "commands"
          ],
          "interfaceState": "Built in but unused / dormant",
          "replayProtection": "None",
          "protocolDetail": "Bluetooth pairing and GATT"
        }
      },
      {
        "id": "flow-phys-touch",
        "type": "flow",
        "from": "entity-physical",
        "to": "process-touch",
        "bidirectional": true,
        "title": "Unattended panel use",
        "description": "Anyone in the bay can read the panel and drive it: kiosk PIN guessing, gesture escape to the browser, on-screen keyboard.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Physical / manual transfer",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Single device / single patient",
          "carries": [
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "Capacitive touch panel"
        }
      },
      {
        "id": "flow-touch-kiosk",
        "type": "flow",
        "from": "process-touch",
        "to": "process-kiosk",
        "bidirectional": true,
        "title": "Touch input / rendered display",
        "description": "Touch events into the kiosk session on tty1, and the glucose trend and alarm view rendered back to the panel.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Other",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "alarm",
            "clinicalData"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-012",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming",
          "carries": [
            "data",
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "libinput events in, DSI display out"
        }
      },
      {
        "id": "flow-touch-clin",
        "type": "flow",
        "from": "process-touch",
        "to": "entity-clinician",
        "bidirectional": false,
        "title": "Bedside annunciation",
        "description": "What the clinician actually sees and hears at the bedside: current glucose, trend, and the hypo / hyper alarm.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Physical / manual transfer",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)",
          "safetyFunctions": [
            "alarm",
            "clinicalData"
          ],
          "harmSeverity": "Critical — permanent impairment or life-threatening injury",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-012",
          "harmScope": "Single device / single patient",
          "useCases": "Viewing glucose data, Alarming",
          "carries": [
            "data"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "Visual display and audible alarm"
        }
      },
      {
        "id": "flow-bt-kiosk",
        "type": "flow",
        "from": "process-bt",
        "to": "process-kiosk",
        "bidirectional": false,
        "title": "Paired HID input",
        "description": "A Bluetooth keyboard paired from outside the bay types into the kiosk session exactly as the bedside user would.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Bluetooth / BLE",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High",
          "safetyFunctions": [
            "alarm",
            "careDelivery"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-011",
          "harmScope": "Single device / single patient",
          "carries": [
            "commands"
          ],
          "interfaceState": "Built in but unused / dormant",
          "replayProtection": "None",
          "protocolDetail": "Bluetooth HID profile"
        }
      },
      {
        "id": "flow-usb-conf",
        "type": "flow",
        "from": "process-usb",
        "to": "datastore-conf",
        "bidirectional": true,
        "title": "Removable-media config copy",
        "description": "Diagnostic dumps written to a USB stick and config restored from one — the device serial and the MQTT credentials travel with them.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Physical / manual transfer",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Single device / single patient",
          "carries": [
            "data"
          ],
          "interfaceState": "Built in but unused / dormant",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "Mounted mass-storage volume"
        }
      },
      {
        "id": "flow-usb-root",
        "type": "flow",
        "from": "process-usb",
        "to": "datastore-root",
        "bidirectional": false,
        "title": "Auto-mount + udev rule execution",
        "description": "Mount helpers and udev rules run as root the moment a device enumerates, so removable media reaches the root filesystem without anyone logging in.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Physical / manual transfer",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium",
          "harmScope": "Single device / single patient",
          "carries": [
            "code"
          ],
          "interfaceState": "Built in but unused / dormant",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "udev rules run on device insertion"
        }
      },
      {
        "id": "flow-ble-bt",
        "type": "flow",
        "from": "process-ble",
        "to": "process-bt",
        "bidirectional": false,
        "title": "HCI advertising control",
        "description": "The advertiser drives the same controller through BlueZ, so whoever owns bluetoothd owns what the device broadcasts.",
        "isAsset": false,
        "existingControls": "",
        "props": {
          "protocol": "Other",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Low",
          "harmScope": "Single device / single patient",
          "useCases": "Glucose monitoring",
          "carries": [
            "commands"
          ],
          "interfaceState": "In use for the intended use",
          "replayProtection": "Not applicable — not a replayable channel",
          "protocolDetail": "HCI between advertiser and controller"
        }
      }
    ],
    "scoring": null,
    "assessments": {
      "process-web::proc-t-input": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "score": 9.2,
        "severity": "Critical",
        "rationale": "SQL injection in the login gives an unauthenticated admin session and, via the export traversal, read of on-device secrets. Network, no auth, no interaction. Scored in the CVSS v4.0 calculator as a teaching illustration.",
        "updated": "2026-08-29"
      },
      "process-mqtt::safe-alarm-t": {
        "vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:H",
        "score": 8.7,
        "severity": "High",
        "rationale": "With a leaked broker credential, forging a retained 'in range' reading on glucose/# suppresses a genuine hypoglycaemia alarm (integrity + safety impact). Adjacent network, low privilege. Illustrative CVSS v4.0 score.",
        "updated": "2026-08-29"
      }
    },
    "treatments": {
      "process-mqtt::safe-alarm-t": {
        "status": "Mitigated by design",
        "control": "Broker ACLs and a TLS client certificate per sensor, so only the paired sensor can publish to glucose/#",
        "residual": "Medium",
        "rationale": "The lab fix. A forged reading now needs the sensor's private key rather than a shared password.",
        "evidence": "Lab retest: forged publish to glucose/# rejected",
        "updated": "2026-08-29"
      },
      "process-web::proc-t-input": {
        "status": "Mitigated by design",
        "control": "Parameterised queries and allow-list validation on every console input",
        "residual": "Low",
        "rationale": "The lab fix for the login and diagnostic injection flaws.",
        "evidence": "",
        "updated": "2026-08-29"
      },
      "process-host::proc-i-sharedkeys": {
        "status": "Transferred to the user (disclosed in labeling)",
        "control": "",
        "residual": "High",
        "rationale": "Operators are told to change the SSH password at commissioning. Nothing enforces it, so the risk stays with every site that does not.",
        "evidence": "",
        "updated": "2026-08-29"
      }
    }
  };

  function cgmLabModel() {
    /* Through the file path the app already trusts, so a model that would not
       open from disk cannot sneak in from here either. */
    return TM.deserialize(JSON.stringify(CGM_LAB));
  }

  /* ---------------------------------------------------------------------
   * Registry - the order here is the order in the toolbar picker.
   * ------------------------------------------------------------------- */
  register('infusion-pump', 'Connected infusion pump',
    'A large-volume infusion pump with hospital connectivity and a vendor cloud, ' +
    'covering device control, alarms and a dose-limit safety stop.',
    infusionPumpModel);

  register('cgm-lab', 'CGM lab — GlucoSense CGM-3000',
    'The deliberately vulnerable CGM-LAB-INT appliance: BLE sensor, MQTT telemetry, ' +
    'HL7 interface, web and bedside kiosk, and the Pi\'s USB, Bluetooth and touchscreen.',
    cgmLabModel);

  /* Older scripts and bookmarks called the first example directly. */
  TM.sampleModel = infusionPumpModel;

})(window.TM);
