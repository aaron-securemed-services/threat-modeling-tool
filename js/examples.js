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
      safetyDocRef: 'RMF-IP-2200 rev C'
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

    return m;
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
      "intendedUse": "A continuous glucose monitor tracks a patient's interstitial glucose every few minutes and streams it to a display and to the clinical record. Patients and clinicians rely on it for two things: hypo/hyper ALARMS that warn of a dangerous low or high, and the glucose trend used to decide insulin dosing (including automated-delivery loops). A missed low-glucose alarm or a falsely reassuring reading can lead to severe, un-treated hypoglycaemia — seizure, coma or death. This lab is a deliberately vulnerable simulation (GlucoSense CGM-3000) that teaches students to find and fix the flaws that would let an attacker read, forge or suppress that safety-critical data.",
      "scope": "In scope: the appliance's web/kiosk console, HL7 listener, MQTT broker and telemetry, BLE advertiser, on-device config and user store, the host privilege model, and the Pi's physical interfaces — USB host ports, the on-board Bluetooth controller and the bedside touchscreen panel. Out of scope: the physical sensor hardware and adhesive, the upstream hospital EHR/LIS itself, the lab network fabric, and any real patient.",
      "safetyDoc": "CGM-3000 Risk Management File (ISO 14971)",
      "safetyDocRef": "RMF-CGM-3000 rev A"
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
          "criticality": "Low"
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
          "safetyNotes": "The clinician doses insulin and responds to lows based on what the console/kiosk shows. Wrong or missing readings and suppressed alarms lead to a wrong or withheld clinical decision."
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
          "criticality": "Medium"
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
          "safetyNotes": "The console is where a clinician reads glucose trends and acknowledges alarms; a compromise that alters what it shows biases a dosing decision."
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
          "safetyNotes": "Discloses per-patient glucose results and the device serial to any HL7 speaker; wrong or leaked results can misinform a downstream clinical decision."
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
          "safetyNotes": "A recovered credential can WRITE glucose/# even though it cannot READ it: a forged 'IN_RANGE' reading masks a true hypoglycaemia, suppresses its alarm, and drives an automated-delivery / dosing decision toward under-treatment."
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
          "safetyNotes": "Broadcasts patient-linked data over the air. Confidentiality only here, but the process runs as root, so its compromise is a host compromise (CWE-250)."
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
          "safetyNotes": "The bedside display is a clinician's at-a-glance view of glucose and alarms; if it is unlocked, frozen or shows the wrong patient, a low can be missed at the bedside."
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
          "owner": "Platform team"
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
          "owner": "Device web team"
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
          "owner": "Firmware team"
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
          "safetyNotes": "The reading and alarm state a clinician or automated-delivery loop consumes. If it can be written with no integrity control, a fabricated 'in range' value hides a real low."
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
          "owner": "Platform team"
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
          "safetyNotes": "Source of truth for glucose and alarms; the value a forged reading has to be told apart from."
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
          "owner": "Privacy officer"
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
          "safetyNotes": "If a real hypoglycaemia alarm is suppressed (by a forged reading or a frozen display), the last warning before harm is gone."
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
          "owner": "Platform team"
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
          "criticality": "Low"
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
          "safetyNotes": "A USB device that types (BadUSB HID) is the bedside operator: it can silence alarms, edit thresholds in cgm.conf or kill the kiosk, and because the mount helper runs as root, removable media is also a path to persistent control of the alarm path. Nothing at the bedside tells a charging cable from an attack."
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
          "safetyNotes": "A keyboard paired from the corridor is an unauthenticated console at the bedside, a rogue GATT client can read the patient-linked advertisement, and flooding the controller drops the sensor link — so glucose stops updating and the hypo alarm never annunciates."
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
          "safetyNotes": "This panel is where a hypo alarm is seen at the bedside. Left on another screen, frozen, dimmed, unlocked by PIN guessing or driven by an injected input device, the alarm is annunciated to nobody and the low is missed. It also shows the patient's name and readings to whoever is standing in the bay."
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
          "criticality": "High"
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
          "safetyFileRef": "SEC-HAZ-002"
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
          "safetyFileRef": "SEC-HAZ-008"
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
            "clinicalData"
          ],
          "harmSeverity": "Minor — temporary injury, no professional intervention",
          "safetyFileRef": "SEC-HAZ-005"
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
          "criticality": "High"
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
          "criticality": "High"
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
          "protocol": "AMQP / Kafka / queue",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "High"
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
          "protocol": "AMQP / Kafka / queue",
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
          "safetyFileRef": "SEC-HAZ-001"
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
          "protocol": "AMQP / Kafka / queue",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "Username + password",
          "authorization": "Simple ownership check",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Critical (safety / life)"
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
          "protocol": "AMQP / Kafka / queue",
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
          "safetyFileRef": "SEC-HAZ-001, RC-011, RC-012"
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
          "protocol": "AMQP / Kafka / queue",
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
          "safetyFileRef": "SEC-HAZ-008"
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
          "protocol": "Other",
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
          "safetyFileRef": "SEC-HAZ-007"
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
          "protocol": "Other",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium"
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
          "criticality": "High"
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
          "criticality": "High"
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
          "criticality": "Medium"
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
          "protocol": "Other",
          "encryptionInTransit": "None (cleartext)",
          "flowIntegrity": "None",
          "throttling": "None",
          "authentication": "None / anonymous",
          "authorization": "None",
          "logging": "None",
          "dataClassification": "Restricted (PII / PHI / PCI)",
          "criticality": "Medium"
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
          "criticality": "Medium"
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
          "safetyFileRef": "SEC-HAZ-012"
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
          "safetyFileRef": "SEC-HAZ-012"
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
            "careDelivery"
          ],
          "harmSeverity": "Serious — injury needing professional intervention",
          "softwareSafetyClass": "Class B — non-serious injury possible",
          "safetyFileRef": "SEC-HAZ-011"
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
          "criticality": "Medium"
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
          "criticality": "Medium"
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
          "criticality": "Low"
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
