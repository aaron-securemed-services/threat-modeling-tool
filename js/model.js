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

    /* ---- entity ---- */
    {
      key: 'entityKind',
      label: 'Entity kind',
      group: 'Classification',
      help: 'What sort of actor this is.',
      options: [UNSET, 'Human user', 'Privileged user / administrator', 'External system', 'Third-party service', 'Device / sensor', 'Internal component'],
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
      help: 'What stops silent modification of stored data.',
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
      options: [UNSET, 'HTTPS / TLS', 'HTTP (cleartext)', 'gRPC over TLS', 'SQL / database protocol', 'AMQP / Kafka / queue', 'SMB / NFS file share', 'SFTP / SSH', 'FTP / Telnet (cleartext)', 'Email / SMTP', 'Physical / manual transfer', 'Other'],
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
        scope: ''
      },
      nodes: [],
      flows: []
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
