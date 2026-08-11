/* ---------------------------------------------------------------------------
 * app.js - wiring: palette, properties panel, model metadata, file IO,
 * exports, the report modal and the worked example.
 * --------------------------------------------------------------------------- */
(function (TM) {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var AUTOSAVE_KEY = 'tm.autosave.v1';

  var state = {
    model: TM.emptyModel(),
    history: new TM.History(),
    diagram: null,
    lastReport: null
  };

  /* ---------------------------------------------------------------------
   * Boot
   * ------------------------------------------------------------------- */
  function boot() {
    state.diagram = new TM.Diagram($('canvas'), {
      onChange: onModelChanged,
      onSelect: renderProps,
      onStatus: status,
      onZoom: function (k) { $('zoomLabel').textContent = Math.round(k * 100) + '%'; },
      onToolChange: function (tool) {
        Array.prototype.forEach.call(document.querySelectorAll('.tool'), function (b) {
          b.classList.toggle('active', b.getAttribute('data-tool') === tool);
        });
        banner(tool);
      }
    });

    bindPalette();
    bindToolbar();
    bindShortcuts();

    var restored = loadAutosave();
    setModel(restored || sampleModel(), { resetHistory: true, fit: true });
    if (!restored) status('Loaded the worked example. Press ? in the toolbar for the teaching guide.');
    state.diagram.setTool('select');
  }

  /* ---------------------------------------------------------------------
   * Model plumbing
   * ------------------------------------------------------------------- */
  function setModel(model, opts) {
    opts = opts || {};
    state.model = model;
    if (opts.resetHistory) state.history = new TM.History();
    $('modelName').value = model.meta.name || '';
    state.diagram.setModel(model);
    if (opts.fit) state.diagram.zoomFit();
    renderProps(state.diagram.selectionId || null, {});
    updateCounts();
    autosave();
  }

  /** Called by the diagram after a structural edit. */
  function onModelChanged() {
    updateCounts();
    autosave();
    renderProps(state.diagram.selectionId, { keepFocus: true });
  }

  /** Snapshot before a change so it can be undone. */
  function checkpoint() {
    state.history.push(state.model);
  }

  function undo() {
    var m = state.history.undo(state.model);
    if (!m) { status('Nothing to undo.'); return; }
    setModel(m, {});
    status('Undo.');
  }
  function redo() {
    var m = state.history.redo(state.model);
    if (!m) { status('Nothing to redo.'); return; }
    setModel(m, {});
    status('Redo.');
  }

  function autosave() {
    try {
      localStorage.setItem(AUTOSAVE_KEY, TM.serialize(state.model));
    } catch (e) { /* private mode / quota - not fatal */ }
  }
  function loadAutosave() {
    try {
      var raw = localStorage.getItem(AUTOSAVE_KEY);
      return raw ? TM.deserialize(raw) : null;
    } catch (e) { return null; }
  }

  function updateCounts() {
    var m = state.model;
    var byType = {};
    m.nodes.forEach(function (n) { byType[n.type] = (byType[n.type] || 0) + 1; });
    $('statusCounts').textContent =
      (byType.entity || 0) + ' entities · ' + (byType.process || 0) + ' processes · ' +
      (byType.datastore || 0) + ' data stores · ' + m.flows.length + ' flows · ' +
      (byType.boundary || 0) + ' boundaries · ' +
      (m.nodes.filter(function (n) { return n.isAsset || n.type === 'asset'; }).length) + ' assets';
  }

  function status(msg) { $('statusMsg').textContent = msg; }

  function banner(tool) {
    var b = $('banner');
    if (tool === 'select') { b.hidden = true; return; }
    if (tool === 'flow') {
      b.textContent = 'Data flow: click the source element, then the destination. Esc to cancel.';
    } else {
      b.textContent = 'Click on the canvas to place ' + TM.TYPES[tool].article + ' ' + TM.TYPES[tool].label.toLowerCase() + '. Esc to cancel.';
    }
    b.hidden = false;
  }

  /* ---------------------------------------------------------------------
   * Palette + toolbar
   * ------------------------------------------------------------------- */
  function bindPalette() {
    Array.prototype.forEach.call(document.querySelectorAll('.tool'), function (btn) {
      btn.addEventListener('click', function () {
        var tool = btn.getAttribute('data-tool');
        if (tool !== 'select') checkpoint();
        state.diagram.setTool(tool);
      });
    });

    $('btnZoomIn').addEventListener('click', function () { state.diagram.zoomBy(1.2); });
    $('btnZoomOut').addEventListener('click', function () { state.diagram.zoomBy(1 / 1.2); });
    $('btnZoomFit').addEventListener('click', function () { state.diagram.zoomFit(); });
    $('btnUndo').addEventListener('click', undo);
    $('btnRedo').addEventListener('click', redo);

    $('chkGrid').addEventListener('change', function (e) { state.diagram.setOption('showGrid', e.target.checked); });
    $('chkSnap').addEventListener('change', function (e) { state.diagram.snap = e.target.checked; });
    $('chkLegend').addEventListener('change', function (e) { state.diagram.setOption('showLegend', e.target.checked); });
  }

  function bindToolbar() {
    $('modelName').addEventListener('input', function (e) {
      state.model.meta.name = e.target.value;
      autosave();
    });
    $('modelName').addEventListener('change', function () { checkpoint(); });

    $('btnNew').addEventListener('click', function () {
      if (!confirm('Start a new, empty threat model? Unsaved work in this diagram will be lost.')) return;
      var m = TM.emptyModel();
      setModel(m, { resetHistory: true });
      state.diagram.view = { x: 0, y: 0, k: 1 };
      state.diagram.render();
      status('New model.');
    });

    $('btnSample').addEventListener('click', function () {
      if (!confirm('Replace the current diagram with the worked example?')) return;
      setModel(sampleModel(), { resetHistory: true, fit: true });
      status('Worked example loaded.');
    });

    $('btnSave').addEventListener('click', function () {
      var name = (state.model.meta.name || 'threat-model').trim();
      download(slug(name) + '.json', TM.serialize(state.model), 'application/json');
      status('Saved ' + slug(name) + '.json');
    });

    $('btnOpen').addEventListener('click', function () { $('fileInput').click(); });
    $('fileInput').addEventListener('change', function (e) {
      var file = e.target.files && e.target.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        try {
          setModel(TM.deserialize(String(reader.result)), { resetHistory: true, fit: true });
          status('Opened ' + file.name);
        } catch (err) {
          alert('Could not open that file: ' + err.message);
        }
      };
      reader.readAsText(file);
      e.target.value = '';
    });

    $('btnExportPng').addEventListener('click', function () {
      status('Rendering PNG…');
      state.diagram.exportPNG(2, { legend: $('chkLegend').checked }).then(function (url) {
        var a = document.createElement('a');
        a.href = url;
        a.download = slug(state.model.meta.name || 'threat-model') + '.png';
        document.body.appendChild(a); a.click(); a.remove();
        status('Exported PNG.');
      }).catch(function (err) {
        alert('PNG export failed: ' + err.message);
        status('PNG export failed.');
      });
    });

    $('btnExportSvg').addEventListener('click', function () {
      var svg = state.diagram.exportSVGString({ legend: $('chkLegend').checked });
      download(slug(state.model.meta.name || 'threat-model') + '.svg', svg, 'image/svg+xml');
      status('Exported SVG.');
    });

    $('btnReport').addEventListener('click', openReport);
    $('btnHelp').addEventListener('click', openHelp);

    Array.prototype.forEach.call(document.querySelectorAll('[data-close-modal]'), function (b) {
      b.addEventListener('click', function () {
        b.closest('.modal').hidden = true;
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('.modal'), function (m) {
      m.addEventListener('click', function (e) { if (e.target === m) m.hidden = true; });
    });

    $('btnReportMd').addEventListener('click', function () {
      var r = state.lastReport;
      download(slug(state.model.meta.name || 'threat-model') + '-stride-report.md',
        TM.buildReportMarkdown(r.model, r.analysis), 'text/markdown');
    });
    $('btnReportHtml').addEventListener('click', function () {
      var r = state.lastReport;
      var doc = TM.reportDocument(TM.buildReportHTML(r.model, r.analysis),
        (r.model.meta.name || 'Threat model') + ' — STRIDE report', TM.REPORT_CSS);
      download(slug(state.model.meta.name || 'threat-model') + '-stride-report.html', doc, 'text/html');
    });
    $('btnReportCsv').addEventListener('click', function () {
      var r = state.lastReport;
      download(slug(state.model.meta.name || 'threat-model') + '-threats.csv',
        TM.buildReportCSV(r.model, r.analysis), 'text/csv');
    });
    $('btnReportPrint').addEventListener('click', function () { window.print(); });
  }

  function bindShortcuts() {
    document.addEventListener('keydown', function (e) {
      var t = e.target;
      var typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT');
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z' && !e.shiftKey) {
        e.preventDefault(); undo(); return;
      }
      if ((e.ctrlKey || e.metaKey) && (e.key.toLowerCase() === 'y' || (e.shiftKey && e.key.toLowerCase() === 'z'))) {
        e.preventDefault(); redo(); return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault(); $('btnSave').click(); return;
      }
      if (e.key === 'Escape') {
        Array.prototype.forEach.call(document.querySelectorAll('.modal'), function (m) { m.hidden = true; });
      }
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
      var map = { v: 'select', e: 'entity', p: 'process', d: 'datastore', f: 'flow', b: 'boundary', a: 'asset' };
      var tool = map[e.key.toLowerCase()];
      if (tool) {
        if (tool !== 'select') checkpoint();
        state.diagram.setTool(tool);
      }
    });
  }

  /* ---------------------------------------------------------------------
   * Properties panel
   * ------------------------------------------------------------------- */
  function renderProps(id, opts) {
    opts = opts || {};
    var body = $('propsBody');
    var empty = $('propsEmpty');
    var el = id ? TM.elementById(state.model, id) : null;

    if (!el) {
      body.hidden = true;
      empty.hidden = false;
      renderModelMeta(empty);
      return;
    }
    empty.hidden = true;
    body.hidden = false;

    /* Preserve which field had focus across the re-render that follows an edit. */
    var activeKey = document.activeElement && document.activeElement.getAttribute
      ? document.activeElement.getAttribute('data-field') : null;
    var selStart = document.activeElement && document.activeElement.selectionStart;

    body.innerHTML = '';
    var type = TM.TYPES[el.type];

    var head = document.createElement('div');
    head.className = 'prop-head';
    head.innerHTML = '<span class="prop-badge">' + type.label + '</span>' +
      '<span class="muted" style="font-size:11px;color:#5b6478">' + escapeHtml(type.shape) + '</span>';
    body.appendChild(head);

    /* STRIDE applicability reminder */
    var cats = TM.applicableCategories(el.type);
    var hint = document.createElement('div');
    hint.className = 'stride-hint';
    if (cats.length) {
      hint.innerHTML = '<b>STRIDE for ' + type.label.toLowerCase() + 's:</b> ' +
        cats.map(function (c) { return c.key + ' — ' + c.name; }).join(', ') +
        '. <br>' + escapeHtml(cats[0].question);
    } else {
      hint.innerHTML = '<b>Trust boundaries are context, not a target.</b> They are not analysed directly — ' +
        'they raise the risk of every data flow that crosses them.';
    }
    body.appendChild(hint);

    body.appendChild(field({
      key: 'title', label: 'Title', type: 'text', value: el.title,
      help: 'Short name shown inside the shape.'
    }, el));
    body.appendChild(field({
      key: 'description', label: 'Description', type: 'textarea', value: el.description,
      help: 'What it is and what it does. Shown on the diagram and quoted in the report.'
    }, el));

    if (el.type === 'flow') {
      var from = TM.nodeById(state.model, el.from), to = TM.nodeById(state.model, el.to);
      var route = document.createElement('div');
      route.className = 'field';
      route.innerHTML = '<label>Route</label><div style="font-size:12.5px">' +
        escapeHtml(TM.label(from)) + ' &rarr; ' + escapeHtml(TM.label(to)) + '</div>';
      var swap = document.createElement('button');
      swap.className = 'btn btn-sm';
      swap.style.marginTop = '5px';
      swap.textContent = 'Reverse direction';
      swap.addEventListener('click', function () {
        checkpoint();
        var tmp = el.from; el.from = el.to; el.to = tmp;
        state.diagram.render(); onModelChanged();
      });
      route.appendChild(swap);
      body.appendChild(route);
      body.appendChild(checkbox('bidirectional', 'Bidirectional (data moves both ways)', el.bidirectional, el));

      var crossed = TM.boundariesCrossed(state.model, el);
      var cb = document.createElement('div');
      cb.className = 'field';
      cb.innerHTML = '<label>Trust boundaries crossed</label>' +
        (crossed.length
          ? '<div class="tag-list">' + crossed.map(function (b) {
              return '<span class="tag" style="border-color:#f0c4c4;color:#a13030">' + escapeHtml(TM.label(b)) + '</span>';
            }).join('') + '</div>'
          : '<div class="field-help">None. Move an endpoint inside a trust boundary and this flow will be analysed as a boundary crossing.</div>');
      body.appendChild(cb);
    }

    if (el.type !== 'boundary' && el.type !== 'asset') {
      body.appendChild(checkbox('isAsset', 'Mark as an asset (adds the ▲ marker)', el.isAsset, el));
    }

    /* Category fields, grouped */
    var fields = TM.fieldsFor(el.type);
    var groups = {};
    var order = [];
    fields.forEach(function (f) {
      if (!groups[f.group]) { groups[f.group] = []; order.push(f.group); }
      groups[f.group].push(f);
    });
    order.forEach(function (groupName) {
      var fs = document.createElement('fieldset');
      var lg = document.createElement('legend');
      lg.textContent = groupName;
      fs.appendChild(lg);
      groups[groupName].forEach(function (f) {
        fs.appendChild(field({
          key: 'props.' + f.key,
          label: f.label,
          type: f.type === 'text' ? 'text' : 'select',
          options: f.options,
          value: (el.props && el.props[f.key]) || (f.type === 'text' ? '' : TM.UNSET),
          help: f.help
        }, el));
      });
      body.appendChild(fs);
    });

    body.appendChild(field({
      key: 'existingControls', label: 'Controls already in place', type: 'textarea',
      value: el.existingControls,
      help: 'Anything already mitigating these threats. Quoted next to each finding in the report.'
    }, el));

    var actions = document.createElement('div');
    actions.className = 'prop-actions';
    if (el.type !== 'flow') {
      var dup = document.createElement('button');
      dup.className = 'btn btn-sm';
      dup.textContent = 'Duplicate';
      dup.addEventListener('click', function () {
        checkpoint();
        var copy = JSON.parse(JSON.stringify(el));
        copy.id = TM.newId(el.type);
        copy.x += 24; copy.y += 24;
        state.model.nodes.push(copy);
        state.diagram.select(copy.id);
        onModelChanged();
      });
      actions.appendChild(dup);
    }
    var del = document.createElement('button');
    del.className = 'btn btn-sm btn-danger';
    del.textContent = 'Delete';
    del.addEventListener('click', function () {
      checkpoint();
      state.diagram.deleteSelected();
    });
    actions.appendChild(del);
    body.appendChild(actions);

    if (opts.focus) {
      var first = body.querySelector('[data-field="title"]');
      if (first) { first.focus(); first.select(); }
    } else if (opts.keepFocus && activeKey) {
      var back = body.querySelector('[data-field="' + activeKey + '"]');
      if (back) {
        back.focus();
        if (selStart !== undefined && selStart !== null && back.setSelectionRange) {
          try { back.setSelectionRange(selStart, selStart); } catch (e) { /* selects have no range */ }
        }
      }
    }
  }

  /** Model-level metadata form, shown when nothing is selected. */
  function renderModelMeta(container) {
    container.innerHTML = '<h2>Threat model details</h2>';
    var meta = state.model.meta;
    [
      { key: 'system', label: 'System / scope name', type: 'text', help: 'The system this diagram describes.' },
      { key: 'author', label: 'Author(s)', type: 'text' },
      { key: 'date', label: 'Date', type: 'text' },
      { key: 'scope', label: 'Scope and assumptions', type: 'textarea', help: 'What is in scope, what is explicitly out, and what you are assuming. Printed at the top of the report.' }
    ].forEach(function (f) {
      var wrap = document.createElement('div');
      wrap.className = 'field';
      var lbl = document.createElement('label');
      lbl.textContent = f.label;
      wrap.appendChild(lbl);
      var input = document.createElement(f.type === 'textarea' ? 'textarea' : 'input');
      if (f.type !== 'textarea') input.type = 'text';
      input.value = meta[f.key] || '';
      input.setAttribute('data-field', 'meta.' + f.key);
      input.addEventListener('input', function () { meta[f.key] = input.value; autosave(); });
      input.addEventListener('focus', function () { checkpoint(); });
      wrap.appendChild(input);
      if (f.help) {
        var h = document.createElement('div');
        h.className = 'field-help';
        h.textContent = f.help;
        wrap.appendChild(h);
      }
      container.appendChild(wrap);
    });
    var p = document.createElement('p');
    p.style.fontSize = '12px';
    p.style.color = '#5b6478';
    p.textContent = 'Select an element or data flow on the diagram to edit its title, description and security categories.';
    container.appendChild(p);
  }

  /** Build a labelled input bound to a (possibly nested) key on `el`. */
  function field(def, el) {
    var wrap = document.createElement('div');
    wrap.className = 'field';
    var lbl = document.createElement('label');
    lbl.textContent = def.label;
    wrap.appendChild(lbl);

    var input;
    if (def.type === 'select') {
      input = document.createElement('select');
      (def.options || []).forEach(function (opt) {
        var o = document.createElement('option');
        o.value = opt; o.textContent = opt;
        input.appendChild(o);
      });
      input.value = def.value || TM.UNSET;
    } else if (def.type === 'textarea') {
      input = document.createElement('textarea');
      input.value = def.value || '';
    } else {
      input = document.createElement('input');
      input.type = 'text';
      input.value = def.value || '';
    }
    input.setAttribute('data-field', def.key);

    function write(value) {
      if (def.key.indexOf('props.') === 0) {
        el.props = el.props || {};
        el.props[def.key.slice(6)] = value;
      } else {
        el[def.key] = value;
      }
    }

    if (def.type === 'select') {
      input.addEventListener('change', function () {
        checkpoint();
        write(input.value);
        state.diagram.render();
        onModelChanged();
      });
    } else {
      var dirty = false;
      input.addEventListener('focus', function () { dirty = false; });
      input.addEventListener('input', function () {
        if (!dirty) { checkpoint(); dirty = true; }
        write(input.value);
        state.diagram.render();
        updateCounts();
        autosave();
      });
    }
    wrap.appendChild(input);

    if (def.help) {
      var h = document.createElement('div');
      h.className = 'field-help';
      h.textContent = def.help;
      wrap.appendChild(h);
    }
    return wrap;
  }

  function checkbox(key, label, value, el) {
    var wrap = document.createElement('label');
    wrap.className = 'check';
    var input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = !!value;
    input.setAttribute('data-field', key);
    input.addEventListener('change', function () {
      checkpoint();
      el[key] = input.checked;
      state.diagram.render();
      onModelChanged();
    });
    wrap.appendChild(input);
    wrap.appendChild(document.createTextNode(' ' + label));
    var box = document.createElement('div');
    box.className = 'field';
    box.appendChild(wrap);
    return box;
  }

  /* ---------------------------------------------------------------------
   * Report
   * ------------------------------------------------------------------- */
  function openReport() {
    var analysis = TM.analyze(state.model);
    state.lastReport = { model: state.model, analysis: analysis };
    $('reportContent').innerHTML = TM.buildReportHTML(state.model, analysis);
    $('reportModal').hidden = false;
    $('reportContent').scrollTop = 0;
    status(analysis.stats.total + ' threat(s) identified.');
  }

  /* ---------------------------------------------------------------------
   * Help
   * ------------------------------------------------------------------- */
  function openHelp() {
    $('helpContent').innerHTML = [
      '<h3>1. Draw the diagram</h3>',
      '<p>Pick a shape in the left palette, then click the canvas. Every shape follows the standard legend:</p>',
      '<table><thead><tr><th>Element</th><th>Symbol</th><th>Represents</th></tr></thead><tbody>',
      ['entity', 'process', 'datastore', 'flow', 'boundary', 'asset'].map(function (t) {
        return '<tr><td><b>' + TM.TYPES[t].label + '</b></td><td>' + TM.TYPES[t].shape + '</td><td>' + TM.TYPES[t].legend + '</td></tr>';
      }).join(''),
      '</tbody></table>',
      '<ul>',
      '<li>Drag to move, drag a corner handle to resize, drag empty canvas to pan, scroll to zoom.</li>',
      '<li>Dragging a trust boundary moves everything inside it.</li>',
      '<li>To connect: press the <b>Data flow</b> tool, click the source element, then the destination.</li>',
      '<li>Any element can be flagged as an <b>asset</b> in the properties panel — it gets the ▲ marker.</li>',
      '<li>A flow drawn between elements that sit in different trust boundaries is drawn dashed and analysed more strictly.</li>',
      '</ul>',
      '<h3>2. Annotate</h3>',
      '<p>Select an element and fill in the title, description and the security categories on the right. ' +
      'The categories are the input to the report: data classification and availability need set the impact, ' +
      'exposure and trust level set the likelihood, and the control questions (authentication, authorisation, ' +
      'encryption, logging, validation, throttling, backup) decide which threats fire.</p>',
      '<p>Leave a category on <em>not set</em> and it is reported as a coverage gap rather than assumed safe — ' +
      'that distinction is worth making explicit with a class.</p>',
      '<h3>3. Generate the report</h3>',
      '<p>Press <b>STRIDE report</b>. The report applies STRIDE per element:</p>',
      '<table><thead><tr><th>Letter</th><th>Threat</th><th>Violates</th><th>Applies to</th></tr></thead><tbody>',
      TM.STRIDE_ORDER.map(function (c) {
        var s = TM.STRIDE[c];
        var applies = Object.keys(TM.APPLICABILITY).filter(function (t) {
          return TM.APPLICABILITY[t].indexOf(c) !== -1;
        }).map(function (t) { return TM.TYPES[t].label; }).join(', ');
        return '<tr><td><b>' + c + '</b></td><td>' + s.name + '</td><td>' + s.property + '</td><td>' + applies + '</td></tr>';
      }).join(''),
      '</tbody></table>',
      '<p>Download it as Markdown, HTML or CSV (one row per threat, for a risk register), or print to PDF.</p>',
      '<h3>4. Export the picture</h3>',
      '<p><b>Export PNG</b> or <b>Export SVG</b> writes the diagram, its title and the legend to an image file. ' +
      'The grid and selection handles are never included.</p>',
      '<h3>Keyboard</h3>',
      '<p><kbd>V</kbd> select · <kbd>E</kbd> entity · <kbd>P</kbd> process · <kbd>D</kbd> data store · ' +
      '<kbd>F</kbd> flow · <kbd>B</kbd> boundary · <kbd>A</kbd> asset · <kbd>Del</kbd> delete · ' +
      '<kbd>Esc</kbd> cancel · <kbd>Ctrl</kbd>+<kbd>Z</kbd> undo · <kbd>Ctrl</kbd>+<kbd>Y</kbd> redo · ' +
      '<kbd>Ctrl</kbd>+<kbd>S</kbd> save · arrows nudge, <kbd>Shift</kbd>+arrows nudge by grid.</p>',
      '<h3>Saving</h3>',
      '<p>The diagram is kept in this browser automatically. <b>Save .json</b> writes a portable file you can hand ' +
      'to students or check into a repository; <b>Open…</b> loads it back.</p>'
    ].join('');
    $('helpModal').hidden = false;
  }

  /* ---------------------------------------------------------------------
   * Utilities
   * ------------------------------------------------------------------- */
  function download(filename, content, mime) {
    var blob = new Blob([content], { type: mime + ';charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function slug(s) {
    return String(s || 'threat-model').toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '').slice(0, 60) || 'threat-model';
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* ---------------------------------------------------------------------
   * Worked example - a small patient portal, deliberately imperfect so the
   * generated report has something to say in every STRIDE category.
   * ------------------------------------------------------------------- */
  function sampleModel() {
    var m = TM.emptyModel();
    m.meta = {
      name: 'Patient portal (worked example)',
      system: 'Web portal that lets patients view results and message their clinician',
      author: 'Teaching example',
      date: new Date().toISOString().slice(0, 10),
      scope: 'In scope: the portal web tier, its API, the records database and the billing integration. ' +
        'Out of scope: the clinical EHR itself, corporate IT and physical security of the data centre.'
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

    var internet = node('boundary', 40, 40, 360, 480, 'Internet',
      'Anything outside our control.', { boundaryKind: 'Internet / DMZ perimeter' });
    var corp = node('boundary', 460, 40, 620, 480, 'Hosting VPC (internal network)',
      'Our managed cloud environment.', { boundaryKind: 'Network segment' });
    void internet; void corp;

    var patient = node('entity', 100, 120, 160, 70, 'Patient',
      'Members of the public using the portal from their own devices.', {
        entityKind: 'Human user',
        trustLevel: 'Untrusted (anonymous)',
        authentication: 'Username + password',
        logging: 'Errors only',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Medium'
      });

    var clinician = node('entity', 100, 260, 160, 70, 'Clinician',
      'Staff replying to messages and releasing results.', {
        entityKind: 'Privileged user / administrator',
        trustLevel: 'Semi-trusted (authenticated)',
        authentication: 'Username + password',
        logging: 'Security events logged',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'High'
      });

    var billing = node('entity', 100, 400, 160, 70, 'Billing SaaS',
      'Third-party billing provider.', {
        entityKind: 'Third-party service',
        trustLevel: 'Semi-trusted (authenticated)',
        authentication: 'Shared secret or API key',
        logging: 'None',
        dataClassification: 'Confidential',
        criticality: 'Low'
      });

    var web = node('process', 520, 110, 180, 92, 'Portal web app',
      'Server-rendered front end.', {
        exposure: 'Internet-facing',
        privilege: 'Least privilege',
        inputValidation: 'Partial / deny-list',
        resilience: 'Timeouts only',
        authentication: 'Session token / JWT',
        authorization: 'Role-based (RBAC)',
        logging: 'Security events logged',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'High',
        owner: 'Portal team'
      });

    var api = node('process', 790, 110, 180, 92, 'Records API',
      'Reads and writes patient records.', {
        exposure: 'Internal network',
        privilege: 'Elevated service account',
        inputValidation: 'None',
        resilience: 'None',
        authentication: 'None / anonymous',
        authorization: 'Simple ownership check',
        logging: 'Errors only',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'High',
        owner: 'Platform team'
      });

    var db = node('datastore', 790, 290, 190, 76, 'Patient records DB',
      'PostgreSQL: results, messages, demographics.', {
        storeKind: 'Relational database',
        encryptionAtRest: 'Full-disk / volume',
        integrity: 'Constraints / checksums',
        backup: 'Backups, never tested',
        authentication: 'Shared secret or API key',
        authorization: 'Shared credential for everyone',
        logging: 'None',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Critical (safety / life)',
        owner: 'Platform team'
      }, true);

    var audit = node('datastore', 520, 290, 190, 76, 'Application log store',
      'Aggregated application and access logs.', {
        storeKind: 'Object / blob storage',
        encryptionAtRest: 'None',
        integrity: 'None',
        backup: 'Tested backups with retention',
        authentication: 'Session token / JWT',
        authorization: 'Role-based (RBAC)',
        logging: 'Errors only',
        dataClassification: 'Confidential',
        criticality: 'Medium'
      });

    var phi = node('asset', 620, 420, 96, 82, 'PHI',
      '', {
        assetKind: 'Information',
        dataClassification: 'Restricted (PII / PHI / PCI)',
        criticality: 'Critical (safety / life)',
        owner: 'Chief Privacy Officer'
      });
    void phi;

    flow(patient, web, 'Portal session', 'Login, results, secure messaging.', {
      protocol: 'HTTPS / TLS',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'None',
      authentication: 'Session token / JWT',
      authorization: 'Role-based (RBAC)',
      logging: 'Security events logged',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'High'
    }, true);

    flow(clinician, web, 'Clinician workspace', 'Review and release results, reply to messages.', {
      protocol: 'HTTPS / TLS',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'Timeouts only',
      authentication: 'Username + password',
      authorization: 'Role-based (RBAC)',
      logging: 'Security events logged',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'High'
    }, true);

    flow(web, api, 'Record lookup', 'Internal service call.', {
      protocol: 'HTTP (cleartext)',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'None / anonymous',
      authorization: 'None',
      logging: 'None',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'High'
    }, true);

    flow(api, db, 'SQL queries', 'Reads and writes patient records.', {
      protocol: 'SQL / database protocol',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'None',
      authentication: 'Shared secret or API key',
      authorization: 'Shared credential for everyone',
      logging: 'None',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'Critical (safety / life)'
    }, true);

    flow(web, audit, 'Application logs', 'Request and error logs shipped to the log store.', {
      protocol: 'HTTPS / TLS',
      encryptionInTransit: 'TLS (server authenticated)',
      flowIntegrity: 'Transport (TLS) only',
      throttling: 'Timeouts only',
      authentication: 'Shared secret or API key',
      authorization: 'Role-based (RBAC)',
      logging: 'Errors only',
      dataClassification: 'Confidential',
      criticality: 'Low'
    });

    flow(api, billing, 'Billing export', 'Nightly claim export.', {
      protocol: 'Physical / manual transfer',
      encryptionInTransit: 'None (cleartext)',
      flowIntegrity: 'None',
      throttling: 'None',
      authentication: 'Shared secret or API key',
      authorization: 'Shared credential for everyone',
      logging: 'None',
      dataClassification: 'Restricted (PII / PHI / PCI)',
      criticality: 'Low'
    });

    return m;
  }

  TM.sampleModel = sampleModel;
  TM.app = state;   /* exposed for debugging and for automated checks */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})(window.TM);
