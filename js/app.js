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
      onSelect: function (id, opts) {
        renderProps(id, opts);
        $('btnDelete').disabled = !id;
      },
      onContextMenu: openContextMenu,
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
    bindContextMenu();
    bindReportInteractions();

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
    $('btnDelete').addEventListener('click', function () {
      if (!state.diagram.selectionId) return;
      checkpoint();
      state.diagram.deleteSelected();
      $('btnDelete').disabled = true;
      status('Deleted.');
    });

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
          var opened = TM.deserialize(String(reader.result));
          var badProfile = opened.scoringErrors && opened.scoringErrors.length;
          setModel(opened, { resetHistory: true, fit: true });
          if (badProfile) {
            status('Opened ' + file.name + ' — its scoring profile was rejected, using the built-in scale.');
            alert('This file contains a severity scoring profile that could not be used:\n\n' +
              opened.scoringErrors.join('\n') + '\n\nThe built-in scale is being used instead.');
          } else {
            status('Opened ' + file.name);
          }
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

    $('btnReport').addEventListener('click', function () { openReport(); });
    $('btnHelp').addEventListener('click', openHelp);
    $('btnScoring').addEventListener('click', openScoring);

    $('btnScoringTemplate').addEventListener('click', function () {
      download('stride-scoring-profile-template.json', scoringTemplate(), 'application/json');
    });
    $('btnScoringImport').addEventListener('click', function () { $('scoringFileInput').click(); });
    $('scoringFileInput').addEventListener('change', function (e) {
      var file = e.target.files && e.target.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () { applyScoringText(String(reader.result)); };
      reader.readAsText(file);
      e.target.value = '';
    });

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
    $('btnSafetyCsv').addEventListener('click', function () {
      var r = state.lastReport;
      if (!r.analysis.safetyTrace.length) {
        alert('Nothing to trace yet: no element on the diagram has a safety-relevant function.\n\n' +
          'Select an element and tick what it does under "Patient safety" — controls therapy, raises alarms, ' +
          'implements a safety stop, and so on.');
        return;
      }
      download(slug(state.model.meta.name || 'threat-model') + '-safety-traceability.csv',
        TM.buildSafetyTraceCSV(r.model, r.analysis), 'text/csv');
      status('Safety traceability matrix exported.');
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
   * Context menu
   * ------------------------------------------------------------------- */
  function bindContextMenu() {
    document.addEventListener('pointerdown', function (e) {
      var menu = $('contextMenu');
      if (menu.hidden) return;
      if (!menu.contains(e.target)) closeContextMenu();
    }, true);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeContextMenu();
    });
    window.addEventListener('blur', closeContextMenu);
    window.addEventListener('resize', closeContextMenu);
  }

  function closeContextMenu() {
    var menu = $('contextMenu');
    menu.hidden = true;
    menu.innerHTML = '';
  }

  /**
   * Build the right-click menu for whatever was clicked: an element, a data
   * flow, or empty canvas.
   */
  function openContextMenu(id, pos) {
    var menu = $('contextMenu');
    menu.innerHTML = '';
    var el = id ? TM.elementById(state.model, id) : null;
    var items = [];

    if (el) {
      items.push({ title: TM.TYPES[el.type].label + ': ' + TM.label(el) });
      items.push({
        label: 'Edit properties', shortcut: 'dbl-click',
        action: function () { state.diagram.select(el.id, { focus: true }); }
      });
      if (el.type !== 'flow' && el.type !== 'boundary') {
        items.push({
          label: 'Draw data flow from here', shortcut: 'F',
          action: function () { state.diagram.startFlowFrom(el.id); }
        });
      }
      if (el.type === 'flow') {
        items.push({
          label: 'Reverse direction',
          action: function () {
            checkpoint();
            var t = el.from; el.from = el.to; el.to = t;
            state.diagram.render(); onModelChanged();
          }
        });
        items.push({
          label: el.bidirectional ? 'Make one-way' : 'Make bidirectional',
          action: function () {
            checkpoint();
            el.bidirectional = !el.bidirectional;
            state.diagram.render(); onModelChanged();
          }
        });
      }
      if (el.type !== 'boundary' && el.type !== 'asset') {
        items.push({
          label: el.isAsset ? 'Unmark as asset' : 'Mark as asset',
          action: function () {
            checkpoint();
            el.isAsset = !el.isAsset;
            state.diagram.render(); onModelChanged();
          }
        });
      }
      if (el.type !== 'flow') {
        items.push({
          label: 'Duplicate',
          action: function () {
            checkpoint();
            var copy = JSON.parse(JSON.stringify(el));
            copy.id = TM.newId(el.type);
            copy.x += 24; copy.y += 24;
            state.model.nodes.push(copy);
            state.diagram.select(copy.id);
            onModelChanged();
          }
        });
      }
      items.push({ separator: true });
      items.push({
        label: 'Delete', shortcut: 'Del', danger: true,
        action: function () {
          checkpoint();
          state.diagram.deleteById(el.id);
          $('btnDelete').disabled = true;
          status('Deleted.');
        }
      });
    } else {
      items.push({ title: 'Add here' });
      TM.NODE_TYPES.forEach(function (type) {
        items.push({
          label: TM.TYPES[type].label,
          action: function () { state.diagram.addNode(type, pos.world); }
        });
      });
      items.push({ separator: true });
      items.push({ label: 'Fit to content', action: function () { state.diagram.zoomFit(); } });
    }

    items.forEach(function (item) {
      var li = document.createElement('li');
      if (item.separator) {
        li.className = 'menu-sep';
      } else if (item.title) {
        li.className = 'menu-title';
        li.textContent = item.title;
      } else {
        var btn = document.createElement('button');
        btn.type = 'button';
        if (item.danger) btn.className = 'danger';
        var span = document.createElement('span');
        span.textContent = item.label;
        btn.appendChild(span);
        if (item.shortcut) {
          var sc = document.createElement('span');
          sc.className = 'shortcut';
          sc.textContent = item.shortcut;
          btn.appendChild(sc);
        }
        btn.addEventListener('click', function () {
          closeContextMenu();
          item.action();
        });
        li.appendChild(btn);
      }
      menu.appendChild(li);
    });

    /* Show first so it can be measured, then keep it inside the viewport. */
    menu.hidden = false;
    menu.style.left = '0px';
    menu.style.top = '0px';
    var rect = menu.getBoundingClientRect();
    var x = Math.min(pos.clientX, window.innerWidth - rect.width - 8);
    var y = Math.min(pos.clientY, window.innerHeight - rect.height - 8);
    menu.style.left = Math.max(4, x) + 'px';
    menu.style.top = Math.max(4, y) + 'px';
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

    /* Patient safety summary: what this element can do to the patient. */
    var fns = TM.safetyFunctionsOf(el);
    if (fns.length) {
      var sh = document.createElement('div');
      sh.className = 'stride-hint safety-hint';
      var missing = [];
      if (TM.isUnset((el.props || {}).harmSeverity)) missing.push('severity of harm');
      if (!((el.props || {}).safetyFileRef || '').trim()) missing.push('safety file reference');
      sh.innerHTML = '<b>Reaches the patient:</b> ' +
        fns.map(function (k) {
          return '<span class="safety-flag">' + escapeHtml(TM.safetyFunction(k).short) + '</span>';
        }).join(' ') +
        '<br>Safety hazards are analysed for each of these and traced in the report.' +
        (missing.length ? '<br><b>Still needed for traceability:</b> ' + escapeHtml(missing.join(', ')) + '.' : '');
      body.appendChild(sh);
    }

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
      if (groupName === 'Patient safety') fs.className = 'fieldset-safety';
      groups[groupName].forEach(function (f) {
        var type = f.type === 'text' ? 'text'
          : f.type === 'textarea' ? 'textarea'
            : f.type === 'multi' ? 'multi' : 'select';
        var stored = el.props && el.props[f.key];
        fs.appendChild(field({
          key: 'props.' + f.key,
          label: f.label,
          type: type,
          options: f.options,
          value: stored !== undefined && stored !== null
            ? stored
            : (type === 'multi' ? [] : (type === 'select' ? TM.UNSET : '')),
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
      { key: 'system', label: 'System / device name', type: 'text', help: 'The system or device this diagram describes.' },
      { key: 'author', label: 'Author(s)', type: 'text' },
      { key: 'date', label: 'Date', type: 'text' },
      { key: 'intendedUse', label: 'Intended use', type: 'textarea', help: 'What the device is for, and for which patients. Everything about patient safety is judged against this.' },
      { key: 'scope', label: 'Scope and assumptions', type: 'textarea', help: 'What is in scope, what is explicitly out, and what you are assuming. Printed at the top of the report.' },
      { key: 'safetyDoc', label: 'Safety risk management file', type: 'text', help: 'The ISO 14971 risk management file this security analysis feeds, by name.' },
      { key: 'safetyDocRef', label: 'Safety file document ID / version', type: 'text', help: 'Printed on the traceability matrix so the two documents can be reconciled.' }
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

    /* Multi-select: a checkbox per option, stored as an array. Used for the
       safety-relevant functions, where an element can play several roles. */
    if (def.type === 'multi') {
      /* def.key is namespaced ("props.safetyFunctions"); the array lives under
         the bare key inside el.props. */
      var propKey = def.key.indexOf('props.') === 0 ? def.key.slice(6) : def.key;
      var selected = Array.isArray(def.value) ? def.value.slice() : [];
      var list = document.createElement('div');
      list.className = 'multi-list';
      (def.options || []).forEach(function (opt) {
        var row = document.createElement('label');
        row.className = 'multi-option';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = selected.indexOf(opt.value) !== -1;
        cb.setAttribute('data-field', def.key + '.' + opt.value);
        cb.addEventListener('change', function () {
          checkpoint();
          el.props = el.props || {};
          var current = Array.isArray(el.props[propKey]) ? el.props[propKey].slice() : [];
          var at = current.indexOf(opt.value);
          if (cb.checked && at === -1) current.push(opt.value);
          if (!cb.checked && at !== -1) current.splice(at, 1);
          el.props[propKey] = current;
          state.diagram.render();
          onModelChanged();
        });
        var textWrap = document.createElement('span');
        var strong = document.createElement('span');
        strong.className = 'multi-label';
        strong.textContent = opt.label;
        textWrap.appendChild(strong);
        if (opt.help) {
          var hint = document.createElement('span');
          hint.className = 'multi-help';
          hint.textContent = opt.help;
          textWrap.appendChild(hint);
        }
        row.appendChild(cb);
        row.appendChild(textWrap);
        list.appendChild(row);
      });
      wrap.appendChild(list);
      if (def.help) {
        var mh = document.createElement('div');
        mh.className = 'field-help';
        mh.textContent = def.help;
        wrap.appendChild(mh);
      }
      return wrap;
    }

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
  function openReport(opts) {
    opts = opts || {};
    var scrollTop = opts.keepScroll ? $('reportContent').scrollTop : 0;
    var analysis = TM.analyze(state.model);
    state.lastReport = { model: state.model, analysis: analysis };
    $('reportContent').innerHTML = TM.buildReportHTML(state.model, analysis, { interactive: true });
    $('reportModal').hidden = false;
    $('reportContent').scrollTop = scrollTop;
    if (opts.openCvssKey) {
      var box = $('reportContent').querySelector('[data-cvss-key="' + cssEscape(opts.openCvssKey) + '"]');
      if (box) {
        var form = box.querySelector('[data-cvss-form]');
        if (form) form.classList.add('open');
      }
    }
    status(analysis.stats.total + ' ' + (analysis.stats.total === 1 ? 'threat' : 'threats') + ' identified.');
  }

  function cssEscape(s) { return String(s).replace(/["\\]/g, '\\$&'); }

  /* ---------------------------------------------------------------------
   * CVSS v4.0 entry inside the report
   * ------------------------------------------------------------------- */
  function bindReportInteractions() {
    var root = $('reportContent');

    root.addEventListener('click', function (e) {
      var toggle = e.target.closest('[data-cvss-toggle]');
      if (toggle) {
        var form = toggle.parentNode.querySelector('[data-cvss-form]');
        if (form) form.classList.toggle('open');
        return;
      }
      var save = e.target.closest('[data-cvss-save]');
      if (save) { saveCvss(save.closest('[data-cvss-key]')); return; }
      var clear = e.target.closest('[data-cvss-clear]');
      if (clear) { clearCvss(clear.closest('[data-cvss-key]')); return; }
    });

    /* Enter in either field saves, so the form is usable without the mouse. */
    root.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      var box = e.target.closest && e.target.closest('[data-cvss-key]');
      if (!box) return;
      if (!e.target.matches('[data-cvss-vector], [data-cvss-score], [data-cvss-rationale]')) return;
      e.preventDefault();
      saveCvss(box);
    });
  }

  function saveCvss(box) {
    if (!box) return;
    var key = box.getAttribute('data-cvss-key');
    var vector = box.querySelector('[data-cvss-vector]').value;
    var score = box.querySelector('[data-cvss-score]').value;
    var rationaleEl = box.querySelector('[data-cvss-rationale]');
    var errBox = box.querySelector('[data-cvss-error]');

    var made = TM.CVSS4.makeAssessment(vector, score, rationaleEl ? rationaleEl.value : '');
    if (!made.ok) {
      errBox.hidden = false;
      errBox.innerHTML = made.errors.map(function (m) { return escapeHtml(m); }).join('<br>');
      return;
    }
    errBox.hidden = true;
    checkpoint();
    state.model.assessments = state.model.assessments || {};
    state.model.assessments[key] = made.assessment;
    autosave();
    openReport({ keepScroll: true, openCvssKey: key });
    status('CVSS v4.0 ' + made.assessment.score.toFixed(1) + ' (' + made.assessment.severity + ') recorded.');
  }

  function clearCvss(box) {
    if (!box) return;
    var key = box.getAttribute('data-cvss-key');
    checkpoint();
    if (state.model.assessments) delete state.model.assessments[key];
    autosave();
    openReport({ keepScroll: true, openCvssKey: key });
    status('CVSS score removed.');
  }

  /* ---------------------------------------------------------------------
   * Severity scoring profiles
   * ------------------------------------------------------------------- */
  function openScoring() {
    renderScoring(TM.serialize(TM.scoringOf(state.model)), null);
    $('scoringModal').hidden = false;
  }

  function renderScoring(jsonText, result) {
    var profile = TM.scoringOf(state.model);
    var custom = !!state.model.scoring;
    var box = $('scoringContent');

    var html = [];
    html.push('<div class="active-profile"><b>Active profile:</b> ' + escapeHtml(profile.name) +
      (custom ? '' : ' <span class="muted">(built in)</span>') +
      (profile.description ? '<div class="muted">' + escapeHtml(profile.description) + '</div>' : '') +
      '</div>');

    html.push('<p>Severity is scored as: <b>base rating of the rule</b> + category points + points for aggravating ' +
      'diagram context − points for mitigating context, mapped onto the levels below. Import your own profile to ' +
      'use your organisation\'s severity names, colours, thresholds and weightings. The profile is saved inside the ' +
      'threat model file.</p>');

    html.push('<table><thead><tr><th>Level</th><th>Applies from score</th><th>Colour</th></tr></thead><tbody>');
    profile.levels.slice().reverse().forEach(function (lv) {
      html.push('<tr><td><span class="level-swatch" style="background:' + escapeHtml(lv.color) + '"></span>' +
        escapeHtml(lv.label) + '</td><td>' + escapeHtml(String(lv.min)) + '</td><td><code>' +
        escapeHtml(lv.color) + '</code></td></tr>');
    });
    html.push('</tbody></table>');

    html.push('<h3>Profile JSON</h3>');
    html.push('<p class="muted" style="font-size:12px">Edit here, or import a file. ' +
      '<code>ruleScores</code> overrides the base score of individual rules by id — rule ids appear in the CSV export.</p>');
    html.push('<textarea id="scoringJson" spellcheck="false"></textarea>');
    html.push('<div class="scoring-actions">' +
      '<button class="btn btn-primary btn-sm" id="btnScoringApply">Apply profile</button>' +
      '<button class="btn btn-sm" id="btnScoringReset">Reset to built-in</button>' +
      '<button class="btn btn-sm" id="btnScoringDownload">Download this profile</button>' +
      '<label class="check" style="margin:0 0 0 6px"><input type="checkbox" id="chkCvssOverride"' +
      (profile.cvss && profile.cvss.useWhenPresent ? ' checked' : '') +
      '> CVSS scores override modelled severity</label>' +
      '</div>');

    if (result) {
      if (result.errors && result.errors.length) {
        html.push('<div class="validation bad"><b>Not applied — fix these first:</b><ul>' +
          result.errors.map(function (m) { return '<li>' + escapeHtml(m) + '</li>'; }).join('') + '</ul></div>');
      } else {
        html.push('<div class="validation ok"><b>' + escapeHtml(result.message || 'Profile applied.') + '</b>' +
          (result.warnings && result.warnings.length
            ? '<ul>' + result.warnings.map(function (m) { return '<li>' + escapeHtml(m) + '</li>'; }).join('') + '</ul>'
            : '') + '</div>');
      }
    }

    box.innerHTML = html.join('');
    $('scoringJson').value = jsonText;

    $('btnScoringApply').addEventListener('click', function () {
      applyScoringText($('scoringJson').value);
    });
    $('btnScoringReset').addEventListener('click', function () {
      checkpoint();
      state.model.scoring = null;
      autosave();
      renderScoring(TM.serialize(TM.DEFAULT_SCORING), { message: 'Reset to the built-in scale.', errors: [] });
      refreshReportIfOpen();
      status('Severity scoring reset to the built-in scale.');
    });
    $('btnScoringDownload').addEventListener('click', function () {
      download(slug(state.model.meta.name || 'threat-model') + '-scoring-profile.json',
        $('scoringJson').value, 'application/json');
    });
    $('chkCvssOverride').addEventListener('change', function (e) {
      checkpoint();
      var p = JSON.parse(TM.serialize(TM.scoringOf(state.model)));
      p.cvss = { useWhenPresent: e.target.checked };
      var checked = TM.validateScoring(p);
      state.model.scoring = checked.profile;
      autosave();
      renderScoring(TM.serialize(TM.scoringOf(state.model)), {
        message: e.target.checked
          ? 'CVSS scores will override the modelled severity where present.'
          : 'CVSS scores are recorded but will not override the modelled severity.',
        errors: []
      });
      refreshReportIfOpen();
    });
  }

  function applyScoringText(text) {
    var raw;
    try {
      raw = JSON.parse(text);
    } catch (err) {
      renderScoring(text, { errors: ['That is not valid JSON: ' + err.message] });
      return;
    }
    var checked = TM.validateScoring(raw);
    if (!checked.profile) {
      renderScoring(text, { errors: checked.errors });
      return;
    }
    checkpoint();
    state.model.scoring = checked.profile;
    autosave();
    renderScoring(TM.serialize(checked.profile), {
      message: 'Applied "' + checked.profile.name + '" with ' + checked.profile.levels.length + ' severity levels.',
      errors: [],
      warnings: checked.warnings
    });
    refreshReportIfOpen();
    status('Severity scoring profile applied: ' + checked.profile.name);
  }

  function refreshReportIfOpen() {
    if (!$('reportModal').hidden) openReport({ keepScroll: true });
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
      '<li>To connect: press the <b>Data flow</b> tool, click the source element, then the destination. ' +
      'Each flow gets its own connection point on the edge of an element, so several flows into the same box ' +
      'stay separate.</li>',
      '<li><b>Right-click</b> an element for its menu (edit, draw a flow from here, mark as asset, duplicate, ' +
      'delete), or right-click empty canvas to add an element there. Delete also works from the ' +
      '<b>Delete selected</b> button and the <kbd>Del</kbd> key.</li>',
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
      '<h3>2a. Patient safety</h3>',
      '<p>This is what separates a medical device threat model from an IT one. For each element, tick the ' +
      '<b>safety-relevant functions</b> it performs — whether it controls or actuates therapy, generates or carries ' +
      'alarms, implements a safety stop or interlock, produces clinical data, or is needed for timely care. Then set ' +
      'the worst-case <b>severity of harm</b>, the <b>IEC 62304 software safety class</b>, and the <b>safety file ' +
      'reference</b> (the hazard or risk control ID in your ISO 14971 risk management file).</p>',
      '<p>Elements that can reach the patient are marked on the diagram with a red badge and a letter per function ' +
      '(C control, A alarms, S safety stop, D clinical data, T care delivery). The report analyses each of those ' +
      'functions for the safety hazards a security compromise creates, states the <b>harm</b> in clinical terms, and ' +
      'gives every one a hazard reference (SEC-HAZ-nnn) you can carry into the safety file. Section 5 of the report ' +
      'is the traceability matrix, also downloadable as its own CSV.</p>',
      '<p>Three questions worth putting to a class for every element: could a compromise here <b>control the device ' +
      'in a way that harms the patient</b>? Could it cause <b>incorrect alarms</b> — real ones suppressed, or false ' +
      'ones injected? Could it <b>degrade a safety stop</b> so the last barrier does not engage? A "no" is an answer ' +
      'worth recording, not a blank.</p>',
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
      '<h3>3a. Severity scoring</h3>',
      '<p>The built-in scale rates each threat from the rule\'s base rating plus the diagram context. Press ' +
      '<b>Scoring…</b> to see exactly how that arithmetic works, or to import your own profile: your own severity ' +
      'names, colours, thresholds, per-category weights and per-rule overrides. The profile is stored inside the ' +
      'threat model file, so a class or a team all score the same way.</p>',
      '<h3>3b. CVSS v4.0</h3>',
      '<p>Any individual threat in the report can carry a <b>CVSS v4.0</b> assessment. Build the vector in the ' +
      '<a href="' + TM.CVSS4.CALCULATOR_URL + '" target="_blank" rel="noopener">NVD calculator</a>, then paste the ' +
      'vector and the score it produced into the finding. The vector is validated metric by metric; the score is ' +
      'taken as entered and its band (None / Low / Medium / High / Critical) replaces the modelled severity, unless ' +
      'you turn that off under <b>Scoring…</b>. Vectors and scores are saved with the model and appear in every ' +
      'export.</p>',
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

  /** A worked example of a custom profile, for people writing their own. */
  function scoringTemplate() {
    return JSON.stringify({
      _readme: [
        'Severity scoring profile for the STRIDE threat modeling tool.',
        'Score = baseScores[rule base rating] + categoryPoints[STRIDE letter]',
        '        + aggravatorPoints that apply - mitigatorPoints that apply',
        '        + harmSeverityPoints[severity of harm] for patient-safety threats.',
        'The score is then mapped onto the highest level whose "min" it reaches.',
        'Keys beginning with _ are ignored.'
      ],
      name: 'Example: four-point corporate scale',
      description: 'Replace the levels, colours and weights with your own risk standard.',
      levels: [
        { label: 'Observation', color: '#7d8ba6', min: 0 },
        { label: 'Minor', color: '#3f9c63', min: 2 },
        { label: 'Moderate', color: '#cbb01f', min: 3 },
        { label: 'Major', color: '#e07b1a', min: 4 },
        { label: 'Severe', color: '#c62828', min: 5.5 }
      ],
      baseScores: { info: 1, low: 2, medium: 3, high: 4, critical: 6 },
      categoryPoints: { S: 0, T: 0, R: 0, I: 0.5, D: 0, E: 0.5 },
      aggravatorPoints: {
        patientSafety: 0.5,
        sensitiveData: 0.5,
        externalExposure: 0.5,
        markedAsset: 0.5,
        safetyCriticalDoS: 0.5
      },
      mitigatorPoints: { publicData: 0.5, lowAvailabilityNeed: 0.5 },
      harmSeverityPoints: TM.HARM_SEVERITY.reduce(function (acc, level) {
        acc[level] = TM.HARM_SEVERITY_POINTS[level];
        return acc;
      }, {}),
      ruleScores: {
        'ds-i-rest': 5,
        'proc-e-chain': 6
      },
      cvss: { useWhenPresent: true }
    }, null, 2);
  }

  function slug(s) {
    return String(s || 'threat-model').toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '').slice(0, 60) || 'threat-model';
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* ---------------------------------------------------------------------
   * Worked example - a connected infusion pump, deliberately imperfect so the
   * generated report has something to say in every STRIDE category and in all
   * three patient-safety classes: device control, alarms and safety stops.
   * ------------------------------------------------------------------- */
  function sampleModel() {
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


  TM.sampleModel = sampleModel;
  TM.app = state;   /* exposed for debugging and for automated checks */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})(window.TM);
