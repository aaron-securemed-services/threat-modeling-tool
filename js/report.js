/* ---------------------------------------------------------------------------
 * report.js - turns an analysis into a readable STRIDE report in HTML,
 * Markdown or CSV.
 * --------------------------------------------------------------------------- */
window.TM = window.TM || {};

(function (TM) {
  'use strict';

  function esc(s) {
    return String(s === undefined || s === null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  /** Severity chip. Colours come from the scoring profile, so custom scales work. */
  function sevPill(sev) {
    return '<span class="pill" style="background:' + esc(sev.color) + '1f;color:' + esc(sev.color) + '">' +
      esc(String(sev.label).toUpperCase()) + '</span>';
  }
  function sevNote(sev) {
    if (sev.source === 'CVSS 4.0') {
      return '<span class="muted">CVSS 4.0 base score ' + esc(sev.score.toFixed ? sev.score.toFixed(1) : sev.score) + '</span>';
    }
    return '<span class="muted">model score ' + esc(sev.score) + '</span>';
  }
  function catTag(c) {
    return '<span class="stride-tag" title="' + esc(TM.STRIDE[c].name) + '">' + c + '</span>';
  }
  function typeLabel(t) { return TM.TYPES[t] ? TM.TYPES[t].label : t; }

  /** The safety-function chips for an element, or a dash. */
  function safetyFlags(el) {
    var fns = TM.safetyFunctionsOf(el);
    if (!fns.length) return '<span class="muted">—</span>';
    return fns.map(function (k) {
      var def = TM.safetyFunction(k);
      return '<span class="safety-flag" title="' + esc(def.label) + '">' + esc(def.short) + '</span>';
    }).join(' ');
  }
  function safetyFlagsText(el) {
    var fns = TM.safetyFunctionsOf(el);
    if (!fns.length) return '';
    return fns.map(function (k) { return TM.safetyFunction(k).short; }).join('; ');
  }
  function dash(v) { return TM.isUnset(v) ? '<span class="muted">not set</span>' : esc(v); }
  function plain(v) { return TM.isUnset(v) ? 'not set' : String(v); }

  /* ---------------------------------------------------------------------
   * HTML report body
   * ------------------------------------------------------------------- */
  /**
   * @param opts.interactive when true, each finding gets a CVSS v4.0 entry form
   *        (used in the app; downloaded reports show the stored values instead).
   */
  TM.buildReportHTML = function (model, a, opts) {
    opts = opts || {};
    var meta = model.meta || {};
    var out = [];
    var name = (meta.name || '').trim() || 'Untitled threat model';

    out.push('<h1>' + esc(name) + '</h1>');
    out.push('<p class="muted">STRIDE threat model report · generated ' + esc(new Date().toLocaleString()) + '</p>');

    out.push('<dl class="meta-grid">');
    if (meta.system) out.push('<dt>System</dt><dd>' + esc(meta.system) + '</dd>');
    if (meta.author) out.push('<dt>Author</dt><dd>' + esc(meta.author) + '</dd>');
    if (meta.date) out.push('<dt>Date</dt><dd>' + esc(meta.date) + '</dd>');
    if (meta.scope) out.push('<dt>Scope / assumptions</dt><dd>' + esc(meta.scope) + '</dd>');
    out.push('<dt>Methodology</dt><dd>STRIDE per element (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege)</dd>');
    if (meta.intendedUse) out.push('<dt>Intended use</dt><dd>' + esc(meta.intendedUse) + '</dd>');
    if (meta.safetyDoc || meta.safetyDocRef) {
      out.push('<dt>Safety risk management file</dt><dd>' +
        esc(meta.safetyDoc || 'Not named') +
        (meta.safetyDocRef ? ' <span class="muted">(' + esc(meta.safetyDocRef) + ')</span>' : '') +
        '</dd>');
    }
    out.push('<dt>Severity scale</dt><dd>' + esc(a.profile.name) +
      (a.stats.scored
        ? ' · ' + a.stats.scored + ' of ' + a.stats.total + ' ' +
          noun(a.stats.total, 'threat', 'threats') + ' scored with CVSS v4.0'
        : '') + '</dd>');
    out.push('</dl>');

    /* ---- summary ---- */
    out.push('<h2>1. Summary</h2>');
    out.push('<p>The diagram contains <b>' + a.stats.elements + '</b> analysed ' +
      noun(a.stats.elements, 'element', 'elements') + ' — ' +
      pl(count(model, 'entity'), 'entity', 'entities') + ', ' +
      pl(count(model, 'process'), 'process', 'processes') + ', ' +
      pl(count(model, 'datastore'), 'data store', 'data stores') + ' and ' +
      pl(a.stats.flows, 'data flow', 'data flows') + ' — inside <b>' + a.stats.boundaries + '</b> trust ' +
      noun(a.stats.boundaries, 'boundary', 'boundaries') + ', with <b>' + a.stats.assets + '</b> ' +
      noun(a.stats.assets, 'element', 'elements') + ' marked as ' + noun(a.stats.assets, 'an asset', 'assets') + '. <b>' +
      a.stats.total + '</b> ' + noun(a.stats.total, 'threat was', 'threats were') + ' identified.</p>');

    out.push('<table><thead><tr><th>Severity</th>' +
      a.stats.levels.map(function (lv) {
        return '<th class="num"><span class="level-swatch" style="background:' + esc(lv.color) + '"></span>' + esc(lv.label) + '</th>';
      }).join('') +
      '<th class="num">Total</th></tr></thead><tbody><tr><td>Threats</td>' +
      a.stats.levels.map(function (lv) { return '<td class="num">' + lv.count + '</td>'; }).join('') +
      '<td class="num"><b>' + a.stats.total + '</b></td></tr></tbody></table>');

    if (a.stats.scored) {
      var profileLabels = a.profile.levels.map(function (lv) { return lv.label; });
      var mixed = a.stats.levels.some(function (lv) { return profileLabels.indexOf(lv.label) === -1; });
      out.push('<p class="muted">' + a.stats.scored + ' of these ' +
        noun(a.stats.total, 'threat carries', 'threats carry') + ' a CVSS v4.0 assessment' +
        (mixed
          ? ', counted above under its CVSS band (None / Low / Medium / High / Critical) rather than under the levels of "' + esc(a.profile.name) + '".'
          : '.') + '</p>');
    }

    if (a.stats.safety) {
      out.push('<p class="safety-callout"><b>' + a.stats.safety + ' of these ' +
        noun(a.stats.total, 'threat', 'threats') + ' can affect patient safety</b>, across ' +
        pl(a.stats.safetyElements, 'element', 'elements') +
        ' with a safety-relevant function. They are listed with their hazard, harm and safety file ' +
        'reference in section 4, and traced in section 5.</p>');
      out.push('<table><thead><tr><th>Safety impact</th><th>What a compromise does to the patient</th>' +
        '<th class="num">Threats</th></tr></thead><tbody>');
      TM.SAFETY_FUNCTIONS.forEach(function (fn) {
        var n = a.stats.bySafetyFunction[fn.key] || 0;
        if (!n) return;
        out.push('<tr><td><span class="safety-flag">' + esc(fn.short) + '</span> ' + esc(fn.label) +
          '</td><td>' + esc(fn.harm) + '</td><td class="num">' + n + '</td></tr>');
      });
      out.push('</tbody></table>');
    } else if (a.stats.safetyElements === 0) {
      out.push('<p class="muted">No element on this diagram has been marked as safety-relevant. If this is a ' +
        'medical device, that is itself a finding: work through each element and record whether it can control ' +
        'the device, raise alarms, or implement a safety stop.</p>');
    }

    out.push('<table><thead><tr><th>STRIDE category</th><th>Security property</th><th class="num">Threats</th></tr></thead><tbody>');
    TM.STRIDE_ORDER.forEach(function (c) {
      var s = TM.STRIDE[c];
      out.push('<tr><td>' + catTag(c) + ' ' + esc(s.name) + '</td><td>' + esc(s.property) +
        '</td><td class="num">' + a.stats.byCategory[c] + '</td></tr>');
    });
    out.push('</tbody></table>');

    if (a.notes.length) {
      out.push('<h3>Modelling notes</h3><ul>');
      a.notes.forEach(function (n) { out.push('<li>' + esc(n) + '</li>'); });
      out.push('</ul>');
    }

    /* ---- inventory ---- */
    out.push('<h2>2. Diagram inventory</h2>');

    var boundaries = model.nodes.filter(function (n) { return n.type === 'boundary'; });
    if (boundaries.length) {
      out.push('<h3>2.1 Trust boundaries</h3><table><thead><tr><th>Boundary</th><th>Kind</th><th>Description</th></tr></thead><tbody>');
      boundaries.forEach(function (b) {
        out.push('<tr><td><b>' + esc(TM.label(b)) + '</b></td><td>' + dash(b.props.boundaryKind) +
          '</td><td>' + dash(b.description) + '</td></tr>');
      });
      out.push('</tbody></table>');
    }

    var nodes = model.nodes.filter(function (n) { return n.type !== 'boundary'; });
    if (nodes.length) {
      out.push('<h3>2.2 Elements</h3><table><thead><tr><th>Element</th><th>Type</th><th>Description</th>' +
        '<th>Classification</th><th>Safety impact</th><th>Severity of harm</th><th>In boundary</th>' +
        '<th>Asset</th></tr></thead><tbody>');
      nodes.forEach(function (n) {
        var inB = TM.boundariesContaining(model, n).map(TM.label).join(', ');
        out.push('<tr><td><b>' + esc(TM.label(n)) + '</b></td><td>' + typeLabel(n.type) + '</td><td>' +
          dash(n.description) + '</td><td>' + dash(n.props.dataClassification) + '</td><td>' +
          safetyFlags(n) + '</td><td>' + dash(n.props.harmSeverity) + '</td><td>' +
          (inB ? esc(inB) : '<span class="muted">—</span>') + '</td><td class="num">' +
          (n.isAsset || n.type === 'asset' ? '▲' : '') + '</td></tr>');
      });
      out.push('</tbody></table>');
    }

    if (model.flows.length) {
      out.push('<h3>2.3 Data flows</h3><table><thead><tr><th>Flow</th><th>Source</th><th>Destination</th>' +
        '<th>Protocol</th><th>Encryption</th><th>Crosses boundary</th><th>Classification</th></tr></thead><tbody>');
      model.flows.forEach(function (f) {
        var from = TM.nodeById(model, f.from), to = TM.nodeById(model, f.to);
        var crossed = TM.boundariesCrossed(model, f).map(TM.label).join(', ');
        out.push('<tr><td><b>' + esc(TM.label(f)) + '</b></td><td>' + esc(TM.label(from)) + '</td><td>' +
          esc(TM.label(to)) + (f.bidirectional ? ' <span class="muted">(bidirectional)</span>' : '') +
          '</td><td>' + dash(f.props.protocol) + '</td><td>' + dash(f.props.encryptionInTransit) +
          '</td><td>' + (crossed ? esc(crossed) : '<span class="muted">no</span>') + '</td><td>' +
          dash(f.props.dataClassification) + '</td></tr>');
      });
      out.push('</tbody></table>');
    }

    /* ---- coverage matrix ---- */
    out.push('<h2>3. STRIDE coverage matrix</h2>');
    out.push('<p class="muted">Each element is analysed only for the categories that can apply to it. ' +
      'A dot means the category applies and no threat was raised; a number is the count of threats found. ' +
      'A blank cell means the category does not apply to that element type.</p>');
    out.push('<table><thead><tr><th>Element</th><th>Type</th>' +
      TM.STRIDE_ORDER.map(function (c) { return '<th class="num" title="' + esc(TM.STRIDE[c].name) + '">' + c + '</th>'; }).join('') +
      '</tr></thead><tbody>');
    a.coverage.forEach(function (row) {
      out.push('<tr><td>' + esc(row.label) + '</td><td>' + typeLabel(row.type) + '</td>' +
        TM.STRIDE_ORDER.map(function (c) {
          var cell = row.cells[c];
          if (!cell.applicable) return '<td class="num muted">·</td>';
          return '<td class="num">' + (cell.count ? '<b>' + cell.count + '</b>' : '○') + '</td>';
        }).join('') + '</tr>');
    });
    out.push('</tbody></table>');

    /* ---- findings ---- */
    out.push('<h2>4. Threats and recommended mitigations</h2>');
    if (!a.findings.length) {
      out.push('<p>No threats were raised. With a diagram this size that usually means the security ' +
        'categories have not been filled in yet — see the coverage gaps below.</p>');
    } else {
      var byElement = {};
      var order = [];
      a.findings.forEach(function (f) {
        if (!byElement[f.elementId]) { byElement[f.elementId] = []; order.push(f.elementId); }
        byElement[f.elementId].push(f);
      });
      order.forEach(function (id) {
        var list = byElement[id];
        var elx = TM.elementById(model, id);
        out.push('<h3>' + esc(list[0].elementLabel) + ' <span class="muted">(' + typeLabel(list[0].elementType) + ')</span></h3>');
        if (elx && elx.description) out.push('<p class="muted">' + esc(elx.description) + '</p>');
        list.forEach(function (f) {
          out.push('<div class="finding" style="border-left-color:' + esc(f.severity.color) + '">');
          out.push('<div class="finding-head">' + catTag(f.category) + ' <strong>' + esc(f.ref) + ' · ' +
            esc(f.title) + '</strong> ' + sevPill(f.severity) + ' ' +
            (f.safety ? '<span class="safety-flag">Patient safety · ' + esc(f.safety.fnShort) + '</span> ' : '') +
            sevNote(f.severity) +
            ' <span class="muted">' + esc(TM.STRIDE[f.category].name) + ' — ' + esc(TM.STRIDE[f.category].property) + '</span></div>');
          out.push('<div>' + esc(f.threat) + '</div>');
          if (f.safety) out.push(safetyPanel(f));
          if (f.via) out.push('<div class="muted">Via data flow: ' + esc(f.via) + '</div>');
          if (f.crossings && f.crossings.length) {
            out.push('<div class="muted">Crosses: ' + esc(f.crossings.join(', ')) + '</div>');
          }
          if (f.existingControls) {
            out.push('<div class="mitig"><b>Controls already in place</b><div>' + esc(f.existingControls) + '</div></div>');
          }
          out.push('<div class="mitig"><b>Recommended mitigations</b><ul>' +
            f.mitigations.map(function (m) { return '<li>' + esc(m) + '</li>'; }).join('') + '</ul></div>');
          out.push(cvssBlock(f, opts.interactive));
          out.push('</div>');
        });
      });
    }

    /* ---- patient safety traceability ---- */
    out.push('<h2>5. Patient safety traceability</h2>');
    if (!a.safetyTrace.length) {
      out.push('<p>No element on this diagram carries a safety-relevant function, so there is nothing to trace ' +
        'to a safety risk management file. For a medical device, revisit this: mark every element that controls ' +
        'the device, produces clinical data, raises alarms, implements a safety stop, or is needed for timely care.</p>');
    } else {
      out.push('<p>Each row is a security threat with a credible path to patient harm. Carry the hazard reference ' +
        'into the safety risk management file' +
        (meta.safetyDoc ? ' (<b>' + esc(meta.safetyDoc) + '</b>' + (meta.safetyDocRef ? ', ' + esc(meta.safetyDocRef) : '') + ')' : '') +
        ' so the security control and the safety risk control are the same decision, evaluated once. ' +
        'Rows without a safety file reference are breaks in the trace and need closing.</p>');

      out.push('<table><thead><tr><th>Hazard ref</th><th>Threat</th><th>Element</th><th>STRIDE</th>' +
        '<th>Safety impact</th><th>Hazardous situation → harm</th><th>Severity of harm</th>' +
        '<th>Severity</th><th>Safety file ref</th></tr></thead><tbody>');
      a.safetyTrace.forEach(function (row) {
        if (!row.findings.length) return;
        row.findings.forEach(function (f) {
          out.push('<tr>' +
            '<td><b>' + esc(f.safety.hazardRef) + '</b></td>' +
            '<td>' + esc(f.ref) + '</td>' +
            '<td>' + esc(row.label) + ' <span class="muted">(' + typeLabel(row.type) + ')</span></td>' +
            '<td>' + catTag(f.category) + '</td>' +
            '<td>' + esc(TM.safetyFunction(f.safety.fn).short) + '</td>' +
            '<td>' + esc(f.title) + ' → ' + esc(f.safety.harm) + '</td>' +
            '<td>' + dash(row.severityOfHarm) + '</td>' +
            '<td>' + sevPill(f.severity) + '</td>' +
            '<td>' + (row.fileRef
              ? esc(row.fileRef)
              : '<span class="missing-trace">missing</span>') + '</td>' +
            '</tr>');
        });
      });
      out.push('</tbody></table>');

      var clean = a.safetyTrace.filter(function (r) { return !r.findings.length; });
      if (clean.length) {
        out.push('<h3>5.1 Safety-relevant elements with no threat raised</h3>');
        out.push('<p class="muted">These elements can reach the patient but no rule fired against them. That is a ' +
          'result, not an absence of one: record it in the safety file as a justified residual risk, with the ' +
          'controls that make it so.</p>');
        out.push('<table><thead><tr><th>Element</th><th>Safety functions</th><th>Severity of harm</th>' +
          '<th>Controls in place</th><th>Safety file ref</th></tr></thead><tbody>');
        clean.forEach(function (row) {
          out.push('<tr><td><b>' + esc(row.label) + '</b> <span class="muted">(' + typeLabel(row.type) + ')</span></td>' +
            '<td>' + row.functions.map(function (k) {
              return '<span class="safety-flag">' + esc(TM.safetyFunction(k).short) + '</span>';
            }).join(' ') + '</td>' +
            '<td>' + dash(row.severityOfHarm) + '</td>' +
            '<td>' + (row.existingControls ? esc(row.existingControls) : '<span class="muted">none recorded</span>') + '</td>' +
            '<td>' + (row.fileRef ? esc(row.fileRef) : '<span class="missing-trace">missing</span>') + '</td></tr>');
        });
        out.push('</tbody></table>');
      }

      if (a.safetyGaps.length) {
        out.push('<h3>5.2 Breaks in the safety trace</h3>');
        out.push('<table><thead><tr><th>Element</th><th>Type</th><th>What is missing</th></tr></thead><tbody>');
        a.safetyGaps.forEach(function (g) {
          out.push('<tr><td>' + esc(g.label) + '</td><td>' + typeLabel(g.type) + '</td><td>' + esc(g.issue) + '</td></tr>');
        });
        out.push('</tbody></table>');
      }

      out.push('<h3>5.3 How to use this section</h3>');
      out.push('<ul>' +
        '<li>Every hazard reference here should appear in the safety risk management file as a hazardous ' +
        'situation with a security cause, evaluated with the same severity scale as every other hazard.</li>' +
        '<li>The mitigations in section 4 are candidate <em>risk controls</em>. Once chosen, they need the same ' +
        'verification evidence as any other risk control, and the safety file should reference that evidence.</li>' +
        '<li>Check that a security control does not itself create a new hazard — a lockout that blocks a clinician ' +
        'in an emergency, or an update that reboots a device mid-therapy, is a safety risk of its own.</li>' +
        '<li>Re-run this analysis on every design change, and after any change to the safety file.</li>' +
        '</ul>');
    }

    /* ---- gaps ---- */
    out.push('<h2>6. Coverage gaps</h2>');
    if (!a.gaps.length) {
      out.push('<p>Every element has all of its security categories answered. Good — the analysis above is ' +
        'based on stated facts rather than assumptions.</p>');
    } else {
      out.push('<p class="muted">These questions have not been answered on the diagram. Unanswered categories are ' +
        'treated conservatively by the analysis, but an unanswered question is not the same as a control: ' +
        'close these before treating the report as complete.</p>');
      out.push('<table><thead><tr><th>Element</th><th>Type</th><th>Unanswered categories</th></tr></thead><tbody>');
      a.gaps.forEach(function (g) {
        out.push('<tr><td>' + esc(g.elementLabel) + (g.noDescription ? ' <span class="pill pill-info">no description</span>' : '') +
          '</td><td>' + typeLabel(g.elementType) + '</td><td>' + esc(g.fields.join(', ')) + '</td></tr>');
      });
      out.push('</tbody></table>');
    }

    /* ---- appendix ---- */
    out.push('<h2>Appendix A · STRIDE reference</h2>');
    out.push('<table><thead><tr><th>Letter</th><th>Threat</th><th>Property violated</th><th>Definition</th>' +
      '<th>Question to ask</th><th>Applies to</th></tr></thead><tbody>');
    TM.STRIDE_ORDER.forEach(function (c) {
      var s = TM.STRIDE[c];
      var applies = Object.keys(TM.APPLICABILITY).filter(function (t) {
        return TM.APPLICABILITY[t].indexOf(c) !== -1;
      }).map(typeLabel).join(', ');
      out.push('<tr><td>' + catTag(c) + '</td><td><b>' + esc(s.name) + '</b></td><td>' + esc(s.property) +
        '</td><td>' + esc(s.definition) + '</td><td>' + esc(s.question) + '</td><td>' + esc(applies) + '</td></tr>');
    });
    out.push('</tbody></table>');

    out.push('<h2>Appendix B · How severity was rated</h2>');
    var p = a.profile;
    out.push('<p>Severity scale in force: <b>' + esc(p.name) + '</b>' +
      (p.description ? ' — ' + esc(p.description) : '') + '.</p>');
    out.push('<p>Each rule carries a base rating, which is converted to a number and then adjusted by the diagram ' +
      'context: points are added for aggravating factors and subtracted for mitigating ones. The result is mapped ' +
      'onto the levels below.</p>');

    out.push('<table><thead><tr><th>Level</th><th class="num">Score from</th></tr></thead><tbody>');
    p.levels.slice().reverse().forEach(function (lv) {
      out.push('<tr><td><span class="level-swatch" style="background:' + esc(lv.color) + '"></span>' +
        esc(lv.label) + '</td><td class="num">' + esc(lv.min) + '</td></tr>');
    });
    out.push('</tbody></table>');

    out.push('<table><thead><tr><th>Factor</th><th class="num">Points</th></tr></thead><tbody>');
    ['info', 'low', 'medium', 'high', 'critical'].forEach(function (k) {
      out.push('<tr><td>Base rating: ' + cap(k) + '</td><td class="num">' + esc(p.baseScores[k]) + '</td></tr>');
    });
    var factorLabels = {
      patientSafety: 'Aggravating: the threat can reach the patient',
      sensitiveData: 'Aggravating: confidential or regulated data',
      externalExposure: 'Aggravating: internet-facing, anonymous-facing, or crosses an external boundary',
      markedAsset: 'Aggravating: element is marked as an asset',
      safetyCriticalDoS: 'Aggravating: availability threat to a safety-critical element',
      publicData: 'Mitigating: data is public',
      lowAvailabilityNeed: 'Mitigating: low availability need'
    };
    TM.SCORING_AGGRAVATORS.forEach(function (k) {
      out.push('<tr><td>' + esc(factorLabels[k]) + '</td><td class="num">+' + esc(p.aggravatorPoints[k]) + '</td></tr>');
    });
    TM.SCORING_MITIGATORS.forEach(function (k) {
      out.push('<tr><td>' + esc(factorLabels[k]) + '</td><td class="num">−' + esc(p.mitigatorPoints[k]) + '</td></tr>');
    });
    TM.STRIDE_ORDER.forEach(function (c) {
      if (!p.categoryPoints[c]) return;
      out.push('<tr><td>Category adjustment: ' + c + ' — ' + esc(TM.STRIDE[c].name) + '</td><td class="num">' +
        (p.categoryPoints[c] > 0 ? '+' : '') + esc(p.categoryPoints[c]) + '</td></tr>');
    });
    TM.HARM_SEVERITY.forEach(function (level) {
      var pts = (p.harmSeverityPoints && p.harmSeverityPoints[level]) || 0;
      if (!pts) return;
      out.push('<tr><td>Patient-safety threat, severity of harm: ' + esc(level) + '</td><td class="num">+' +
        esc(pts) + '</td></tr>');
    });
    out.push('</tbody></table>');
    out.push('<p class="muted">A threat that can reach the patient is weighted by the severity of the harm it could ' +
      'cause, not only by the data it touches — which is the point of doing this for a medical device rather than ' +
      'for an IT system.</p>');

    var overrides = Object.keys(p.ruleScores || {});
    if (overrides.length) {
      out.push('<p>Per-rule overrides in this profile: ' +
        overrides.map(function (id) { return '<code>' + esc(id) + '</code> → ' + esc(p.ruleScores[id]); }).join(', ') + '.</p>');
    }

    out.push('<h3>CVSS v4.0</h3>');
    out.push('<p>' + (p.cvss && p.cvss.useWhenPresent
      ? 'Where a CVSS v4.0 vector and base score have been entered for a threat, that score and its qualitative band replace the modelled rating, and the finding is labelled with its vector.'
      : 'CVSS v4.0 assessments are recorded but the profile is configured not to let them override the modelled rating.') +
      ' Vectors are validated against the CVSS v4.0 specification; the numeric score is entered by the assessor from the ' +
      '<a href="' + TM.CVSS4.CALCULATOR_URL + '" target="_blank" rel="noopener">NVD CVSS v4.0 calculator</a>. ' +
      'CVSS bands are None (0.0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9) and Critical (9.0–10.0).</p>');
    out.push('<p class="muted">Ratings are a starting point for the discussion, not a substitute for your own risk ' +
      'acceptance process.</p>');

    return out.join('\n');
  };

  /** The patient-safety consequence panel shown inside a safety finding. */
  function safetyPanel(f) {
    var s = f.safety;
    var out = ['<div class="safety-panel">'];
    out.push('<div class="safety-head"><b>Patient safety consequence</b> <span class="muted">' +
      esc(s.hazardRef || '') + ' · ' + esc(s.fnLabel) + '</span></div>');
    out.push('<div><b>Harm:</b> ' + esc(s.harm) + '</div>');
    if (s.notes) out.push('<div><b>Hazardous situation (as modelled):</b> ' + esc(s.notes) + '</div>');
    var bits = [];
    if (!TM.isUnset(s.severityOfHarm)) bits.push('Severity of harm: <b>' + esc(s.severityOfHarm) + '</b>');
    if (!TM.isUnset(s.softwareSafetyClass)) bits.push('Software safety class: ' + esc(s.softwareSafetyClass));
    bits.push(s.fileRef
      ? 'Safety file: <b>' + esc(s.fileRef) + '</b>'
      : '<span class="missing-trace">No safety file reference recorded</span>');
    out.push('<div class="muted">' + bits.join(' · ') + '</div>');
    out.push('</div>');
    return out.join('');
  }

  /**
   * The CVSS v4.0 panel for one finding. Interactive in the app (an editable
   * vector + score that is stored on the model); a static record of what was
   * entered in a downloaded report.
   */
  function cvssBlock(f, interactive) {
    var key = TM.assessmentKey(f.elementId, f.ruleId);
    var current = f.cvss;
    var out = ['<div class="cvss-box" data-cvss-key="' + esc(key) + '">'];

    if (current) {
      out.push('<div class="cvss-current"><b>CVSS v4.0</b> ' +
        '<span class="pill" style="background:' + esc(TM.CVSS4.color(current.severity)) + '1f;color:' +
        esc(TM.CVSS4.color(current.severity)) + '">' + esc(current.severity.toUpperCase()) + ' ' +
        esc(Number(current.score).toFixed(1)) + '</span> <code>' + esc(current.vector) + '</code>' +
        (current.updated ? ' <span class="muted">· entered ' + esc(current.updated) + '</span>' : '') +
        (current.rationale ? '<div class="muted">' + esc(current.rationale) + '</div>' : '') +
        '</div>');
    } else if (!interactive) {
      out.push('<div class="cvss-current muted">No CVSS v4.0 score recorded; severity is from the ' +
        'scoring profile.</div>');
    }

    if (interactive) {
      out.push('<button type="button" class="cvss-toggle" data-cvss-toggle>' +
        (current ? 'Edit CVSS v4.0 score' : 'Add a CVSS v4.0 score') + '</button>');
      out.push('<div class="cvss-form" data-cvss-form>');
      out.push('<div class="cvss-row">' +
        '<input type="text" data-cvss-vector spellcheck="false" placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" value="' +
        esc(current ? current.vector : '') + '">' +
        '<input type="text" class="cvss-score" data-cvss-score placeholder="0.0–10.0" value="' +
        esc(current ? current.score : '') + '">' +
        '<button type="button" class="btn btn-sm" data-cvss-save>Save</button>' +
        (current ? '<button type="button" class="btn btn-sm btn-danger" data-cvss-clear>Remove</button>' : '') +
        '</div>');
      out.push('<div class="cvss-row" style="margin-top:6px"><input type="text" data-cvss-rationale ' +
        'style="font-family:inherit" placeholder="Optional note: why this score" value="' +
        esc(current ? current.rationale : '') + '"></div>');
      out.push('<div class="cvss-help">Build the vector in the ' +
        '<a href="' + TM.CVSS4.CALCULATOR_URL + '" target="_blank" rel="noopener">NVD CVSS v4.0 calculator</a>, ' +
        'then paste the vector string and the score it produced. The vector is validated here; the score is taken as entered.</div>');
      out.push('<div class="cvss-error" data-cvss-error hidden></div>');
      out.push('</div>');
    }
    out.push('</div>');
    return out.join('');
  }

  function noun(n, one, many) { return n === 1 ? one : many; }
  function pl(n, one, many) { return n + ' ' + noun(n, one, many); }

  function count(model, type) {
    return model.nodes.filter(function (n) { return n.type === type; }).length;
  }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  /* ---------------------------------------------------------------------
   * Standalone HTML document (for download / print)
   * ------------------------------------------------------------------- */
  TM.reportDocument = function (bodyHTML, title, css) {
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>' + esc(title) + '</title><style>' + css + '</style></head>' +
      '<body class="report-page"><div class="report">' + bodyHTML + '</div></body></html>';
  };

  /** Minimal print-friendly stylesheet used by the downloadable report. */
  TM.REPORT_CSS = [
    'body{margin:0;padding:32px;background:#fff;color:#1f2430;',
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.55}',
    '.report{max-width:960px;margin:0 auto}',
    'h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:26px 0 8px;padding-bottom:4px;border-bottom:1px solid #d3d9e4}',
    'h3{font-size:14px;margin:18px 0 6px}',
    'table{width:100%;border-collapse:collapse;margin:8px 0 14px;font-size:12.5px}',
    'th,td{border:1px solid #d3d9e4;padding:5px 8px;text-align:left;vertical-align:top}',
    'th{background:#f2f5fa}td.num,th.num{text-align:center}',
    '.muted{color:#5b6478}ul{margin:5px 0 5px 18px;padding:0}li{margin:2px 0}',
    '.meta-grid{display:grid;grid-template-columns:150px 1fr;gap:2px 10px;margin:8px 0}',
    '.meta-grid dt{font-weight:600;color:#5b6478}.meta-grid dd{margin:0}',
    '.pill{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:20px}',
    '.pill-critical{background:#fbe2e2;color:#8f1b1b}.pill-high{background:#fdeada;color:#96520a}',
    '.pill-medium{background:#fdf6d5;color:#7a6008}.pill-low{background:#e4f1e6;color:#1f5c36}',
    '.pill-info{background:#e8edf6;color:#3a4a68}',
    '.stride-tag{display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;border-radius:4px;',
    'font-weight:700;font-size:12px;background:#e8edf6;color:#2a3a58}',
    '.finding{border:1px solid #d3d9e4;border-left-width:4px;border-radius:5px;padding:9px 12px;margin:8px 0;break-inside:avoid}',
    '.finding-critical{border-left-color:#c62828}.finding-high{border-left-color:#e07b1a}',
    '.finding-medium{border-left-color:#cbb01f}.finding-low{border-left-color:#3f9c63}.finding-info{border-left-color:#7d8ba6}',
    '.finding-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px}',
    '.mitig{margin-top:5px}.mitig b{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#5b6478}',
    '.safety-flag{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;',
    'padding:2px 7px;border-radius:20px;background:#fbe2e2;color:#8f1b1b}',
    '.safety-callout{background:#fdf1f1;border-left:3px solid #c62828;padding:9px 12px;border-radius:4px;margin:10px 0}',
    '.safety-panel{margin-top:7px;padding:7px 10px;border-radius:4px;background:#fdf5f5;border:1px solid #f2d3d3;font-size:12.5px}',
    '.safety-panel>div{margin:2px 0}.missing-trace{color:#c62828;font-weight:600}',
    '.level-swatch{display:inline-block;width:11px;height:11px;border-radius:3px;vertical-align:-1px;margin-right:5px}',
    '.stride-tag,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}',
    '.cvss-current code{background:#f2f5fa;padding:1px 5px;border-radius:3px;font-size:11px}',
    '.cvss-box{margin-top:7px;padding-top:6px;border-top:1px dashed #d3d9e4;font-size:12.5px}'
  ].join('');

  /* ---------------------------------------------------------------------
   * Markdown
   * ------------------------------------------------------------------- */
  TM.buildReportMarkdown = function (model, a) {
    var meta = model.meta || {};
    var L = [];
    L.push('# ' + ((meta.name || '').trim() || 'Untitled threat model'));
    L.push('');
    L.push('STRIDE threat model report — generated ' + new Date().toISOString().slice(0, 16).replace('T', ' '));
    L.push('');
    if (meta.system) L.push('- **System:** ' + meta.system);
    if (meta.author) L.push('- **Author:** ' + meta.author);
    if (meta.date) L.push('- **Date:** ' + meta.date);
    if (meta.scope) L.push('- **Scope / assumptions:** ' + meta.scope);
    if (meta.intendedUse) L.push('- **Intended use:** ' + meta.intendedUse);
    if (meta.safetyDoc || meta.safetyDocRef) {
      L.push('- **Safety risk management file:** ' + (meta.safetyDoc || 'Not named') +
        (meta.safetyDocRef ? ' (' + meta.safetyDocRef + ')' : ''));
    }
    L.push('- **Methodology:** STRIDE per element');
    L.push('- **Severity scale:** ' + a.profile.name +
      (a.stats.scored ? ' (' + a.stats.scored + ' of ' + a.stats.total + ' threats scored with CVSS v4.0)' : ''));
    L.push('');

    L.push('## 1. Summary');
    L.push('');
    L.push('| Metric | Value |');
    L.push('| --- | --- |');
    L.push('| Elements analysed | ' + a.stats.elements + ' |');
    L.push('| Data flows | ' + a.stats.flows + ' |');
    L.push('| Trust boundaries | ' + a.stats.boundaries + ' |');
    L.push('| Assets | ' + a.stats.assets + ' |');
    L.push('| Threats identified | ' + a.stats.total + ' |');
    L.push('| Threats affecting patient safety | ' + a.stats.safety + ' |');
    L.push('| Safety-relevant elements | ' + a.stats.safetyElements + ' |');
    L.push('');
    if (a.stats.safety) {
      L.push('| Safety impact | What a compromise does to the patient | Threats |');
      L.push('| --- | --- | --- |');
      TM.SAFETY_FUNCTIONS.forEach(function (fn) {
        var n = a.stats.bySafetyFunction[fn.key] || 0;
        if (!n) return;
        L.push('| ' + fn.short + ' — ' + md(fn.label) + ' | ' + md(fn.harm) + ' | ' + n + ' |');
      });
      L.push('');
    }
    L.push('| Severity | ' + a.stats.levels.map(function (lv) { return md(lv.label); }).join(' | ') + ' |');
    L.push('| --- |' + a.stats.levels.map(function () { return ' --- |'; }).join(''));
    L.push('| Threats | ' + a.stats.levels.map(function (lv) { return lv.count; }).join(' | ') + ' |');
    L.push('');
    L.push('| STRIDE | Property | Threats |');
    L.push('| --- | --- | --- |');
    TM.STRIDE_ORDER.forEach(function (c) {
      L.push('| ' + c + ' — ' + TM.STRIDE[c].name + ' | ' + TM.STRIDE[c].property + ' | ' + a.stats.byCategory[c] + ' |');
    });
    L.push('');
    if (a.notes.length) {
      L.push('### Modelling notes');
      L.push('');
      a.notes.forEach(function (n) { L.push('- ' + n); });
      L.push('');
    }

    L.push('## 2. Diagram inventory');
    L.push('');
    var boundaries = model.nodes.filter(function (n) { return n.type === 'boundary'; });
    if (boundaries.length) {
      L.push('### 2.1 Trust boundaries');
      L.push('');
      L.push('| Boundary | Kind | Description |');
      L.push('| --- | --- | --- |');
      boundaries.forEach(function (b) {
        L.push('| ' + md(TM.label(b)) + ' | ' + md(plain(b.props.boundaryKind)) + ' | ' + md(b.description || '—') + ' |');
      });
      L.push('');
    }
    var nodes = model.nodes.filter(function (n) { return n.type !== 'boundary'; });
    if (nodes.length) {
      L.push('### 2.2 Elements');
      L.push('');
      L.push('| Element | Type | Description | Classification | Safety impact | Severity of harm | In boundary | Asset |');
      L.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
      nodes.forEach(function (n) {
        L.push('| ' + md(TM.label(n)) + ' | ' + typeLabel(n.type) + ' | ' + md(n.description || '—') + ' | ' +
          md(plain(n.props.dataClassification)) + ' | ' + (safetyFlagsText(n) || '—') + ' | ' +
          md(plain(n.props.harmSeverity)) + ' | ' +
          md(TM.boundariesContaining(model, n).map(TM.label).join(', ') || '—') + ' | ' +
          (n.isAsset || n.type === 'asset' ? 'yes' : '') + ' |');
      });
      L.push('');
    }
    if (model.flows.length) {
      L.push('### 2.3 Data flows');
      L.push('');
      L.push('| Flow | Source | Destination | Protocol | Encryption | Crosses boundary |');
      L.push('| --- | --- | --- | --- | --- | --- |');
      model.flows.forEach(function (f) {
        L.push('| ' + md(TM.label(f)) + ' | ' + md(TM.label(TM.nodeById(model, f.from))) + ' | ' +
          md(TM.label(TM.nodeById(model, f.to))) + (f.bidirectional ? ' (bi)' : '') + ' | ' +
          md(plain(f.props.protocol)) + ' | ' + md(plain(f.props.encryptionInTransit)) + ' | ' +
          md(TM.boundariesCrossed(model, f).map(TM.label).join(', ') || 'no') + ' |');
      });
      L.push('');
    }

    L.push('## 3. STRIDE coverage matrix');
    L.push('');
    L.push('| Element | Type | ' + TM.STRIDE_ORDER.join(' | ') + ' |');
    L.push('| --- | --- |' + TM.STRIDE_ORDER.map(function () { return ' --- |'; }).join(''));
    a.coverage.forEach(function (row) {
      L.push('| ' + md(row.label) + ' | ' + typeLabel(row.type) + ' | ' +
        TM.STRIDE_ORDER.map(function (c) {
          var cell = row.cells[c];
          return !cell.applicable ? '·' : (cell.count ? String(cell.count) : 'o');
        }).join(' | ') + ' |');
    });
    L.push('');

    L.push('## 4. Threats and recommended mitigations');
    L.push('');
    if (!a.findings.length) {
      L.push('_No threats were raised — fill in the security categories on each element._');
      L.push('');
    } else {
      /* Group by element, keeping elements in order of their worst finding. */
      var byElement = {}, order = [];
      a.findings.forEach(function (f) {
        if (!byElement[f.elementId]) { byElement[f.elementId] = []; order.push(f.elementId); }
        byElement[f.elementId].push(f);
      });
      order.forEach(function (id) {
        var list = byElement[id];
        var elx = TM.elementById(model, id);
        L.push('### ' + list[0].elementLabel + ' (' + typeLabel(list[0].elementType) + ')');
        L.push('');
        if (elx && elx.description) { L.push('_' + elx.description + '_'); L.push(''); }
        list.forEach(function (f) {
          L.push('#### ' + f.ref + ' · [' + f.category + '] ' + f.title + ' — **' +
            String(f.severity.label).toUpperCase() + '**');
          L.push('');
          L.push('_' + TM.STRIDE[f.category].name + ' — violates ' + TM.STRIDE[f.category].property + '_');
          L.push('');
          if (f.cvss) {
            L.push('**CVSS v4.0:** ' + Number(f.cvss.score).toFixed(1) + ' (' + f.cvss.severity + ') — `' +
              f.cvss.vector + '`' + (f.cvss.rationale ? ' — ' + f.cvss.rationale : ''));
            L.push('');
          }
          L.push(f.threat);
          L.push('');
          if (f.safety) {
            L.push('> **Patient safety — ' + f.safety.hazardRef + ' · ' + f.safety.fnLabel + '**  ');
            L.push('> **Harm:** ' + f.safety.harm + '  ');
            if (f.safety.notes) L.push('> **Hazardous situation (as modelled):** ' + f.safety.notes + '  ');
            L.push('> Severity of harm: ' + plain(f.safety.severityOfHarm) +
              ' · Software safety class: ' + plain(f.safety.softwareSafetyClass) +
              ' · Safety file: ' + (f.safety.fileRef || '**missing**'));
            L.push('');
          }
          if (f.via) { L.push('Via data flow: ' + f.via); L.push(''); }
          if (f.crossings && f.crossings.length) { L.push('Crosses: ' + f.crossings.join(', ')); L.push(''); }
          if (f.existingControls) { L.push('**Controls already in place:** ' + f.existingControls); L.push(''); }
          L.push('**Recommended mitigations:**');
          f.mitigations.forEach(function (m) { L.push('- ' + m); });
          L.push('');
        });
      });
    }

    L.push('## 5. Patient safety traceability');
    L.push('');
    if (!a.safetyTrace.length) {
      L.push('No element carries a safety-relevant function, so there is nothing to trace to a safety risk ' +
        'management file. For a medical device, revisit this.');
      L.push('');
    } else {
      L.push('Each row is a security threat with a credible path to patient harm. Carry the hazard reference into ' +
        'the safety risk management file' +
        (meta.safetyDoc ? ' (' + meta.safetyDoc + (meta.safetyDocRef ? ', ' + meta.safetyDocRef : '') + ')' : '') +
        ' so the security control and the safety risk control are the same decision.');
      L.push('');
      L.push('| Hazard ref | Threat | Element | STRIDE | Safety impact | Hazardous situation -> harm | Severity of harm | Severity | Safety file ref |');
      L.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- |');
      a.safetyTrace.forEach(function (row) {
        row.findings.forEach(function (f) {
          L.push('| ' + f.safety.hazardRef + ' | ' + f.ref + ' | ' + md(row.label) + ' | ' + f.category +
            ' | ' + TM.safetyFunction(f.safety.fn).short + ' | ' + md(f.title) + ' -> ' + md(f.safety.harm) +
            ' | ' + md(plain(row.severityOfHarm)) + ' | ' + String(f.severity.label).toUpperCase() +
            ' | ' + (row.fileRef ? md(row.fileRef) : '**missing**') + ' |');
        });
      });
      L.push('');

      var cleanRows = a.safetyTrace.filter(function (r) { return !r.findings.length; });
      if (cleanRows.length) {
        L.push('### 5.1 Safety-relevant elements with no threat raised');
        L.push('');
        L.push('Record these in the safety file as justified residual risks.');
        L.push('');
        L.push('| Element | Safety functions | Severity of harm | Controls in place | Safety file ref |');
        L.push('| --- | --- | --- | --- | --- |');
        cleanRows.forEach(function (row) {
          L.push('| ' + md(row.label) + ' | ' + (safetyFlagsText({ props: { safetyFunctions: row.functions } }) || '—') +
            ' | ' + md(plain(row.severityOfHarm)) + ' | ' + md(row.existingControls || 'none recorded') +
            ' | ' + (row.fileRef ? md(row.fileRef) : '**missing**') + ' |');
        });
        L.push('');
      }
      if (a.safetyGaps.length) {
        L.push('### 5.2 Breaks in the safety trace');
        L.push('');
        L.push('| Element | Type | What is missing |');
        L.push('| --- | --- | --- |');
        a.safetyGaps.forEach(function (g) {
          L.push('| ' + md(g.label) + ' | ' + typeLabel(g.type) + ' | ' + md(g.issue) + ' |');
        });
        L.push('');
      }
    }

    L.push('## 6. Coverage gaps');
    L.push('');
    if (!a.gaps.length) {
      L.push('All security categories are answered.');
    } else {
      L.push('| Element | Type | Unanswered categories |');
      L.push('| --- | --- | --- |');
      a.gaps.forEach(function (g) {
        L.push('| ' + md(g.elementLabel) + (g.noDescription ? ' (no description)' : '') + ' | ' +
          typeLabel(g.elementType) + ' | ' + md(g.fields.join(', ')) + ' |');
      });
    }
    L.push('');

    L.push('## Appendix A · STRIDE reference');
    L.push('');
    L.push('| Letter | Threat | Property violated | Definition | Applies to |');
    L.push('| --- | --- | --- | --- | --- |');
    TM.STRIDE_ORDER.forEach(function (c) {
      var s = TM.STRIDE[c];
      var applies = Object.keys(TM.APPLICABILITY).filter(function (t) {
        return TM.APPLICABILITY[t].indexOf(c) !== -1;
      }).map(typeLabel).join(', ');
      L.push('| ' + c + ' | ' + s.name + ' | ' + s.property + ' | ' + s.definition + ' | ' + applies + ' |');
    });
    L.push('');

    L.push('## Appendix B · How severity was rated');
    L.push('');
    L.push('Severity scale in force: **' + a.profile.name + '**' +
      (a.profile.description ? ' — ' + a.profile.description : ''));
    L.push('');
    L.push('| Level | Score from |');
    L.push('| --- | --- |');
    a.profile.levels.slice().reverse().forEach(function (lv) {
      L.push('| ' + md(lv.label) + ' | ' + lv.min + ' |');
    });
    L.push('');
    L.push('| Factor | Points |');
    L.push('| --- | --- |');
    ['info', 'low', 'medium', 'high', 'critical'].forEach(function (k) {
      L.push('| Base rating: ' + cap(k) + ' | ' + a.profile.baseScores[k] + ' |');
    });
    TM.SCORING_AGGRAVATORS.forEach(function (k) {
      L.push('| Aggravating: ' + k + ' | +' + a.profile.aggravatorPoints[k] + ' |');
    });
    TM.SCORING_MITIGATORS.forEach(function (k) {
      L.push('| Mitigating: ' + k + ' | -' + a.profile.mitigatorPoints[k] + ' |');
    });
    L.push('');
    L.push('CVSS v4.0 assessments ' + (a.profile.cvss && a.profile.cvss.useWhenPresent
      ? 'override the modelled rating where present.'
      : 'are recorded but do not override the modelled rating.') +
      ' Vectors are validated against the CVSS v4.0 specification; scores are entered from the ' +
      'NVD calculator (' + TM.CVSS4.CALCULATOR_URL + ').');
    L.push('');
    return L.join('\n');
  };

  function md(s) { return String(s === undefined || s === null ? '' : s).replace(/\|/g, '\\|').replace(/\n+/g, ' '); }

  /* ---------------------------------------------------------------------
   * CSV (one row per threat - drops straight into a risk register)
   * ------------------------------------------------------------------- */
  TM.buildReportCSV = function (model, a) {
    var head = ['Ref', 'Element', 'Element type', 'STRIDE', 'Category', 'Property violated',
      'Threat title', 'Threat description', 'Severity', 'Severity source', 'Score',
      'CVSS v4.0 vector', 'CVSS v4.0 score', 'CVSS rationale',
      'Affects patient safety', 'Safety hazard ref', 'Safety impact', 'Harm',
      'Severity of harm', 'Safety file ref',
      'Crosses boundary', 'Via flow', 'Existing controls', 'Recommended mitigations', 'Rule id'];
    var rows = [head];
    a.findings.forEach(function (f) {
      rows.push([
        f.ref, f.elementLabel, typeLabel(f.elementType), f.category, TM.STRIDE[f.category].name,
        TM.STRIDE[f.category].property, f.title, f.threat,
        String(f.severity.label).toUpperCase(), f.severity.source, f.severity.score,
        f.cvss ? f.cvss.vector : '', f.cvss ? Number(f.cvss.score).toFixed(1) : '',
        f.cvss ? f.cvss.rationale : '',
        f.safety ? 'Yes' : 'No',
        f.safety ? f.safety.hazardRef : '',
        f.safety ? TM.safetyFunction(f.safety.fn).short : '',
        f.safety ? f.safety.harm : '',
        f.safety ? plain(f.safety.severityOfHarm) : '',
        f.safety ? f.safety.fileRef : '',
        (f.crossings || []).join('; '), f.via || '', f.existingControls || '',
        f.mitigations.join(' | '), f.ruleId
      ]);
    });
    return toCSV(rows);
  };

  /**
   * The security-to-safety traceability matrix, as a CSV that can be pasted
   * into or referenced from the safety risk management file. One row per
   * safety-relevant threat, plus a row for every safety-relevant element
   * where no threat was raised (which still needs a recorded justification).
   */
  TM.buildSafetyTraceCSV = function (model, a) {
    var meta = model.meta || {};
    var head = ['Hazard ref', 'Threat ref', 'Element', 'Element type', 'Safety function',
      'STRIDE', 'STRIDE category', 'Security threat (cause)', 'Hazardous situation',
      'Harm', 'Severity of harm', 'Software safety class', 'Security severity',
      'CVSS v4.0 vector', 'CVSS v4.0 score', 'Candidate risk controls',
      'Controls already in place', 'Safety file reference', 'Threat model', 'Safety file'];
    var rows = [head];

    a.safetyTrace.forEach(function (row) {
      if (row.findings.length) {
        row.findings.forEach(function (f) {
          rows.push([
            f.safety.hazardRef, f.ref, row.label, typeLabel(row.type),
            TM.safetyFunction(f.safety.fn).label, f.category, TM.STRIDE[f.category].name,
            f.title, row.notes || f.safety.hazard, f.safety.harm,
            plain(row.severityOfHarm), plain(row.softwareSafetyClass),
            String(f.severity.label).toUpperCase(),
            f.cvss ? f.cvss.vector : '', f.cvss ? Number(f.cvss.score).toFixed(1) : '',
            f.mitigations.join(' | '), row.existingControls || '',
            row.fileRef || 'MISSING', meta.name || '', meta.safetyDoc || ''
          ]);
        });
      } else {
        rows.push([
          '', '', row.label, typeLabel(row.type),
          row.functions.map(function (k) { return TM.safetyFunction(k).label; }).join('; '),
          '', '', 'No security threat raised by the model',
          row.notes || '', '', plain(row.severityOfHarm), plain(row.softwareSafetyClass),
          '', '', '', '', row.existingControls || '',
          row.fileRef || 'MISSING', meta.name || '', meta.safetyDoc || ''
        ]);
      }
    });
    return toCSV(rows);
  };

  function toCSV(rows) {
    return rows.map(function (r) {
      return r.map(function (cell) {
        var v = String(cell === undefined || cell === null ? '' : cell);
        return '"' + v.replace(/"/g, '""') + '"';
      }).join(',');
    }).join('\r\n');
  }

})(window.TM);
