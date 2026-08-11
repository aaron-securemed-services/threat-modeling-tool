/* ---------------------------------------------------------------------------
 * diagram.js - SVG canvas: drawing the legend shapes, direct manipulation
 * (place, move, resize, connect), and export to SVG/PNG.
 *
 * All diagram styling is applied as presentation attributes rather than CSS
 * classes so that an exported .svg or .png is self-contained and looks exactly
 * like what is on screen.
 * --------------------------------------------------------------------------- */
window.TM = window.TM || {};

(function (TM) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var FONT = 'Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif';
  var INK = '#1f2430';
  var MUTED = '#5b6478';
  var BOUNDARY_RED = '#e23b3b';
  var ASSET_FILL = '#2b6b86';
  var SAFETY_RED = '#c62828';
  var SELECT_BLUE = '#2d6cdf';
  var GRID = 20;
  var MIN_W = 70, MIN_H = 48;

  function el(tag, attrs, children) {
    var node = document.createElementNS(NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] === null || attrs[k] === undefined) return;
        node.setAttribute(k, String(attrs[k]));
      });
    }
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function text(str, attrs) {
    var t = el('text', attrs);
    t.textContent = str;
    return t;
  }

  /* Rough character-count wrapping - good enough for diagram labels. */
  function wrap(str, maxChars, maxLines) {
    var words = String(str || '').trim().split(/\s+/).filter(Boolean);
    var lines = [], cur = '';
    for (var i = 0; i < words.length; i++) {
      var w = words[i];
      if (!cur.length) { cur = w; }
      else if ((cur + ' ' + w).length <= maxChars) { cur += ' ' + w; }
      else { lines.push(cur); cur = w; }
      if (lines.length === maxLines) break;
    }
    if (lines.length < maxLines && cur) lines.push(cur);
    if (lines.length === maxLines) {
      var consumed = lines.join(' ').length;
      if (String(str || '').trim().length > consumed) {
        var last = lines[maxLines - 1];
        lines[maxLines - 1] = last.slice(0, Math.max(0, maxChars - 1)).replace(/\s+\S*$/, '') + '…';
      }
    }
    return lines;
  }

  /* ---------------------------------------------------------------------
   * Diagram
   * ------------------------------------------------------------------- */
  TM.Diagram = function (svg, handlers) {
    this.svg = svg;
    this.handlers = handlers || {};
    this.model = TM.emptyModel();
    this.view = { x: 0, y: 0, k: 1 };
    this.tool = 'select';
    this.selectionId = null;
    this.showGrid = true;
    this.snap = true;
    this.showLegend = true;
    this.pending = null;   /* interaction state */
    this.flowStart = null;
    this.pointer = { x: 0, y: 0 };
    this._bind();
  };

  var P = TM.Diagram.prototype;

  /* ------------------------------ public API -------------------------- */
  P.setModel = function (model) {
    this.model = model;
    if (this.selectionId && !TM.elementById(model, this.selectionId)) this.selectionId = null;
    this.render();
  };

  P.setTool = function (tool) {
    this.tool = tool;
    this.flowStart = null;
    this.svg.classList.toggle('mode-place', TM.NODE_TYPES.indexOf(tool) !== -1);
    this.svg.classList.toggle('mode-flow', tool === 'flow');
    this.render();
    if (this.handlers.onToolChange) this.handlers.onToolChange(tool);
  };

  P.select = function (id, opts) {
    this.selectionId = id;
    this.render();
    if (this.handlers.onSelect) this.handlers.onSelect(id, opts || {});
  };

  P.setOption = function (key, value) {
    this[key] = value;
    this.render();
  };

  P.zoomBy = function (factor, cx, cy) {
    var rect = this.svg.getBoundingClientRect();
    var px = cx === undefined ? rect.width / 2 : cx;
    var py = cy === undefined ? rect.height / 2 : cy;
    var wx = (px - this.view.x) / this.view.k;
    var wy = (py - this.view.y) / this.view.k;
    this.view.k = Math.max(0.25, Math.min(3, this.view.k * factor));
    this.view.x = px - wx * this.view.k;
    this.view.y = py - wy * this.view.k;
    this.render();
    if (this.handlers.onZoom) this.handlers.onZoom(this.view.k);
  };

  P.zoomTo = function (k) {
    this.zoomBy(k / this.view.k);
  };

  P.zoomFit = function () {
    var b = this.contentBounds();
    var rect = this.svg.getBoundingClientRect();
    if (!b) { this.view = { x: 0, y: 0, k: 1 }; this.render(); return; }
    var pad = 40;
    var k = Math.min((rect.width - pad * 2) / b.w, (rect.height - pad * 2) / b.h, 2);
    k = Math.max(0.25, Math.min(2, k || 1));
    this.view.k = k;
    this.view.x = (rect.width - b.w * k) / 2 - b.x * k;
    this.view.y = (rect.height - b.h * k) / 2 - b.y * k;
    this.render();
    if (this.handlers.onZoom) this.handlers.onZoom(this.view.k);
  };

  /** True when anything on the diagram is marked as safety-relevant. */
  P.hasSafety = function () {
    var any = this.model.nodes.some(TM.hasSafetyRole);
    return any || this.model.flows.some(TM.hasSafetyRole);
  };

  /** Bounding box of all nodes in world coordinates. */
  P.contentBounds = function (pad) {
    var nodes = this.model.nodes;
    if (!nodes.length) return null;
    var x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
    nodes.forEach(function (n) {
      x1 = Math.min(x1, n.x); y1 = Math.min(y1, n.y);
      x2 = Math.max(x2, n.x + n.w); y2 = Math.max(y2, n.y + n.h);
    });
    pad = pad === undefined ? 0 : pad;
    return { x: x1 - pad, y: y1 - pad, w: (x2 - x1) + pad * 2, h: (y2 - y1) + pad * 2 };
  };

  /* ------------------------------ rendering --------------------------- */
  P.render = function () {
    var svg = this.svg;
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    svg.appendChild(this._defs());

    if (this.showGrid) {
      svg.appendChild(el('rect', {
        x: 0, y: 0, width: '100%', height: '100%', fill: 'url(#tm-grid)',
        'pointer-events': 'none'
      }));
      var pat = svg.querySelector('#tm-grid');
      if (pat) {
        pat.setAttribute('patternTransform',
          'translate(' + this.view.x + ',' + this.view.y + ') scale(' + this.view.k + ')');
      }
    }

    var world = el('g', {
      id: 'tm-world',
      transform: 'translate(' + this.view.x + ',' + this.view.y + ') scale(' + this.view.k + ')'
    });
    svg.appendChild(world);
    this.world = world;

    var content = el('g', { id: 'tm-content' });
    world.appendChild(content);
    this.content = content;

    this.anchors = computeAnchors(this.model);

    var boundaryLayer = el('g', { id: 'tm-boundaries' });
    var flowLayer = el('g', { id: 'tm-flows' });
    var nodeLayer = el('g', { id: 'tm-nodes' });
    content.appendChild(boundaryLayer);
    content.appendChild(flowLayer);
    content.appendChild(nodeLayer);

    var self = this;
    this.model.nodes.forEach(function (n) {
      if (n.type === 'boundary') boundaryLayer.appendChild(self._renderNode(n));
    });
    this.model.flows.forEach(function (f) {
      var g = self._renderFlow(f);
      if (g) flowLayer.appendChild(g);
    });
    this.model.nodes.forEach(function (n) {
      if (n.type !== 'boundary') nodeLayer.appendChild(self._renderNode(n));
    });

    /* overlay: selection handles and the in-progress connector */
    var overlay = el('g', { id: 'tm-overlay' });
    world.appendChild(overlay);
    this._renderSelection(overlay);
    if (this.flowStart) this._renderPendingFlow(overlay);

    if (this.showLegend) {
      var legend = TM.buildLegend({ safety: this.hasSafety() });
      var rect = svg.getBoundingClientRect();
      legend.setAttribute('transform', 'translate(12,' + Math.max(12, rect.height - 246) + ')');
      legend.setAttribute('opacity', '0.97');
      svg.appendChild(legend);
    }
  };

  P._defs = function () {
    return el('defs', null, [
      el('pattern', { id: 'tm-grid', width: GRID, height: GRID, patternUnits: 'userSpaceOnUse' }, [
        el('path', { d: 'M ' + GRID + ' 0 L 0 0 0 ' + GRID, fill: 'none', stroke: '#e4e9f2', 'stroke-width': 1 })
      ]),
      arrowMarker('tm-arrow', INK),
      arrowMarker('tm-arrow-sel', SELECT_BLUE)
    ]);
  };

  /* orient="auto-start-reverse" lets the same marker serve both ends of a
     bidirectional flow - at the start it is rotated to point outwards. */
  function arrowMarker(id, color) {
    return el('marker', {
      id: id, viewBox: '0 0 10 10', refX: 9, refY: 5,
      markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse', markerUnits: 'strokeWidth'
    }, [el('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: color })]);
  }

  /* ------------------------------- nodes ------------------------------ */
  P._renderNode = function (n) {
    var selected = n.id === this.selectionId;
    var g = el('g', { 'data-id': n.id, 'data-kind': 'node', class: 'tm-node', style: 'cursor:move' });
    var stroke = selected ? SELECT_BLUE : INK;

    if (n.type === 'entity') {
      g.appendChild(el('rect', { x: n.x, y: n.y, width: n.w, height: n.h, fill: '#ffffff', stroke: stroke, 'stroke-width': 2 }));
      this._labels(g, n, n.x + n.w / 2, n.y, n.w, n.h, 'middle');
    } else if (n.type === 'process') {
      g.appendChild(el('ellipse', {
        cx: n.x + n.w / 2, cy: n.y + n.h / 2, rx: n.w / 2, ry: n.h / 2,
        fill: '#ffffff', stroke: stroke, 'stroke-width': 2
      }));
      this._labels(g, n, n.x + n.w / 2, n.y, n.w * 0.78, n.h, 'middle');
    } else if (n.type === 'datastore') {
      g.appendChild(el('rect', { x: n.x, y: n.y, width: n.w, height: n.h, fill: '#ffffff', 'fill-opacity': 0.9, stroke: 'none' }));
      g.appendChild(el('path', {
        d: 'M ' + n.x + ' ' + n.y + ' H ' + (n.x + n.w) + ' M ' + n.x + ' ' + (n.y + n.h) + ' H ' + (n.x + n.w),
        stroke: stroke, 'stroke-width': 2.5, fill: 'none'
      }));
      this._labels(g, n, n.x + n.w / 2, n.y, n.w, n.h, 'middle');
    } else if (n.type === 'boundary') {
      g.appendChild(el('rect', {
        x: n.x, y: n.y, width: n.w, height: n.h, rx: 4,
        fill: selected ? 'rgba(226,59,59,.05)' : 'none',
        stroke: selected ? SELECT_BLUE : BOUNDARY_RED,
        'stroke-width': 2, 'stroke-dasharray': '9 6'
      }));
      /* invisible band so the boundary is grabbable without blocking its contents */
      g.appendChild(el('rect', {
        x: n.x - 6, y: n.y - 6, width: n.w + 12, height: n.h + 12, rx: 8,
        fill: 'none', stroke: 'transparent', 'stroke-width': 14, 'pointer-events': 'stroke'
      }));
      var lbl = text(TM.label(n), {
        x: n.x + 8, y: n.y - 6, 'font-family': FONT, 'font-size': 12,
        'font-weight': 700, fill: selected ? SELECT_BLUE : BOUNDARY_RED
      });
      g.appendChild(lbl);
      if (n.description) {
        g.appendChild(text(wrap(n.description, 60, 1)[0] || '', {
          x: n.x + 8, y: n.y + 16, 'font-family': FONT, 'font-size': 11, fill: MUTED
        }));
      }
    } else if (n.type === 'asset') {
      var cx = n.x + n.w / 2;
      var top = n.y, bottom = n.y + n.h - 20;
      g.appendChild(el('polygon', {
        points: cx + ',' + top + ' ' + (n.x + n.w) + ',' + bottom + ' ' + n.x + ',' + bottom,
        fill: ASSET_FILL, stroke: selected ? SELECT_BLUE : '#1d4c60', 'stroke-width': selected ? 2.5 : 1
      }));
      var lines = wrap(TM.label(n), Math.max(12, Math.round(n.w / 5.2)), 2);
      lines.forEach(function (line, i) {
        g.appendChild(text(line, {
          x: cx, y: n.y + n.h - 6 + i * 12, 'text-anchor': 'middle',
          'font-family': FONT, 'font-size': 11, 'font-weight': 600, fill: INK
        }));
      });
    }

    /* asset badge: the legend's triangle placed next to an element */
    if (n.isAsset && n.type !== 'asset') {
      var bx = n.x + n.w - 6, by = n.y - 4;
      g.appendChild(el('polygon', {
        points: bx + ',' + (by - 14) + ' ' + (bx + 12) + ',' + (by + 6) + ' ' + (bx - 12) + ',' + (by + 6),
        fill: ASSET_FILL, stroke: '#1d4c60', 'stroke-width': 1
      }));
    }

    /* patient-safety badge: this element can act on the patient */
    if (TM.hasSafetyRole(n) && n.type !== 'boundary') {
      safetyBadge(g, n.x + 2, n.y - 11, TM.safetyFunctionsOf(n));
    }
    return g;
  };

  /**
   * The patient-safety marker: a cross, plus one letter per safety function
   * (C control, A alarm, S safety stop, D clinical data, T care delivery) so
   * the diagram shows *how* an element can reach the patient.
   */
  function safetyBadge(g, x, y, fns) {
    var letters = fns.map(function (k) {
      return { control: 'C', alarm: 'A', safetyStop: 'S', clinicalData: 'D', careDelivery: 'T' }[k] || '?';
    }).join('');
    var w = 20 + letters.length * 8;
    g.appendChild(el('rect', {
      x: x, y: y, width: w, height: 17, rx: 4,
      fill: SAFETY_RED, stroke: '#8f1b1b', 'stroke-width': 0.8
    }));
    /* cross */
    g.appendChild(el('path', {
      d: 'M ' + (x + 8) + ' ' + (y + 4.5) + ' v 8 M ' + (x + 4) + ' ' + (y + 8.5) + ' h 8',
      stroke: '#ffffff', 'stroke-width': 2.2, 'stroke-linecap': 'round'
    }));
    if (letters) {
      g.appendChild(text(letters, {
        x: x + 15, y: y + 12.5, 'font-family': FONT, 'font-size': 10.5,
        'font-weight': 700, fill: '#ffffff', 'letter-spacing': '0.5'
      }));
    }
  }

  /** Title + description text stacked inside a node box. */
  P._labels = function (g, n, cx, top, availW, availH, anchor) {
    var charW = 6.2;
    var maxChars = Math.max(8, Math.floor(availW / charW));
    var titleLines = wrap(TM.label(n), maxChars, 2);
    var descLines = n.description ? wrap(n.description, Math.max(10, Math.floor(availW / 5.4)), availH > 78 ? 3 : 2) : [];
    var lineH = 14, descH = 12;
    var totalH = titleLines.length * lineH + (descLines.length ? 4 + descLines.length * descH : 0);
    var y = top + (availH - totalH) / 2 + 11;

    titleLines.forEach(function (line) {
      g.appendChild(text(line, {
        x: cx, y: y, 'text-anchor': anchor, 'font-family': FONT,
        'font-size': 12.5, 'font-weight': 700, fill: INK
      }));
      y += lineH;
    });
    if (descLines.length) {
      y += 3;
      descLines.forEach(function (line) {
        g.appendChild(text(line, {
          x: cx, y: y, 'text-anchor': anchor, 'font-family': FONT,
          'font-size': 10.5, fill: MUTED
        }));
        y += descH;
      });
    }
  };

  /* ------------------------------- flows ------------------------------ */
  P._renderFlow = function (f) {
    var from = TM.nodeById(this.model, f.from);
    var to = TM.nodeById(this.model, f.to);
    if (!from || !to) return null;
    var selected = f.id === this.selectionId;
    var ports = (this.anchors && this.anchors[f.id]) || {};
    var a = ports.a || anchor(from, TM.center(to));
    var b = ports.b || anchor(to, TM.center(from));
    var color = selected ? SELECT_BLUE : INK;
    var crosses = TM.boundariesCrossed(this.model, f).length > 0;

    var g = el('g', { 'data-id': f.id, 'data-kind': 'flow', class: 'tm-flow', style: 'cursor:pointer' });
    var d = 'M ' + a.x + ' ' + a.y + ' L ' + b.x + ' ' + b.y;

    g.appendChild(el('path', { d: d, stroke: 'transparent', 'stroke-width': 14, fill: 'none' }));
    g.appendChild(el('path', {
      d: d, stroke: color, 'stroke-width': selected ? 2.6 : 1.8, fill: 'none',
      'stroke-dasharray': crosses ? '7 4' : null,
      'marker-end': 'url(#' + (selected ? 'tm-arrow-sel' : 'tm-arrow') + ')',
      'marker-start': f.bidirectional ? 'url(#' + (selected ? 'tm-arrow-sel' : 'tm-arrow') + ')' : null
    }));

    /* Offset the label slightly off the line so it never hides an arrowhead. */
    var len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    var offset = 11;
    var mx = (a.x + b.x) / 2 + ((b.y - a.y) / len) * offset;
    var my = (a.y + b.y) / 2 - ((b.x - a.x) / len) * offset;
    var label = TM.label(f);
    if (label) {
      var lines = wrap(label, 26, 2);
      var wpx = Math.max.apply(null, lines.map(function (l) { return l.length * 5.9; })) + 10;
      var hpx = lines.length * 13 + 4;
      g.appendChild(el('rect', {
        x: mx - wpx / 2, y: my - hpx / 2 - 6, width: wpx, height: hpx, rx: 3,
        fill: '#fbfcfe', 'fill-opacity': 0.92, stroke: selected ? SELECT_BLUE : 'none', 'stroke-width': 1
      }));
      lines.forEach(function (line, i) {
        g.appendChild(text(line, {
          x: mx, y: my - hpx / 2 + 4 + i * 13, 'text-anchor': 'middle',
          'font-family': FONT, 'font-size': 11, 'font-weight': 600, fill: selected ? SELECT_BLUE : INK
        }));
      });
    }
    if (f.isAsset) {
      g.appendChild(el('polygon', {
        points: (mx + 3) + ',' + (my + 8) + ' ' + (mx + 15) + ',' + (my + 26) + ' ' + (mx - 9) + ',' + (my + 26),
        fill: ASSET_FILL, stroke: '#1d4c60', 'stroke-width': 1
      }));
    }
    if (TM.hasSafetyRole(f)) {
      var fns = TM.safetyFunctionsOf(f);
      safetyBadge(g, mx - (20 + fns.length * 8) / 2, my + (f.isAsset ? 28 : 8), fns);
    }
    return g;
  };

  /* ---------------------------------------------------------------------
   * Connection points
   *
   * Every flow gets its own point on the border of each element it touches.
   * Flows are assigned to the side of the box facing the other end, then
   * spread evenly along that side (ordered so lines do not cross each other
   * needlessly). Without this, several flows into one element all land on the
   * same spot and the arrowheads pile up.
   * ------------------------------------------------------------------- */
  function computeAnchors(model) {
    var sides = {};   /* nodeId -> { top: [], right: [], bottom: [], left: [] } */
    var result = {};  /* flowId -> { a: point, b: point } */

    function sideBucket(nodeId) {
      if (!sides[nodeId]) sides[nodeId] = { top: [], right: [], bottom: [], left: [] };
      return sides[nodeId];
    }

    /** Which side of `node` faces `other`, comparing angles against the corners. */
    function sideFacing(node, other) {
      var c = TM.center(node), o = TM.center(other);
      var dx = o.x - c.x, dy = o.y - c.y;
      if (!dx && !dy) return 'right';
      /* Normalise by the box aspect so wide boxes still use their long sides. */
      var nx = dx / Math.max(1, node.w), ny = dy / Math.max(1, node.h);
      if (Math.abs(nx) >= Math.abs(ny)) return nx >= 0 ? 'right' : 'left';
      return ny >= 0 ? 'bottom' : 'top';
    }

    model.flows.forEach(function (f) {
      var from = TM.nodeById(model, f.from), to = TM.nodeById(model, f.to);
      if (!from || !to) return;
      var sa = sideFacing(from, to), sb = sideFacing(to, from);
      /* Sort key: position of the other end along the axis of this side. */
      var oa = TM.center(to), ob = TM.center(from);
      sideBucket(from.id)[sa].push({ flowId: f.id, end: 'a', key: (sa === 'top' || sa === 'bottom') ? oa.x : oa.y });
      sideBucket(to.id)[sb].push({ flowId: f.id, end: 'b', key: (sb === 'top' || sb === 'bottom') ? ob.x : ob.y });
      result[f.id] = { a: null, b: null };
    });

    Object.keys(sides).forEach(function (nodeId) {
      var node = TM.nodeById(model, nodeId);
      if (!node) return;
      ['top', 'right', 'bottom', 'left'].forEach(function (side) {
        var list = sides[nodeId][side];
        if (!list.length) return;
        list.sort(function (p, q) { return p.key - q.key; });
        /* Keep the usable span away from the corners of the box. */
        var inset = Math.min(0.22, 0.5 / (list.length + 1));
        list.forEach(function (item, i) {
          var t = inset + ((i + 1) / (list.length + 1)) * (1 - inset * 2);
          var p;
          if (side === 'top') p = { x: node.x + node.w * t, y: node.y };
          else if (side === 'bottom') p = { x: node.x + node.w * t, y: node.y + node.h };
          else if (side === 'left') p = { x: node.x, y: node.y + node.h * t };
          else p = { x: node.x + node.w, y: node.y + node.h * t };
          /* Project the box point onto the real outline (ellipse, triangle…). */
          result[item.flowId][item.end] = anchor(node, p);
        });
      });
    });
    return result;
  }

  /** Point on the border of `node` in the direction of `toward`. */
  function anchor(node, toward) {
    var c = TM.center(node);
    var dx = toward.x - c.x, dy = toward.y - c.y;
    if (!dx && !dy) return c;
    var rx = node.w / 2 + 3, ry = node.h / 2 + 3;
    var t;
    if (node.type === 'process') {
      t = 1 / Math.sqrt((dx * dx) / (rx * rx) + (dy * dy) / (ry * ry));
    } else {
      t = Math.min(
        Math.abs(dx) > 1e-6 ? rx / Math.abs(dx) : Infinity,
        Math.abs(dy) > 1e-6 ? ry / Math.abs(dy) : Infinity
      );
    }
    return { x: c.x + dx * t, y: c.y + dy * t };
  }

  /* ----------------------------- overlay ------------------------------ */
  P._renderSelection = function (overlay) {
    var sel = this.selectionId && TM.elementById(this.model, this.selectionId);
    if (!sel || sel.type === 'flow') return;
    var pad = 5;
    overlay.appendChild(el('rect', {
      x: sel.x - pad, y: sel.y - pad, width: sel.w + pad * 2, height: sel.h + pad * 2,
      fill: 'none', stroke: SELECT_BLUE, 'stroke-width': 1, 'stroke-dasharray': '4 3',
      'pointer-events': 'none'
    }));
    var self = this;
    [['nw', sel.x, sel.y], ['ne', sel.x + sel.w, sel.y],
     ['sw', sel.x, sel.y + sel.h], ['se', sel.x + sel.w, sel.y + sel.h]]
      .forEach(function (h) {
        overlay.appendChild(el('rect', {
          x: h[1] - 4.5, y: h[2] - 4.5, width: 9, height: 9,
          fill: '#fff', stroke: SELECT_BLUE, 'stroke-width': 1.5,
          'data-handle': h[0], 'data-id': sel.id,
          style: 'cursor:' + (h[0] === 'nw' || h[0] === 'se' ? 'nwse-resize' : 'nesw-resize')
        }));
      });
    void self;
  };

  P._renderPendingFlow = function (overlay) {
    var from = TM.nodeById(this.model, this.flowStart);
    if (!from) return;
    var c = TM.center(from);
    var p = this.pointer;
    var a = anchor(from, p);
    overlay.appendChild(el('path', {
      d: 'M ' + a.x + ' ' + a.y + ' L ' + p.x + ' ' + p.y,
      stroke: SELECT_BLUE, 'stroke-width': 2, 'stroke-dasharray': '5 4', fill: 'none',
      'marker-end': 'url(#tm-arrow-sel)', 'pointer-events': 'none'
    }));
    overlay.appendChild(el('rect', {
      x: from.x - 5, y: from.y - 5, width: from.w + 10, height: from.h + 10,
      fill: 'none', stroke: SELECT_BLUE, 'stroke-width': 1.5, 'stroke-dasharray': '4 3', 'pointer-events': 'none'
    }));
    void c;
  };

  /* --------------------------- interaction ---------------------------- */
  P._toWorld = function (evt) {
    var r = this.svg.getBoundingClientRect();
    return {
      x: (evt.clientX - r.left - this.view.x) / this.view.k,
      y: (evt.clientY - r.top - this.view.y) / this.view.k
    };
  };

  P._snap = function (v) { return this.snap ? Math.round(v / GRID) * GRID : Math.round(v); };

  P._bind = function () {
    var self = this;
    var svg = this.svg;

    svg.addEventListener('pointerdown', function (e) {
      /* Only the primary button draws and drags. A right-press must not take
         pointer capture, or the contextmenu event that follows is retargeted
         to the <svg> and the menu loses track of what was clicked. */
      if (e.button !== undefined && e.button !== 0) return;
      svg.focus();
      var p = self._toWorld(e);
      self.pointer = p;
      var handleEl = e.target.closest ? e.target.closest('[data-handle]') : null;
      var group = e.target.closest ? e.target.closest('[data-id]') : null;
      var id = group ? group.getAttribute('data-id') : null;

      /* connect mode */
      if (self.tool === 'flow') {
        if (!id) { self.flowStart = null; self.render(); return; }
        var node = TM.nodeById(self.model, id);
        if (!node || node.type === 'boundary') return;
        if (!self.flowStart) {
          self.flowStart = id;
          self.render();
          self._status('Now click the destination element (Esc to cancel).');
        } else if (self.flowStart !== id) {
          var flow = TM.makeFlow(self.flowStart, id);
          self.model.flows.push(flow);
          self.flowStart = null;
          self._commit();
          self.setTool('select');
          self.select(flow.id, { focus: true });
        }
        return;
      }

      /* placement mode */
      if (TM.NODE_TYPES.indexOf(self.tool) !== -1) {
        self.addNode(self.tool, p);
        self.setTool('select');
        return;
      }

      /* resize */
      if (handleEl) {
        var target = TM.nodeById(self.model, handleEl.getAttribute('data-id'));
        if (target) {
          self.pending = {
            mode: 'resize', id: target.id, handle: handleEl.getAttribute('data-handle'),
            start: p, orig: { x: target.x, y: target.y, w: target.w, h: target.h }, moved: false
          };
          svg.setPointerCapture(e.pointerId);
        }
        return;
      }

      /* select + drag */
      if (id) {
        var elm = TM.elementById(self.model, id);
        if (elm) {
          if (self.selectionId !== id) self.select(id);
          if (elm.type !== 'flow') {
            self.pending = {
              mode: 'move', id: id, start: p,
              orig: { x: elm.x, y: elm.y },
              children: elm.type === 'boundary' ? self._childrenOf(elm) : null,
              moved: false
            };
            svg.setPointerCapture(e.pointerId);
          }
        }
        return;
      }

      /* background: deselect + pan */
      self.select(null);
      self.pending = { mode: 'pan', startClient: { x: e.clientX, y: e.clientY }, origView: { x: self.view.x, y: self.view.y } };
      svg.classList.add('panning');
      svg.setPointerCapture(e.pointerId);
    });

    svg.addEventListener('pointermove', function (e) {
      var p = self._toWorld(e);
      self.pointer = p;
      if (self.flowStart) { self.render(); return; }
      var pend = self.pending;
      if (!pend) return;

      if (pend.mode === 'pan') {
        self.view.x = pend.origView.x + (e.clientX - pend.startClient.x);
        self.view.y = pend.origView.y + (e.clientY - pend.startClient.y);
        self.render();
        return;
      }
      var node = TM.nodeById(self.model, pend.id);
      if (!node) return;
      var dx = p.x - pend.start.x, dy = p.y - pend.start.y;
      pend.moved = pend.moved || Math.abs(dx) > 1 || Math.abs(dy) > 1;

      if (pend.mode === 'move') {
        var nx = self._snap(pend.orig.x + dx), ny = self._snap(pend.orig.y + dy);
        if (pend.children) {
          var ddx = nx - node.x, ddy = ny - node.y;
          pend.children.forEach(function (c) { c.x += ddx; c.y += ddy; });
        }
        node.x = nx; node.y = ny;
      } else if (pend.mode === 'resize') {
        var o = pend.orig, h = pend.handle;
        var x1 = o.x, y1 = o.y, x2 = o.x + o.w, y2 = o.y + o.h;
        if (h.indexOf('w') !== -1) x1 = Math.min(self._snap(o.x + dx), x2 - MIN_W);
        if (h.indexOf('e') !== -1) x2 = Math.max(self._snap(o.x + o.w + dx), x1 + MIN_W);
        if (h.indexOf('n') !== -1) y1 = Math.min(self._snap(o.y + dy), y2 - MIN_H);
        if (h.indexOf('s') !== -1) y2 = Math.max(self._snap(o.y + o.h + dy), y1 + MIN_H);
        node.x = x1; node.y = y1; node.w = x2 - x1; node.h = y2 - y1;
      }
      self.render();
    });

    function endPointer(e) {
      svg.classList.remove('panning');
      if (self.pending) {
        if (svg.hasPointerCapture && e.pointerId !== undefined && svg.hasPointerCapture(e.pointerId)) {
          svg.releasePointerCapture(e.pointerId);
        }
        if (self.pending.mode !== 'pan' && self.pending.moved) self._commit();
        self.pending = null;
      }
    }
    svg.addEventListener('pointerup', endPointer);
    svg.addEventListener('pointercancel', endPointer);

    /* Right-click: select what is under the cursor and ask the app for a menu. */
    svg.addEventListener('contextmenu', function (e) {
      e.preventDefault();
      /* elementFromPoint rather than e.target: if a drag is in progress the
         event has been retargeted to the <svg> by pointer capture. */
      var hit = document.elementFromPoint(e.clientX, e.clientY) || e.target;
      var group = hit.closest ? hit.closest('[data-id]') : null;
      var id = group ? group.getAttribute('data-id') : null;
      self.pointer = self._toWorld(e);
      self.flowStart = null;
      self.select(id);
      if (self.handlers.onContextMenu) {
        self.handlers.onContextMenu(id, { clientX: e.clientX, clientY: e.clientY, world: self.pointer });
      }
    });

    svg.addEventListener('dblclick', function (e) {
      var group = e.target.closest ? e.target.closest('[data-id]') : null;
      if (group) self.select(group.getAttribute('data-id'), { focus: true });
    });

    svg.addEventListener('wheel', function (e) {
      e.preventDefault();
      var r = svg.getBoundingClientRect();
      self.zoomBy(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });

    svg.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        self.flowStart = null;
        self.setTool('select');
        self.select(null);
        return;
      }
      if ((e.key === 'Delete' || e.key === 'Backspace') && self.selectionId) {
        e.preventDefault();
        self.deleteSelected();
        return;
      }
      var step = e.shiftKey ? GRID : 1;
      var map = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
      if (map[e.key] && self.selectionId) {
        var node = TM.nodeById(self.model, self.selectionId);
        if (node) {
          e.preventDefault();
          node.x += map[e.key][0];
          node.y += map[e.key][1];
          self._commit();
        }
      }
    });
  };

  /** Non-boundary nodes fully inside a boundary - dragged along with it. */
  P._childrenOf = function (b) {
    return this.model.nodes.filter(function (n) {
      if (n.id === b.id) return false;
      var c = { x: n.x + n.w / 2, y: n.y + n.h / 2 };
      return c.x >= b.x && c.x <= b.x + b.w && c.y >= b.y && c.y <= b.y + b.h;
    });
  };

  /** Place a new node centred on a world-space point. */
  P.addNode = function (type, world) {
    var n = TM.makeNode(type, world.x, world.y);
    n.x = this._snap(n.x);
    n.y = this._snap(n.y);
    this.model.nodes.push(n);
    this._commit();
    this.select(n.id, { focus: true });
    return n;
  };

  /** Begin drawing a data flow out of `nodeId`. */
  P.startFlowFrom = function (nodeId) {
    var node = TM.nodeById(this.model, nodeId);
    if (!node || node.type === 'boundary') return;
    this.setTool('flow');
    this.flowStart = nodeId;
    this.render();
    this._status('Now click the destination element (Esc to cancel).');
  };

  P.deleteById = function (id) {
    if (!id) return;
    this.selectionId = id;
    this.deleteSelected();
  };

  P.deleteSelected = function () {
    var id = this.selectionId;
    if (!id) return;
    var model = this.model;
    model.nodes = model.nodes.filter(function (n) { return n.id !== id; });
    model.flows = model.flows.filter(function (f) {
      return f.id !== id && f.from !== id && f.to !== id;
    });
    this.selectionId = null;
    this._commit();
    if (this.handlers.onSelect) this.handlers.onSelect(null, {});
  };

  P._commit = function () {
    this.render();
    if (this.handlers.onChange) this.handlers.onChange(this.model);
  };

  P._status = function (msg) {
    if (this.handlers.onStatus) this.handlers.onStatus(msg);
  };

  /* ------------------------------ export ------------------------------ */
  /**
   * Serialise the diagram (without grid, selection or pending state) into a
   * standalone SVG document string.
   */
  P.exportSVGString = function (opts) {
    opts = opts || {};
    var padding = 40;
    var bounds = this.contentBounds(padding);
    if (!bounds) bounds = { x: 0, y: 0, w: 400, h: 300 };

    var prevSel = this.selectionId, prevFlow = this.flowStart, prevLegend = this.showLegend, prevGrid = this.showGrid;
    this.selectionId = null; this.flowStart = null; this.showLegend = false; this.showGrid = false;
    this.render();
    var content = this.content.cloneNode(true);
    this.selectionId = prevSel; this.flowStart = prevFlow; this.showLegend = prevLegend; this.showGrid = prevGrid;
    this.render();

    var titleH = 0;
    var header = null;
    var name = (this.model.meta.name || '').trim();
    if (opts.title !== false && name) {
      titleH = 46;
      header = el('g', { transform: 'translate(' + bounds.x + ',' + bounds.y + ')' }, [
        text(name, { x: 4, y: 18, 'font-family': FONT, 'font-size': 17, 'font-weight': 700, fill: INK }),
        text((this.model.meta.system || '') + (this.model.meta.date ? '   ·   ' + this.model.meta.date : ''),
          { x: 4, y: 36, 'font-family': FONT, 'font-size': 11, fill: MUTED })
      ]);
    }

    var legendW = 0, legendG = null;
    if (opts.legend !== false) {
      legendG = TM.buildLegend({ safety: this.hasSafety() });
      legendW = 232;
      legendG.setAttribute('transform', 'translate(' + (bounds.x + bounds.w + 16) + ',' + (bounds.y + titleH) + ')');
    }

    var totalW = bounds.w + (legendW ? legendW + 16 : 0);
    var totalH = Math.max(bounds.h + titleH, legendW ? 250 + titleH : 0);

    var out = el('svg', {
      xmlns: NS, 'xmlns:xlink': 'http://www.w3.org/1999/xlink',
      width: totalW, height: totalH,
      viewBox: bounds.x + ' ' + bounds.y + ' ' + totalW + ' ' + totalH
    });
    out.appendChild(el('rect', { x: bounds.x, y: bounds.y, width: totalW, height: totalH, fill: '#ffffff' }));
    out.appendChild(this._defs());
    if (header) out.appendChild(header);
    content.setAttribute('transform', 'translate(0,' + titleH + ')');
    out.appendChild(content);
    if (legendG) out.appendChild(legendG);

    return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(out);
  };

  /** Render the diagram to a PNG data URL (async). */
  P.exportPNG = function (scale, opts) {
    var svgString = this.exportSVGString(opts);
    var m = /width="([\d.]+)"\s+height="([\d.]+)"/.exec(svgString);
    var w = m ? parseFloat(m[1]) : 1200;
    var h = m ? parseFloat(m[2]) : 800;
    scale = scale || 2;
    return new Promise(function (resolve, reject) {
      var img = new Image();
      img.onload = function () {
        var canvas = document.createElement('canvas');
        canvas.width = Math.round(w * scale);
        canvas.height = Math.round(h * scale);
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        try {
          resolve(canvas.toDataURL('image/png'));
        } catch (err) { reject(err); }
      };
      img.onerror = function () { reject(new Error('Could not rasterise the diagram.')); };
      img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svgString);
    });
  };

  /* ------------------------------ legend ------------------------------ */
  /**
   * The diagram legend, drawn as SVG so it exports with the image.
   * The patient-safety row only appears once something on the diagram is
   * marked as safety-relevant, so the standard legend stays as it is for a
   * plain IT threat model.
   */
  TM.buildLegend = function (opts) {
    opts = opts || {};
    var g = el('g', { id: 'tm-legend' });
    var W = opts.safety ? 258 : 224, rowH = 34, rows = opts.safety ? 7 : 6;
    var H = 26 + rows * rowH;
    g.appendChild(el('rect', { x: 0, y: 0, width: W, height: H, rx: 5, fill: '#ffffff', stroke: '#d3d9e4', 'stroke-width': 1 }));
    g.appendChild(text('Diagram legend', { x: 10, y: 18, 'font-family': FONT, 'font-size': 12, 'font-weight': 700, fill: INK }));

    var items = [
      ['Entity', function (x, y) { return el('rect', { x: x, y: y - 9, width: 44, height: 18, fill: '#fff', stroke: INK, 'stroke-width': 1.6 }); }],
      ['Process', function (x, y) { return el('ellipse', { cx: x + 22, cy: y, rx: 22, ry: 10, fill: '#fff', stroke: INK, 'stroke-width': 1.6 }); }],
      ['Data store', function (x, y) { return el('path', { d: 'M ' + x + ' ' + (y - 9) + ' h 44 M ' + x + ' ' + (y + 9) + ' h 44', stroke: INK, 'stroke-width': 2, fill: 'none' }); }],
      ['Data flow', function (x, y) { return el('path', { d: 'M ' + x + ' ' + y + ' h 38', stroke: INK, 'stroke-width': 1.8, fill: 'none', 'marker-end': 'url(#tm-arrow)' }); }],
      ['Trust boundary', function (x, y) { return el('rect', { x: x, y: y - 9, width: 44, height: 18, fill: 'none', stroke: BOUNDARY_RED, 'stroke-width': 1.8, 'stroke-dasharray': '5 3' }); }],
      ['Asset', function (x, y) { return el('polygon', { points: (x + 22) + ',' + (y - 10) + ' ' + (x + 38) + ',' + (y + 9) + ' ' + (x + 6) + ',' + (y + 9), fill: ASSET_FILL, stroke: '#1d4c60', 'stroke-width': 1 }); }]
    ];
    if (opts.safety) {
      items.push(['Patient safety impact', function (x, y) {
        var sub = el('g');
        safetyBadge(sub, x + 2, y - 8, ['control']);
        return sub;
      }, 'C control · A alarm · S stop · D data · T care']);
    }
    items.forEach(function (item, i) {
      var y = 26 + rowH * i + rowH / 2;
      g.appendChild(item[1](12, y));
      g.appendChild(text(item[0], {
        x: 68, y: y + (item[2] ? 0 : 4), 'font-family': FONT, 'font-size': 11.5, fill: INK
      }));
      if (item[2]) {
        g.appendChild(text(item[2], { x: 68, y: y + 11, 'font-family': FONT, 'font-size': 9, fill: MUTED }));
      }
    });
    return g;
  };

})(window.TM);
