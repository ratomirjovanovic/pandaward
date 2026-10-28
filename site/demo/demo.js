(function () {
  "use strict";

  var screen = document.getElementById("screen");
  var stepsEl = document.getElementById("steps");
  var playBtn = document.getElementById("play");
  var skipBtn = document.getElementById("skip");
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ---- session replay ----
  // Each step is a list of items: user and claude messages, a question,
  // tool calls with their real output, a diff, a written file, a hook.
  var steps = [];
  var current = 0;
  var playing = !reduced;
  var timer = null;

  function ops(item) {
    // Returns [{cls, text, typed}] lines to append for one item.
    var out = [];
    switch (item.kind) {
      case "user":
        out.push({ cls: "user", text: "> " + item.text, typed: true });
        break;
      case "claude":
        out.push({ cls: "claude", text: "● " + item.text });
        break;
      case "question":
        out.push({ cls: "q", text: "? " + item.text });
        item.options.forEach(function (o, i) { out.push({ cls: "q", text: "  " + (i + 1) + ". " + o }); });
        break;
      case "tool":
        out.push({ cls: "cmd", text: "● Bash(" + item.cmd + ")" });
        out.push({ cls: "out", text: item.output, flow: true });
        break;
      case "file":
        out.push({ cls: "cmd", text: "● " + item.cmd });
        out.push({ cls: "out", text: item.output, flow: true });
        break;
      case "diff":
        item.output.split("\n").forEach(function (l) {
          out.push({ cls: l.charAt(0) === "+" && l.indexOf("+++") !== 0 ? "add" : l.charAt(0) === "-" && l.indexOf("---") !== 0 ? "del" : "out", text: l });
        });
        break;
      case "hook":
        out.push({ cls: "hook", text: "⚑ " + item.cmd });
        out.push({ cls: "hook", text: item.output, flow: true });
        break;
    }
    return out;
  }

  function lines(i) {
    var all = [];
    steps[i].items.forEach(function (it, n) {
      if (n > 0) all.push({ cls: "out", text: "" });
      all = all.concat(ops(it));
    });
    return all;
  }

  function append(l, text) {
    var s = el("span", l.cls, text);
    screen.appendChild(s);
    screen.appendChild(document.createTextNode("\n"));
    return s;
  }

  function renderStep(i, instant) {
    clearTimeout(timer);
    current = i;
    Array.prototype.forEach.call(stepsEl.children, function (b, j) {
      b.setAttribute("aria-current", j === i ? "true" : "false");
    });
    screen.textContent = "";
    var ls = lines(i);
    if (instant || reduced) {
      ls.forEach(function (l) { append(l, l.text); });
      screen.scrollTop = 0;
      return;
    }
    var n = 0;
    (function next() {
      if (n >= ls.length) {
        if (playing && current < steps.length - 1) timer = setTimeout(function () { renderStep(current + 1); }, 2600);
        return;
      }
      var l = ls[n++];
      if (l.typed) {
        var s = append(l, "");
        var k = 0;
        (function type() {
          s.textContent = l.text.slice(0, ++k);
          if (k < l.text.length) timer = setTimeout(type, 24);
          else timer = setTimeout(next, 500);
        })();
      } else if (l.flow) {
        var rows = l.text.split("\n");
        var r = 0;
        (function flow() {
          append(l, rows.slice(r, r + 3).join("\n"));
          screen.scrollTop = screen.scrollHeight;
          r += 3;
          timer = setTimeout(r < rows.length ? flow : next, 40);
        })();
      } else {
        append(l, l.text);
        screen.scrollTop = screen.scrollHeight;
        timer = setTimeout(next, l.cls === "claude" ? 700 : 120);
      }
    })();
  }

  playBtn.addEventListener("click", function () {
    playing = !playing;
    playBtn.textContent = playing ? "Pause" : "Play";
    if (playing) renderStep(current);
    else clearTimeout(timer);
  });
  skipBtn.addEventListener("click", function () {
    clearTimeout(timer);
    playing = false;
    playBtn.textContent = "Play";
    screen.textContent = "";
    steps.forEach(function (s, i) {
      append({ cls: "step" }, "── " + (i + 1) + ". " + s.label + " ──");
      lines(i).forEach(function (l) { append(l, l.text); });
      append({ cls: "out" }, "");
    });
    screen.scrollTop = 0;
  });

  fetch("transcript.json")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      steps = data;
      steps.forEach(function (s, i) {
        var b = el("button", null, (i + 1) + ". " + s.label);
        b.type = "button";
        b.addEventListener("click", function () {
          playing = false;
          playBtn.textContent = "Play";
          renderStep(i, true);
        });
        stepsEl.appendChild(b);
      });
      if (!playing) playBtn.textContent = "Play";
      renderStep(0, !playing);
    })
    .catch(function () {
      screen.textContent = "Demo data is generated by the site build and is not available in this preview.";
    });

  // ---- findings explorer ----
  var list = document.getElementById("list");
  var filtersEl = document.getElementById("filters");
  var kpis = document.getElementById("kpis");
  var rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  var filter = "all";
  var findings = [];

  function kpi(value, label) {
    var d = el("div", "kpi");
    d.appendChild(el("b", null, String(value)));
    d.appendChild(el("span", null, label));
    kpis.appendChild(d);
  }

  function row(dl, k, v, mono) {
    if (!v) return;
    dl.appendChild(el("dt", null, k));
    var dd = el("dd", null, v);
    if (mono) dd.style.fontFamily = "var(--mono)";
    dl.appendChild(dd);
  }

  function render() {
    list.textContent = "";
    var shown = findings.filter(function (f) {
      if (filter === "confirmed") return f.confidence !== "HYPOTHESIS";
      if (filter === "suspected") return f.confidence === "HYPOTHESIS";
      if (filter === "high") return rank[f.severity] >= 4;
      return true;
    });
    shown.forEach(function (f) {
      var d = el("details", "finding");
      var s = el("summary");
      s.appendChild(el("span", "id", f.id));
      s.appendChild(el("span", "pill " + f.severity, f.severity));
      s.appendChild(el("span", "pill " + f.confidence, f.confidence));
      s.appendChild(el("b", null, f.title));
      s.appendChild(el("span", "loc", f.file + (f.start_line ? ":" + f.start_line : "") + "  ·  " + f.control_id));
      d.appendChild(s);
      var dl = el("dl");
      row(dl, "Why", f.message);
      row(dl, "Fix", f.fix);
      row(dl, "Retest", f.retest);
      row(dl, "CWE", f.cwe);
      row(dl, "Evidence", (f.evidence_ids || []).join(", "), true);
      row(dl, "Collector", f.collector, true);
      d.appendChild(dl);
      list.appendChild(d);
    });
    if (!shown.length) list.appendChild(el("p", null, "No findings for this filter."));
  }

  [["all", "All"], ["confirmed", "Confirmed"], ["suspected", "Suspected"], ["high", "High and critical"]].forEach(function (p) {
    var b = el("button", null, p[1]);
    b.type = "button";
    b.setAttribute("aria-pressed", p[0] === filter ? "true" : "false");
    b.addEventListener("click", function () {
      filter = p[0];
      Array.prototype.forEach.call(filtersEl.children, function (x) { x.setAttribute("aria-pressed", "false"); });
      b.setAttribute("aria-pressed", "true");
      render();
    });
    filtersEl.appendChild(b);
  });

  fetch("report.json")
    .then(function (r) { return r.json(); })
    .then(function (rep) {
      findings = (rep.findings || []).filter(function (f) { return f.status === "OPEN" || f.status === "REOPENED"; });
      findings.sort(function (a, b) {
        var ca = a.confidence === "HYPOTHESIS" ? 1 : 0, cb = b.confidence === "HYPOTHESIS" ? 1 : 0;
        return ca - cb || rank[b.severity] - rank[a.severity] || (a.id < b.id ? -1 : 1);
      });
      var conf = findings.filter(function (f) { return f.confidence !== "HYPOTHESIS"; }).length;
      var cov = rep.coverage || {};
      kpi(conf, "confirmed, open");
      kpi(findings.length - conf, "suspected, need review");
      kpi(Math.round((cov.decisive_control_coverage || 0) * 100) + "%", "decisive coverage (" + cov.decisive_controls + "/" + cov.applicable_controls + ")");
      kpi(cov.edges_total || 0, "cross-domain edges (" + (cov.edges_failed || 0) + " failed)");
      render();
    })
    .catch(function () {
      list.appendChild(el("p", null, "Report data is generated by the site build and is not available in this preview."));
    });
})();
