(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const API = { "X-PhishLens": "1" };
  const MAX_MB = 10;
  const FLAG_LABELS = {
    "text-mismatch": "Text differs from destination",
    "ip-host": "Raw IP address",
    "shortener": "URL shortener",
    "punycode": "Lookalike domain",
  };
  // Constant markup only. Nothing from an email is ever put into these strings.
  const ICONS = {
    ok: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3.2 3L13 4.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    bad: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    none: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 8h8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    file: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2.5h6.5L16 7v10a.5.5 0 01-.5.5h-10A.5.5 0 015 17V2.5z M11.5 2.5V7H16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  };
  let current = null;
  let findingEls = [];

  // Everything that came from an email is untrusted, so it only ever goes in as text.
  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }
  function icon(name) {
    const t = document.createElement("template");
    t.innerHTML = ICONS[name];
    return t.content.firstElementChild;
  }
  const sev = (points) => (points >= 25 ? "hi" : points >= 15 ? "mid" : "lo");
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  function toast(message) {
    const t = $("toast");
    t.textContent = message;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 1800);
  }
  async function copy(text, message) {
    try { await navigator.clipboard.writeText(text); toast(message || "Copied"); }
    catch (err) { toast("Copy failed. Select the text and copy it by hand."); }
  }
  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = el("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ------------------------------------------------------------ requests
  function setBusy(message) {
    $("drop").classList.toggle("busy", Boolean(message));
    $("status").hidden = !message;
    $("status").textContent = message || "";
  }
  function showError(message) {
    $("error").hidden = !message;
    $("error").textContent = message || "";
  }
  async function send(request, busyText) {
    showError(""); setBusy(busyText);
    try {
      const res = await request();
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "Something went wrong.");
      current = body;
      render(body);
    } catch (err) {
      showError(err.message || "Something went wrong.");
    } finally {
      setBusy("");
    }
  }
  function analyzeFile(file) {
    if (!file) return;
    if (file.size > MAX_MB * 1024 * 1024) { showError("That file is larger than " + MAX_MB + " MB."); return; }
    const intel = $("use-intel").checked;
    const headers = Object.assign({}, API, {
      "Content-Type": "application/octet-stream",
      "X-Filename": encodeURIComponent(file.name),
      "X-Intel": intel ? "1" : "0",
    });
    if (intel) {
      headers["X-VT-Key"] = $("vt-key").value.trim();
      headers["X-Abuse-Key"] = $("abuse-key").value.trim();
    }
    $("intake").hidden = false; $("case").hidden = true;
    send(async () => fetch("/api/analyze", { method: "POST", headers, body: await file.arrayBuffer() }),
      intel ? "Reading the email and asking online services. Free keys are slow, please wait..." : "Reading the email...");
  }
  const loadDemo = () => send(() => fetch("/api/demo", { headers: API }), "Opening the sample...");

  // ------------------------------------------------------------ rendering
  function animateScore(score) {
    const ring = $("ring"), num = $("v-num");
    const set = (v) => { ring.style.setProperty("--p", v); num.textContent = Math.round(v); };
    if (score === 0 || window.matchMedia("(prefers-reduced-motion: reduce)").matches) { set(score); return; }
    const t0 = performance.now(), dur = 750;
    const step = (t) => {
      const k = Math.min(1, (t - t0) / dur);
      set(score * (1 - Math.pow(1 - k, 3)));
      if (k < 1) requestAnimationFrame(step); else set(score);
    };
    requestAnimationFrame(step);
  }

  function hdrRow(dl, label, value, ref, flagged) {
    const dd = el("dd", "", value);
    if (ref) dd.dataset.ref = ref;
    if (flagged) dd.appendChild(el("span", "tagflag", "differs"));
    if (ref) dd.appendChild(el("span", "pin-slot"));
    dl.append(el("dt", "", label), dd);
  }

  function renderMail(a) {
    $("m-subject").textContent = a.subject || "(no subject)";
    const name = a.from.display || a.from.address || "Unknown sender";
    $("m-from").textContent = name;
    $("m-addr").textContent = a.from.display && a.from.address ? a.from.address : "";
    const avatar = $("m-avatar");
    avatar.textContent = (name.match(/[A-Za-z0-9]/) || ["?"])[0].toUpperCase();
    let h = 0;
    for (const ch of a.from.address || name) h = (h * 31 + ch.charCodeAt(0)) % 360;
    avatar.style.background = "hsl(" + h + " 32% 42%)";

    const dl = $("m-hdrs"); dl.replaceChildren();
    if (a.to) hdrRow(dl, "To", a.to);
    if (a.date) hdrRow(dl, "Date", a.date);
    if (a.reply_to.address) hdrRow(dl, "Reply-To", a.reply_to.address, "reply_to", a.mismatch.reply_to);
    if (a.return_path.address) hdrRow(dl, "Return-Path", a.return_path.address, "return_path", a.mismatch.return_path);

    const body = $("m-body"); body.replaceChildren();
    const urgRe = a.urgency_hits.length ? new RegExp("(" + a.urgency_hits.map(escapeRe).join("|") + ")", "gi") : null;
    a.body.forEach((seg) => {
      if (seg.type === "text") {
        if (!urgRe) { body.appendChild(document.createTextNode(seg.text)); return; }
        seg.text.split(urgRe).forEach((part, i) => {
          if (i % 2 === 1) { const m = el("mark", "urg", part); m.dataset.ref = "urgency"; body.appendChild(m); }
          else if (part) body.appendChild(document.createTextNode(part));
        });
        return;
      }
      const u = seg.index !== null && seg.index !== undefined ? a.urls[seg.index] : null;
      const span = el("span", "lnk" + (u && u.flags.length ? " bad" : ""), seg.text);
      if (u) {
        span.dataset.ref = "link:" + seg.index;
        span.title = "Goes to " + u.defanged;
        span.appendChild(el("span", "pin-slot"));
      }
      body.appendChild(span);
      if (u && u.flags.includes("text-mismatch")) body.appendChild(el("span", "dest", "goes to " + u.defanged));
    });
    if (!body.childNodes.length) body.appendChild(el("p", "none", "This email has no readable text."));
    if (a.body_truncated) body.appendChild(el("p", "none", "The rest of the message is not shown."));

    const atts = $("m-atts"); atts.replaceChildren();
    atts.hidden = !a.attachments.length;
    a.attachments.forEach((t, i) => {
      const box = el("div", "att" + (t.risky_extension ? " bad" : ""));
      box.dataset.ref = "att:" + i;
      const info = el("div");
      const nameLine = el("div", "att-name", t.filename);
      nameLine.appendChild(el("span", "pin-slot"));
      const meta = el("div", "att-meta", t.size + " B  ·  SHA256 " + t.sha256.slice(0, 12) + "...");
      const btn = el("button", "", "copy");
      btn.type = "button";
      btn.addEventListener("click", () => copy(t.sha256, "Hash copied"));
      meta.appendChild(btn);
      info.append(nameLine, meta);
      box.append(icon("file"), info);
      atts.appendChild(box);
    });
  }

  function renderRails(a, r) {
    $("verdict").className = "card verdict lv-" + r.level.toLowerCase();
    $("v-word").textContent = r.level;
    $("v-note").textContent = r.summary;
    animateScore(r.score);

    const auth = $("auth"); auth.replaceChildren();
    ["spf", "dkim", "dmarc"].forEach((k) => {
      const v = a.auth[k];
      const kind = v === "pass" ? "pass" : (v === "fail" ? "fail" : "none");
      const li = el("li", kind);
      li.append(icon(kind === "pass" ? "ok" : kind === "fail" ? "bad" : "none"), el("span", "name", k.toUpperCase()), el("span", "state", v));
      auth.appendChild(li);
    });
    const origin = $("origin"); origin.replaceChildren();
    if (a.origin_ip) origin.append("Sent from ", el("code", "", a.origin_ip));
    else if (a.origin_ip_reserved) origin.append("Sent from ", el("code", "", a.origin_ip_reserved), " (a reserved, non-public address)");
    else origin.textContent = "No public sender address in the headers.";

    // findings
    $("n-find").textContent = r.findings.length;
    const list = $("findings"); list.replaceChildren();
    findingEls = [];
    if (!r.findings.length) list.appendChild(el("li", "empty", "Nothing suspicious was found."));
    r.findings.forEach((f, i) => {
      const li = el("li");
      const btn = el("button", "finding sev-" + sev(f.points));
      btn.type = "button";
      const main = el("div");
      main.appendChild(el("p", "f-why", f.reason));
      const tags = el("div", "f-tags"); tags.appendChild(el("span", "tag", f.attack)); main.appendChild(tags);
      btn.append(el("span", "num", String(i + 1)), main, el("span", "pts", "+" + f.points));
      btn.addEventListener("click", () => jump(f.targets));
      li.appendChild(btn); list.appendChild(li);
      findingEls.push(btn);
    });
    const sum = r.findings.reduce((n, f) => n + f.points, 0);
    $("total").textContent = sum > 100 ? "The points add up to " + sum + ", capped at 100." : "Total: " + sum + " of 100.";

    // links
    $("n-links").textContent = a.urls.length || "";
    const links = $("panel-links"); links.replaceChildren();
    if (!a.urls.length) links.appendChild(el("p", "empty", "There are no links in this email."));
    a.urls.forEach((u) => {
      const row = el("div", "linkrow");
      row.appendChild(el("div", "u", u.defanged));
      if (u.text) row.appendChild(el("div", "shown", "Shown as: " + u.text));
      if (u.flags.length) {
        const chips = el("div", "chips");
        u.flags.forEach((f) => chips.appendChild(el("span", "chip", FLAG_LABELS[f] || f)));
        row.appendChild(chips);
      }
      links.appendChild(row);
    });

    // indicators
    const iocs = $("panel-iocs"); iocs.replaceChildren();
    [["URLs", "urls"], ["Domains", "domains"], ["IP addresses", "ips"], ["File hashes (SHA256)", "sha256"]].forEach(([title, key]) => {
      const items = current.iocs[key];
      if (!items.length) return;
      const g = el("div", "group");
      const head = el("div", "group-head"); head.appendChild(el("h4", "", title + " (" + items.length + ")"));
      const b = el("button", "mini", "Copy"); b.type = "button";
      b.addEventListener("click", () => copy(items.join("\n"), title + " copied"));
      head.appendChild(b);
      const ul = el("ul"); items.forEach((v) => ul.appendChild(el("li", "", v)));
      g.append(head, ul); iocs.appendChild(g);
    });
    if (!iocs.childNodes.length) iocs.appendChild(el("p", "empty", "No indicators to list."));

    // online lookups
    const lookups = $("panel-lookups"); lookups.replaceChildren();
    $("tab-lookups").hidden = !current.intel;
    if (current.intel) {
      const ul = el("ul", "look");
      current.intel.results.forEach((t) => ul.appendChild(el("li", "", t)));
      current.intel.notes.forEach((t) => ul.appendChild(el("li", "note", t)));
      if (!ul.childNodes.length) ul.appendChild(el("li", "note", "No results."));
      lookups.appendChild(ul);
    }
  }

  // numbered markers on the email, one per finding target
  function placePins(r) {
    r.findings.forEach((f, i) => {
      f.targets.forEach((t) => {
        const target = document.querySelector('#case [data-ref="' + t + '"]');
        if (!target) return;
        const slot = target.querySelector(".pin-slot") || target;
        const pin = el("button", "pin sev-" + sev(f.points), String(i + 1));
        pin.type = "button";
        pin.title = "Finding " + (i + 1);
        pin.setAttribute("aria-label", "Show finding " + (i + 1));
        pin.addEventListener("click", (e) => { e.stopPropagation(); showFinding(i); });
        slot.appendChild(pin);
      });
    });
  }

  function flash(nodes) {
    nodes.forEach((n) => n.classList.add("flash"));
    setTimeout(() => nodes.forEach((n) => n.classList.remove("flash")), 1500);
  }
  function jump(targets) {
    const nodes = [];
    targets.forEach((t) => document.querySelectorAll('#case [data-ref="' + t + '"]').forEach((n) => nodes.push(n)));
    if (!nodes.length) return;
    nodes[0].scrollIntoView({ behavior: "smooth", block: "center" });
    flash(nodes);
  }
  function showFinding(i) {
    selectTab("findings");
    const btn = findingEls[i];
    if (!btn) return;
    btn.scrollIntoView({ behavior: "smooth", block: "nearest" });
    flash([btn]);
  }

  function selectTab(name) {
    document.querySelectorAll("#tabs [data-tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
    ["findings", "links", "iocs", "lookups"].forEach((n) => { $("panel-" + n).hidden = n !== name; });
  }

  function render(p) {
    const a = p.analysis, r = p.risk;
    $("b-file").textContent = a.file;
    $("bar-file").hidden = false;
    $("again").hidden = false;
    renderMail(a);
    renderRails(a, r);
    placePins(r);
    selectTab("findings");
    $("intake").hidden = true;
    $("case").hidden = false;
    window.scrollTo(0, 0);
  }

  function iocText(p) {
    const lines = ["Indicators from " + p.analysis.file, ""];
    [["URLs", "urls"], ["Domains", "domains"], ["IP addresses", "ips"], ["File hashes (SHA256)", "sha256"]].forEach(([title, key]) => {
      if (p.iocs[key].length) lines.push(title, ...p.iocs[key].map((v) => "  " + v), "");
    });
    return lines.join("\n").trim() + "\n";
  }

  // ------------------------------------------------------------ wiring
  $("pick").addEventListener("click", () => $("file").click());
  $("file").addEventListener("change", (e) => { analyzeFile(e.target.files[0]); e.target.value = ""; });
  $("demo").addEventListener("click", loadDemo);
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) selectTab(b.dataset.tab); });

  // A file can be dropped anywhere on the page.
  let depth = 0;
  const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");
  window.addEventListener("dragenter", (e) => { if (hasFiles(e)) { depth++; $("overlay").hidden = false; } });
  window.addEventListener("dragleave", () => { depth = Math.max(0, depth - 1); if (!depth) $("overlay").hidden = true; });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault(); depth = 0; $("overlay").hidden = true;
    if (e.dataTransfer && e.dataTransfer.files[0]) analyzeFile(e.dataTransfer.files[0]);
  });

  $("again").addEventListener("click", () => {
    $("case").hidden = true; $("intake").hidden = false;
    $("bar-file").hidden = true; $("again").hidden = true;
    showError(""); window.scrollTo(0, 0);
  });
  $("copy-iocs").addEventListener("click", () => current && copy(iocText(current), "Indicators copied"));
  const stem = () => current.analysis.file.replace(/\.[^.]*$/, "");
  $("dl-md").addEventListener("click", () => current && download(stem() + "-phishlens-report.md", current.report_md, "text/markdown"));
  $("dl-json").addEventListener("click", () => current && download(stem() + "-phishlens.json",
    JSON.stringify({ analysis: current.analysis, risk: current.risk, intel: current.intel, iocs: current.iocs }, null, 2), "application/json"));

  $("quit").addEventListener("click", async () => {
    try { await fetch("/api/quit", { method: "POST", headers: API }); } catch (err) { /* already gone */ }
    const box = el("div", "stopped");
    box.append(el("h1", "", "PhishLens has stopped"), el("p", "", "You can close this tab. Open PhishLens again whenever you need it."));
    document.body.replaceChildren(box);
  });
})();
