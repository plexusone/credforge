"use strict";

// The review page. Every text goes in through textContent, never as HTML.

const LIVE_ORDER = ["missing", "stale", "unregistered", "changed", "unrecorded", "unlisted", "unobserved", "present"];
const LIVE_TONE = { missing: "b-red", stale: "b-red", unregistered: "b-red", changed: "b-amber", unrecorded: "b-amber", unlisted: "b-violet", unobserved: "", present: "b-green" };
const LOG_TONE = { expired: "b-red", overdue: "b-red", unrecorded: "b-amber", expiring: "b-amber", due: "b-amber", "unknown-expiry": "b-amber", planned: "b-blue", ok: "b-green", retired: "" };
const STATUS_TONE = { active: "b-green", planned: "b-blue", retired: "" };
const DECISION_TONE = { approved: "b-green", change: "b-amber", remove: "b-red" };
const DECISION_LABEL = { approved: "Approved", change: "Change", remove: "Remove" };

// Who handles each stage of a credential.
const ACTOR_LABEL = { human: "Human operator", agent: "Agent operator", system: "Program" };
const ACTOR_SHORT = { human: "Human", agent: "Agent", system: "Program" };
const ACTOR_TONE = { human: "b-amber", agent: "b-violet", system: "b-green" };
const STAGES = ["generate", "distribute", "rotate"];
const actors = (c) => [...new Set(STAGES.map((s) => c.handling[s]))];
// setupBy is who must set a credential up, or "" when nothing is left:
// a store the live check finds missing, or a planned credential with no
// store found holding a value.
function setupBy(r) {
  if (r.kind !== "credential" || r.cred.status === "retired") return "";
  const states = r.findings.map((f) => f.state);
  const pending = states.includes("missing") || (r.cred.assessment.state === "planned" && !states.includes("present"));
  return pending ? r.cred.handling.generate : "";
}
const handlingText = (c) => STAGES.map((s) => `${s}: ${ACTOR_LABEL[c.handling[s]] || c.handling[s]}`).join(" · ");

const state = {
  data: null,
  rows: [],          // credential rows and unlisted stores, built from data
  filtered: [],
  selected: null,    // subject of the open row
  filters: {},
  q: "",
  view: "table",     // "table" or "setup"
};

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

const badge = (text, tone) => el("span", { class: "badge " + (tone || "") }, text);
const keyString = (k) => `${k.type}:${k.account || ""}:${k.path}`;
const day = (s) => (s ? new Date(s).toISOString().slice(0, 10) : "");
const when = (s) => (s ? new Date(s).toLocaleString() : "");

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let payload = null;
  try {
    payload = await res.json();
  } catch (e) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  if (!res.ok) throw new Error(payload && payload.error ? payload.error : `${res.status} ${res.statusText}`);
  return payload;
}

// Building rows

function build() {
  const d = state.data;
  const reviews = new Map(d.reviews.map((r) => [r.subject, r]));
  const findings = (d.check && d.check.report && d.check.report.findings) || [];
  const byCred = new Map();
  const byKey = new Map();
  const unlisted = [];
  for (const f of findings) {
    const k = keyString(f.store);
    if (f.credential) {
      if (!byCred.has(f.credential)) byCred.set(f.credential, []);
      byCred.get(f.credential).push(f);
      byKey.set(f.credential + "\u0000" + k, f);
    } else {
      unlisted.push(f);
    }
  }
  const worst = (fs) => {
    let best = null;
    for (const f of fs) if (best === null || LIVE_ORDER.indexOf(f.state) < LIVE_ORDER.indexOf(best)) best = f.state;
    return best;
  };
  const rows = d.credentials.map((c) => {
    const fs = byCred.get(c.id) || [];
    const live = d.check && d.check.report ? (worst(fs) || "not checked") : "";
    return {
      kind: "credential", subject: c.id, cred: c, findings: fs, live,
      storeFinding: (s) => byKey.get(c.id + "\u0000" + keyString(s)),
      review: reviews.get(c.id),
      text: searchText(c, reviews.get(c.id)),
    };
  });
  for (const f of unlisted) {
    const k = keyString(f.store);
    const rv = reviews.get(k);
    rows.push({
      kind: "store", subject: k, finding: f, live: f.state, review: rv,
      text: [k, f.detail, f.source, rv && rv.note].join(" ").toLowerCase(),
    });
  }
  state.rows = rows;
}

function searchText(c, rv) {
  const parts = [c.id, c.name, c.description, c.system, c.environment, c.kind, c.owner, c.issuer && c.issuer.type, c.issuer && c.issuer.account];
  for (const s of c.stores || []) parts.push(s.type, s.account, s.path, s.note);
  for (const s of c.consumers || []) parts.push(s.system, s.component, s.via, s.note);
  for (const e of c.entitlements || []) parts.push(e.resource, e.access, e.note);
  for (const t of c.tags || []) parts.push(t);
  if (rv) parts.push(rv.note, rv.decision);
  return parts.filter(Boolean).join(" ").toLowerCase();
}

// Filters

const FILTERS = [
  { key: "system", label: "System", get: (r) => (r.cred ? r.cred.system : "(not in registry)") },
  { key: "environment", label: "Environment", get: (r) => (r.cred ? r.cred.environment || "(none)" : "(not in registry)") },
  { key: "status", label: "Status", get: (r) => (r.cred ? r.cred.status : "unlisted") },
  { key: "store", label: "Store", get: (r) => (r.cred ? (r.cred.stores || []).map((s) => s.type) : [r.finding.store.type]) },
  { key: "handled", label: "Handled by", get: (r) => (r.cred ? actors(r.cred).map((a) => ACTOR_LABEL[a] || a) : "(not in registry)") },
  { key: "setup", label: "To set up by", get: (r) => (r.kind === "credential" ? ACTOR_LABEL[setupBy(r)] || "nothing to do" : "(not in registry)") },
  { key: "sensitivity", label: "Sensitivity", get: (r) => (r.cred ? r.cred.sensitivity || "(none)" : "(not in registry)") },
  { key: "log", label: "Log state", get: (r) => (r.cred ? r.cred.assessment.state : "(not in registry)") },
  { key: "live", label: "Live", get: (r) => r.live || "not checked" },
  { key: "review", label: "Review", get: (r) => (r.review ? r.review.decision : "unreviewed") },
];

function renderFilterSelects() {
  const box = $("filter-selects");
  box.replaceChildren();
  for (const f of FILTERS) {
    const values = new Set();
    for (const r of state.rows) for (const v of [].concat(f.get(r))) values.add(v);
    const sel = el("select", { "aria-label": f.label, onchange: (e) => { setFilter(f.key, e.target.value); } },
      el("option", { value: "" }, `${f.label}: all`),
      [...values].sort().map((v) => el("option", { value: v }, `${f.label}: ${v}`)));
    sel.value = state.filters[f.key] || "";
    if (sel.value !== (state.filters[f.key] || "")) {
      // The saved value is no longer offered; keep it so the filter shows.
      sel.append(el("option", { value: state.filters[f.key] }, `${f.label}: ${state.filters[f.key]}`));
      sel.value = state.filters[f.key];
    }
    box.append(sel);
  }
}

function setFilter(key, value) {
  if (value) state.filters[key] = value; else delete state.filters[key];
  saveHash();
  renderFilterSelects();
  renderList();
}

function applyFilters() {
  const q = state.q.trim().toLowerCase();
  state.filtered = state.rows.filter((r) => {
    for (const f of FILTERS) {
      const want = state.filters[f.key];
      if (want && ![].concat(f.get(r)).includes(want)) return false;
    }
    return !q || q.split(/\s+/).every((w) => r.text.includes(w));
  });
}

function saveHash() {
  const p = new URLSearchParams(state.filters);
  if (state.q) p.set("q", state.q);
  if (state.selected) p.set("open", state.selected);
  if (state.view === "setup") p.set("view", "setup");
  const h = p.toString();
  history.replaceState(null, "", h ? "#" + h : location.pathname);
}

function loadHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  state.filters = {};
  for (const f of FILTERS) if (p.get(f.key)) state.filters[f.key] = p.get(f.key);
  state.q = p.get("q") || "";
  state.selected = p.get("open");
  state.view = p.get("view") === "setup" ? "setup" : "table";
  $("q").value = state.q;
}

// Rendering

function renderHeader() {
  const d = state.data;
  if (d.title) { $("title").textContent = d.title; document.title = d.title; }
  $("subtitle").textContent = `${d.credentials.length} credentials · as of ${when(d.now)}${d.by ? " · reviewing as " + d.by : ""}`;
  $("run-check").hidden = !d.canCheck;
  const cs = $("check-status");
  if (!d.check) cs.textContent = d.canCheck ? "No live check yet" : "Live check not configured";
  else if (d.check.error) { cs.textContent = `Live check failed ${when(d.check.at)}`; cs.className = "small error"; cs.title = d.check.error; }
  else { cs.textContent = `Live check ${when(d.check.at)}`; cs.className = "muted small"; cs.title = ""; }
}

// setupStat is the tile that opens the setup list of what a person sets up.
function setupStat(n) {
  const on = state.view === "setup" && state.filters.setup === ACTOR_LABEL.human;
  return el("button", {
    type: "button", class: "stat" + (on ? " on" : ""), title: "Show the setup list of what you set up by hand",
    onclick: () => {
      if (on) { delete state.filters.setup; state.view = "table"; }
      else { state.filters.setup = ACTOR_LABEL.human; state.view = "setup"; }
      saveHash(); renderSummary(); renderFilterSelects(); renderList();
    },
  }, el("b", {}, n), el("span", {}, "To set up by hand"));
}

function renderSummary() {
  const box = $("summary");
  box.replaceChildren();
  const rows = state.rows;
  const creds = rows.filter((r) => r.kind === "credential");
  const stat = (n, label, key, value) => el("button", {
    type: "button", class: "stat", title: key ? `Show ${label.toLowerCase()}` : undefined,
    onclick: key ? () => setFilter(key, state.filters[key] === value ? "" : value) : undefined,
  }, el("b", {}, n), el("span", {}, label));
  box.append(
    stat(creds.length, "Credentials"),
    stat(creds.filter((r) => r.cred.status === "active").length, "Active", "status", "active"),
    stat(creds.filter((r) => r.cred.status === "planned").length, "Planned", "status", "planned"),
    setupStat(creds.filter((r) => setupBy(r) === "human").length),
    stat(rows.filter((r) => !r.review).length, "Unreviewed", "review", "unreviewed"),
    stat(rows.filter((r) => r.review && r.review.decision === "change").length, "To change", "review", "change"),
  );
  if (state.data.check && state.data.check.report) {
    for (const s of ["missing", "stale", "unregistered", "changed", "unrecorded", "unlisted"]) {
      const n = rows.filter((r) => r.live === s).length;
      if (n) box.append(stat(n, "Live: " + s, "live", s));
    }
  }
  if (state.data.check && state.data.check.error) {
    box.append(el("p", { class: "small error" }, "Live check failed: " + state.data.check.error));
  }
}

function renderList() {
  $("list-table").hidden = state.view !== "table";
  $("list-setup").hidden = state.view !== "setup";
  $("view-table").setAttribute("aria-pressed", String(state.view === "table"));
  $("view-setup").setAttribute("aria-pressed", String(state.view === "setup"));
  if (state.view === "setup") renderSetup(); else renderTable();
}

function setView(v) {
  state.view = v;
  saveHash();
  renderSummary();
  renderList();
}

// renderSetup lists the filtered credentials that are left to set up, by
// system and environment: where to get each, what it may do and where to
// put it.
function renderSetup() {
  applyFilters();
  const box = $("list-setup");
  box.replaceChildren();
  const todo = state.filtered.filter((r) => setupBy(r));
  const groups = new Map();
  for (const r of todo) {
    const g = `${r.cred.system} · ${r.cred.environment || "no environment"}`;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(r);
  }
  const names = [...groups.keys()].sort();
  $("count").textContent = `${todo.length} to set up, of ${state.filtered.length} shown`;
  if (!todo.length) {
    box.append(el("p", { class: "muted" }, "Nothing left to set up among the credentials shown."));
    return;
  }
  box.append(el("p", { class: "muted small" }, state.data.check && state.data.check.report
    ? "From the live check: a store missing a value, or a planned credential with none found."
    : "No live check yet, so this lists every planned credential. Run the live check to leave out what is already in place."));
  for (const name of names) {
    const rs = groups.get(name);
    box.append(el("h2", { class: "setup-group" }, name, el("span", { class: "muted small" }, ` ${rs.length}`)));
    for (const r of rs) box.append(setupCard(r));
  }
}

function setupCard(r) {
  const c = r.cred;
  const g = c.generation || {};
  const issuer = [c.issuer.type, c.issuer.account].filter(Boolean).join(" · ");
  const link = (url, text) => el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, text || url);
  const section = (title, ...kids) => el("div", { class: "setup-part" }, el("h4", {}, title), ...kids);
  const stores = (c.stores || []).slice().sort((a, b) => (a.role === "primary" ? 0 : 1) - (b.role === "primary" ? 0 : 1));
  return el("article", { class: "setup-card" },
    el("header", {},
      el("button", { type: "button", class: "link mono", title: "Open its details", onclick: () => select(r.subject) }, c.id),
      " ", badge(c.kind), c.sensitivity ? badge(c.sensitivity, c.sensitivity === "critical" ? "b-red" : "") : null,
      " ", badge(ACTOR_SHORT[setupBy(r)] || setupBy(r), ACTOR_TONE[setupBy(r)]),
      r.live && r.live !== "not checked" ? badge(r.live, LIVE_TONE[r.live]) : null),
    c.description ? el("p", { class: "small" }, c.description) : null,
    section("Get it from",
      el("div", {}, issuer || "—", c.issuer.console ? [" · ", link(c.issuer.console, "console")] : null),
      g.where ? el("div", { class: "muted small" }, g.where) : null,
      g.command ? el("pre", {}, el("code", {}, g.command)) : null,
      (g.steps || []).length ? el("ol", { class: "small" }, g.steps.map((s) => el("li", {}, s))) : null),
    section("It may",
      (c.entitlements || []).length
        ? el("ul", { class: "small" }, c.entitlements.map((e) => el("li", {}, e.resource, " — ", el("b", {}, e.access), e.note ? el("span", { class: "muted" }, ` (${e.note})`) : null)))
        : el("p", { class: "muted small" }, "No entitlements listed.")),
    section("Put it in",
      el("ul", { class: "small" }, stores.map((s) => {
        const f = r.storeFinding(s);
        return el("li", {},
          el("div", {}, badge(s.type), s.role !== "primary" ? badge(s.role) : null, f ? badge(f.state, LIVE_TONE[f.state]) : null, " ",
            el("span", { class: "mono" }, [s.account, s.path].filter(Boolean).join(" : ")),
            s.console ? [" · ", link(s.console, "console")] : null),
          s.install ? el("pre", {}, el("code", {}, s.install)) : null,
          s.note ? el("div", { class: "muted" }, s.note) : null);
      }))),
    el("p", { class: "muted small" }, "When it is in place, open its details and log a created event."));
}

function renderTable() {
  applyFilters();
  const body = $("rows");
  body.replaceChildren();
  for (const r of state.filtered) {
    const tr = el("tr", { tabindex: "0", "aria-selected": r.subject === state.selected ? "true" : "false", onclick: () => select(r.subject), onkeydown: (e) => { if (e.key === "Enter") select(r.subject); } });
    if (r.kind === "credential") {
      const c = r.cred;
      tr.append(
        el("td", { class: "id" }, el("div", { class: "mono" }, c.id), c.name !== c.id.split("/").pop() ? el("div", { class: "name" }, c.name) : null),
        el("td", {}, c.system),
        el("td", {}, c.environment || ""),
        el("td", {}, badge(c.status, STATUS_TONE[c.status])),
        el("td", {}, badge(c.assessment.state, LOG_TONE[c.assessment.state])),
        el("td", {}, [...new Set((c.stores || []).map((s) => s.type))].map((t) => badge(t))),
        el("td", { class: "nowrap", title: handlingText(c) }, STAGES.map((s) => badge(ACTOR_SHORT[c.handling[s]] || c.handling[s], ACTOR_TONE[c.handling[s]]))),
        el("td", {}, r.live ? badge(r.live, LIVE_TONE[r.live]) : ""),
        el("td", {}, r.review ? badge(DECISION_LABEL[r.review.decision], DECISION_TONE[r.review.decision]) : el("span", { class: "muted small" }, "—")),
      );
    } else {
      tr.append(
        el("td", { class: "id" }, el("div", { class: "mono" }, r.finding.store.path), el("div", { class: "name" }, "not in the registry")),
        el("td", { class: "muted" }, "—"),
        el("td", { class: "muted" }, "—"),
        el("td", {}, badge("unlisted", "b-violet")),
        el("td", { class: "muted" }, "—"),
        el("td", {}, badge(r.finding.store.type)),
        el("td", { class: "muted" }, "—"),
        el("td", {}, badge(r.live, LIVE_TONE[r.live])),
        el("td", {}, r.review ? badge(DECISION_LABEL[r.review.decision], DECISION_TONE[r.review.decision]) : el("span", { class: "muted small" }, "—")),
      );
    }
    body.append(tr);
  }
  $("count").textContent = `Showing ${state.filtered.length} of ${state.rows.length}`;
}

function select(subject) {
  state.selected = subject;
  saveHash();
  for (const tr of $("rows").children) tr.setAttribute("aria-selected", "false");
  if (state.view === "table") renderTable();
  renderDetail();
}

function renderDetail() {
  const box = $("detail");
  const r = state.rows.find((x) => x.subject === state.selected);
  const layout = document.querySelector(".layout");
  if (!r) { box.hidden = true; layout.classList.remove("with-detail"); return; }
  box.hidden = false;
  layout.classList.add("with-detail");
  box.replaceChildren(r.kind === "credential" ? credentialDetail(r) : storeDetail(r));
}

function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) continue;
    dl.append(el("dt", {}, k), el("dd", {}, v));
  }
  return dl;
}

function head(title, sub) {
  return el("div", { class: "detail-head" },
    el("div", {}, el("h2", { class: "mono" }, title), sub ? el("p", { class: "muted" }, sub) : null),
    el("button", { type: "button", class: "link", "aria-label": "Close", onclick: () => select(null) }, "Close"));
}

function credentialDetail(r) {
  const c = r.cred;
  const frag = document.createDocumentFragment();
  frag.append(head(c.id, c.name));
  if (c.description) frag.append(el("p", {}, c.description));
  frag.append(kv([
    ["Status", badge(c.status, STATUS_TONE[c.status])],
    ["Log state", el("span", {}, badge(c.assessment.state, LOG_TONE[c.assessment.state]), " ", c.assessment.reason)],
    ["Next date", day(c.assessment.next)],
    ["Kind", c.kind],
    ["Sensitivity", c.sensitivity],
    ["Owner", c.owner],
    ["Issuer", [c.issuer.type, c.issuer.account].filter(Boolean).join(" · ")],
    ["Depends on", (c.dependsOn || []).join(", ")],
    ["Reaches", (c.reaches || []).join(", ")],
    ["Tags", (c.tags || []).map((t) => badge(t))],
  ]));

  frag.append(el("h3", {}, "Stores"));
  frag.append(el("ul", { class: "items" }, (c.stores || []).map((s) => {
    const f = r.storeFinding(s);
    return el("li", {},
      el("div", {}, badge(s.type), badge(s.role), f ? badge(f.state, LIVE_TONE[f.state]) : null),
      el("div", { class: "mono" }, [s.account, s.path].filter(Boolean).join(" : ")),
      f && f.detail ? el("div", { class: "muted small" }, f.detail + (f.source ? ` (${f.source})` : "")) : null,
      s.install ? el("div", { class: "small" }, "Install: ", el("code", {}, s.install)) : null,
      s.note ? el("div", { class: "muted small" }, s.note) : null);
  })));

  if ((c.consumers || []).length) {
    frag.append(el("h3", {}, "Consumers"));
    frag.append(el("ul", { class: "items" }, c.consumers.map((s) => el("li", {},
      el("div", {}, [s.system, s.component].filter(Boolean).join(" · ")),
      s.via ? el("div", { class: "mono small" }, s.via) : null,
      s.note ? el("div", { class: "muted small" }, s.note) : null))));
  }
  if ((c.entitlements || []).length) {
    frag.append(el("h3", {}, "Entitlements"));
    frag.append(el("ul", { class: "items" }, c.entitlements.map((e) => el("li", {},
      el("div", {}, e.resource, " — ", el("b", {}, e.access)),
      e.note ? el("div", { class: "muted small" }, e.note) : null))));
  }

  frag.append(el("h3", {}, "Generation and rotation"));
  frag.append(kv([
    ["Method", c.generation.method],
    ["Where", c.generation.where],
    ["Command", c.generation.command ? el("code", {}, c.generation.command) : ""],
    ["Steps", (c.generation.steps || []).length ? el("ol", {}, c.generation.steps.map((s) => el("li", {}, s))) : ""],
    ["Rotation", [c.rotation.policy, c.rotation.intervalDays ? `every ${c.rotation.intervalDays} days` : ""].filter(Boolean).join(", ")],
    ["Procedure", c.rotation.procedure],
    ["Impact", c.rotation.impact],
    ["Handled by", handlingText(c)],
    ["Revocation", c.revocation],
    ["Exposure", c.exposure],
    ["Recovery", c.recovery],
  ]));
  if ((c.links || []).length) {
    frag.append(el("h3", {}, "Links"));
    frag.append(el("ul", { class: "items" }, c.links.map((l) => el("li", {}, el("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, l.title)))));
  }

  frag.append(el("h3", {}, "Review"));
  frag.append(reviewForm(r));

  frag.append(el("h3", {}, "Events"));
  frag.append(c.events.length
    ? el("ul", { class: "items" }, c.events.slice().reverse().map((e) => el("li", {},
      el("div", {}, badge(e.type), " ", day(e.at), e.expires ? ` · expires ${day(e.expires)}` : "", e.by ? el("span", { class: "muted" }, ` · ${e.by}`) : ""),
      e.note ? el("div", { class: "muted small" }, e.note) : null)))
    : el("p", { class: "muted small" }, "No events."));
  frag.append(eventForm(c));
  return frag;
}

function storeDetail(r) {
  const f = r.finding;
  const frag = document.createDocumentFragment();
  frag.append(head(f.store.path, "A store no credential in the registry names"));
  frag.append(kv([
    ["Store", badge(f.store.type)],
    ["Account", f.store.account],
    ["Live", badge(f.state, LIVE_TONE[f.state])],
    ["Last set", day(f.modified)],
    ["Detail", f.detail],
    ["Read by", f.source],
  ]));
  frag.append(el("p", { class: "muted small" }, "Approve to add it to the registry, or mark it for removal from the store."));
  frag.append(el("h3", {}, "Review"));
  frag.append(reviewForm(r));
  return frag;
}

function reviewForm(r) {
  let decision = r.review ? r.review.decision : "";
  const note = el("textarea", { "aria-label": "Note", placeholder: "What to change, or why" });
  note.value = r.review ? r.review.note || "" : "";
  const err = el("p", { class: "small error" });
  const choices = el("div", { class: "row" });
  const draw = () => {
    for (const b of choices.children) b.setAttribute("aria-pressed", b.dataset.value === decision ? "true" : "false");
  };
  for (const d of state.data.decisions) {
    const b = el("button", { type: "button", class: "choice", "data-value": d, onclick: () => { decision = d; draw(); } }, badge(DECISION_LABEL[d] || d, DECISION_TONE[d]));
    choices.append(b);
  }
  draw();
  const save = el("button", { type: "button", class: "primary", onclick: async () => {
    err.textContent = "";
    if (!decision) { err.textContent = "Choose a decision."; return; }
    save.disabled = true;
    try {
      await api("PUT", "/api/reviews", { subject: r.subject, decision, note: note.value });
      toast("Review saved");
      await reload();
    } catch (e) { err.textContent = e.message; } finally { save.disabled = false; }
  } }, "Save review");
  const clear = r.review ? el("button", { type: "button", class: "link", onclick: async () => {
    try {
      await api("PUT", "/api/reviews", { subject: r.subject, decision: "", note: "" });
      toast("Review cleared");
      await reload();
    } catch (e) { err.textContent = e.message; }
  } }, "Clear") : null;
  return el("div", { class: "form" },
    r.review ? el("p", { class: "muted small" }, `${DECISION_LABEL[r.review.decision]} by ${r.review.by || "someone"} on ${day(r.review.at)}`) : null,
    choices, note, el("div", { class: "row" }, save, clear), err);
}

function eventForm(c) {
  const type = el("select", { "aria-label": "Event type" }, state.data.eventTypes.map((t) => el("option", { value: t }, t)));
  type.value = "verified";
  const at = el("input", { type: "datetime-local", "aria-label": "When (default now)" });
  const expires = el("input", { type: "date", "aria-label": "Expires" });
  const expiresRow = el("div", { class: "row" }, el("label", {}, "Expires"), expires);
  expiresRow.hidden = true;
  type.addEventListener("change", () => { expiresRow.hidden = type.value !== "expires" && type.value !== "created" && type.value !== "rotated"; });
  const note = el("input", { type: "text", "aria-label": "Note", placeholder: "Note (optional)" });
  const err = el("p", { class: "small error" });
  const add = el("button", { type: "button", onclick: async () => {
    err.textContent = "";
    const body = { credential: c.id, type: type.value, note: note.value };
    if (at.value) body.at = new Date(at.value).toISOString();
    if (!expiresRow.hidden && expires.value) body.expires = new Date(expires.value + "T00:00:00Z").toISOString();
    add.disabled = true;
    try {
      await api("POST", "/api/events", body);
      toast(`Logged ${type.value}`);
      await reload();
    } catch (e) { err.textContent = e.message; } finally { add.disabled = false; }
  } }, "Log event");
  return el("div", { class: "form" },
    el("div", { class: "row" }, el("label", {}, "Log"), type, at),
    expiresRow,
    el("div", { class: "row" }, note, add), err);
}

// Loading

async function reload() {
  state.data = await api("GET", "/api/data");
  build();
  renderHeader();
  renderSummary();
  renderFilterSelects();
  renderList();
  renderDetail();
}

async function runCheck() {
  const b = $("run-check");
  b.disabled = true;
  b.textContent = "Checking…";
  try {
    const res = await api("POST", "/api/check", {});
    toast(res.error ? "Live check failed" : "Live check done");
    await reload();
  } catch (e) {
    toast(e.message);
  } finally {
    b.disabled = false;
    b.textContent = "Run live check";
  }
}

function moveSelection(step) {
  if (!state.filtered.length) return;
  let i = state.filtered.findIndex((r) => r.subject === state.selected);
  i = i < 0 ? 0 : Math.min(state.filtered.length - 1, Math.max(0, i + step));
  select(state.filtered[i].subject);
  const tr = $("rows").children[i];
  if (tr) tr.scrollIntoView({ block: "nearest" });
}

document.addEventListener("DOMContentLoaded", () => {
  loadHash();
  $("q").addEventListener("input", (e) => { state.q = e.target.value; saveHash(); renderList(); });
  $("clear-filters").addEventListener("click", () => { state.filters = {}; state.q = ""; $("q").value = ""; saveHash(); renderSummary(); renderFilterSelects(); renderList(); });
  $("view-table").addEventListener("click", () => setView("table"));
  $("view-setup").addEventListener("click", () => setView("setup"));
  $("run-check").addEventListener("click", runCheck);
  document.addEventListener("keydown", (e) => {
    const t = e.target.tagName;
    if (t === "INPUT" || t === "TEXTAREA" || t === "SELECT") return;
    if (e.key === "j") moveSelection(1);
    else if (e.key === "k") moveSelection(-1);
    else if (e.key === "Escape") select(null);
    else if (e.key === "/") { e.preventDefault(); $("q").focus(); }
  });
  reload().catch((e) => { $("subtitle").textContent = "Could not load: " + e.message; });
});
