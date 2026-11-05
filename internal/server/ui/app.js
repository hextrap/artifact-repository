"use strict";

// hextrap Artifacts UI: a small hash-routed app over /api/v1. Every element
// is built with DOM methods, never by parsing HTML strings, so names from
// the API can't inject markup.
(() => {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const BASE = document.body.dataset.base || window.location.origin;
  const ROLES = ["reader", "developer", "maintainer", "admin"];
  const FORMAT_LABEL = { npm: "npm", pypi: "PyPI", maven: "Maven", cargo: "Cargo", go: "Go", oci: "Container" };
  const TOKEN_PLACEHOLDER = "<YOUR_TOKEN>";

  // ---------- DOM helpers ----------

  function append(el, children) {
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, String(v));
    }
    return append(el, children);
  }

  function frag(...children) {
    return append(document.createDocumentFragment(), children);
  }

  const p = (d) => ["path", { d }];
  const ICONS = {
    box: [p("M21 8l-9-5-9 5v8l9 5 9-5V8z"), p("M3 8l9 5 9-5"), p("M12 13v8")],
    key: [["circle", { cx: 7.5, cy: 15.5, r: 4.5 }], p("M10.7 12.3L21 2"), p("M16 7l3 3"), p("M18.5 4.5l2 2")],
    user: [["circle", { cx: 12, cy: 8, r: 4 }], p("M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1")],
    menu: [p("M3 6h18M3 12h18M3 18h18")],
    logout: [p("M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"), p("M16 17l5-5-5-5"), p("M21 12H9")],
    plus: [p("M12 5v14M5 12h14")],
    copy: [["rect", { x: 9, y: 9, width: 12, height: 12, rx: 2 }], p("M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1")],
    check: [p("M20 6L9 17l-5-5")],
    trash: [p("M3 6h18"), p("M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"), p("M10 11v6M14 11v6"), p("M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2")],
    shield: [p("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z")],
    terminal: [p("M4 17l6-6-6-6"), p("M12 19h8")],
    history: [["circle", { cx: 12, cy: 12, r: 9 }], p("M12 7v5l3 3")],
    sliders: [p("M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6")],
    arrowLeft: [p("M19 12H5"), p("M12 19l-7-7 7-7")],
    alert: [["circle", { cx: 12, cy: 12, r: 9 }], p("M12 8v4M12 16h.01")],
    lock: [["rect", { x: 5, y: 11, width: 14, height: 10, rx: 2 }], p("M8 11V7a4 4 0 0 1 8 0v4")],
  };

  function fillIcon(svg, name) {
    svg.setAttribute("viewBox", "0 0 24 24");
    for (const [tag, attrs] of ICONS[name] || []) {
      const el = document.createElementNS(SVG_NS, tag);
      for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
      svg.append(el);
    }
    return svg;
  }

  function icon(name) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    return fillIcon(svg, name);
  }

  // ---------- API ----------

  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function api(method, path, body) {
    const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    if (resp.status === 401) {
      window.location.href = "/auth/login";
      throw new ApiError(401, "Your session has ended. Sign in again.");
    }
    if (resp.status === 204) return null;
    const text = await resp.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (e) {
      data = null;
    }
    if (!resp.ok) throw new ApiError(resp.status, (data && data.error) || resp.statusText || "Request failed");
    return data;
  }

  const get = (path) => api("GET", path);
  const enc = encodeURIComponent;

  // ---------- Formatting ----------

  function fmtDate(s) {
    if (!s) return "—";
    return new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  function relTime(s) {
    if (!s) return "—";
    const secs = (new Date(s).getTime() - Date.now()) / 1000;
    const units = [["year", 31536000], ["month", 2592000], ["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]];
    for (const [unit, size] of units) {
      if (Math.abs(secs) >= size) return relFmt.format(Math.round(secs / size), unit);
    }
    return "just now";
  }

  const timeCell = (s) => h("span", { title: fmtDate(s) }, relTime(s));

  function fmtBytes(n) {
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
    return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
  }

  const can = (role, min) => ROLES.indexOf(role) >= ROLES.indexOf(min);
  const capitalize = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
  const graceDays = (repo) => Math.round((repo.delete_grace || 0) / 86400e9);
  const repoHref = (name) => `#/repos/${enc(name)}`;
  const go = (href) => {
    window.location.hash = href;
  };

  // ---------- Components ----------

  function button(label, opts = {}) {
    const cls = ["button"];
    if (opts.kind) cls.push(`button-${opts.kind}`);
    if (opts.small) cls.push("button-small");
    return h(
      "button",
      { class: cls.join(" "), type: opts.type || "button", onclick: opts.onClick, disabled: opts.disabled, title: opts.title },
      opts.icon ? icon(opts.icon) : null,
      label,
    );
  }

  function badge(text, kind) {
    return h("span", { class: kind ? `badge badge-${kind}` : "badge" }, text);
  }

  const formatBadge = (format) => badge(FORMAT_LABEL[format] || format, format);
  const roleBadge = (role) => badge(capitalize(role), role === "admin" ? "admin" : null);
  const hostOf = (u) => {
    try {
      return new URL(u).host;
    } catch (e) {
      return u;
    }
  };
  const isProxy = (repo) => repo.type === "proxy";
  const typeCell = (repo) =>
    isProxy(repo)
      ? h("span", { class: "title-row" }, badge("Proxy", "proxy"), h("span", { class: "cell-secondary" }, hostOf(repo.upstream)))
      : badge("Hosted");

  // The signed-in user and edition, fetched once per page load.
  let mePromise;
  const whoami = () =>
    (mePromise ||= get("/api/v1/me").catch((e) => {
      mePromise = null;
      throw e;
    }));
  // Unknown counts as cloud, so the connect prompts never show by mistake.
  const selfHosted = () => whoami().then((me) => me.edition !== "cloud", () => false);

  // policyBadge says whether a proxy's downloads are checked by a hextrap
  // firewall. Only self-hosted proxies can be unchecked.
  function policyBadge(repo, selfHostedEdition) {
    if (!isProxy(repo)) return null;
    if (repo.firewall) return badge("hextrap firewall", "success");
    return selfHostedEdition ? badge("No policy", "warning") : null;
  }

  // sourceBadge says where a package or version came from.
  // unchecked marks files cached without a hextrap firewall.
  function sourceBadge(source, origin, unchecked) {
    if (source === "upstream" && unchecked)
      return h("span", { class: "title-row" }, badge(`Cached from ${origin || "upstream"}`, "upstream"), badge("Unchecked", "warning"));
    if (source === "upstream") return badge(`Cached from ${origin || "upstream"}`, "upstream");
    if (source === "mixed") return badge("Published and cached");
    return badge("Published", "published");
  }

  function toast(message, kind) {
    const el = h("div", { class: kind === "error" ? "toast toast-error" : "toast", role: "status" }, message);
    document.getElementById("toasts").append(el);
    setTimeout(() => el.remove(), 4000);
  }

  function pageHeader(title, subtitle, ...actions) {
    return h(
      "div",
      { class: "page-header" },
      h("div", null, h("h1", { class: "page-title" }, title), subtitle ? h("div", { class: "page-subtitle" }, subtitle) : null),
      actions.length ? h("div", { class: "title-row" }, actions) : null,
    );
  }

  function panel({ title, subtitle, actions, body, danger }) {
    return h(
      "section",
      { class: danger ? "panel panel-danger" : "panel" },
      title
        ? h(
            "div",
            { class: "panel-header" },
            h("div", null, h("h2", { class: "panel-title" }, title), subtitle ? h("div", { class: "panel-subtitle" }, subtitle) : null),
            actions ? h("div", { class: "title-row" }, actions) : null,
          )
        : null,
      body,
    );
  }

  function emptyState(iconName, title, text, action) {
    return h("div", { class: "empty" }, icon(iconName), h("div", { class: "empty-title" }, title), h("div", null, text), action || null);
  }

  // rows: arrays of cells, or { cells, onClick } objects.
  function table(headers, rows) {
    const thead = h("thead", null, h("tr", null, headers.map((t) => h("th", null, t))));
    const tbody = h(
      "tbody",
      null,
      rows.map((row) => {
        const cells = Array.isArray(row) ? row : row.cells;
        const tr = h("tr", { class: row.onClick ? "clickable" : null }, cells.map((c, i) => {
          const isActions = row.actionsLast && i === cells.length - 1;
          return h("td", { class: isActions ? "actions" : null }, c);
        }));
        if (row.onClick) {
          tr.addEventListener("click", (ev) => {
            if (!ev.target.closest("a, button")) row.onClick();
          });
        }
        return tr;
      }),
    );
    return h("div", { class: "table-wrap" }, h("table", { class: "data" }, thead, tbody));
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      // Clipboard API needs a secure context; fall back for plain http.
      const ta = h("textarea", { readonly: true }, text);
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    toast("Copied to clipboard");
  }

  function copyButton(text, label) {
    const b = h("button", { class: "icon-button copy", type: "button", title: label || "Copy", "aria-label": label || "Copy" }, icon("copy"));
    b.addEventListener("click", () => copyText(text));
    return b;
  }

  function codeBlock(text) {
    return h("div", { class: "code-block" }, h("pre", null, h("code", null, text)), copyButton(text));
  }

  function field(label, control, hint) {
    return h("label", { class: "field" }, h("span", { class: "field-label" }, label), control, hint ? h("span", { class: "field-hint" }, hint) : null);
  }

  function input(attrs) {
    return h("input", Object.assign({ class: "input" }, attrs));
  }

  function select(name, options, selected) {
    return h("select", { class: "input", name }, options.map(([value, label]) => h("option", { value, selected: value === selected }, label)));
  }

  // modal opens a dialog. onSubmit receives the form and may throw to show
  // an error in place; it's responsible for closing the dialog.
  function modal({ title, body, submitLabel, submitKind, cancelLabel, onSubmit }) {
    const dlg = h("dialog", { class: "modal" });
    const error = h("div", { class: "notice notice-danger", hidden: true });
    const submit = submitLabel ? button(submitLabel, { kind: submitKind || "primary", type: "submit" }) : null;
    const form = h(
      "form",
      { method: "dialog" },
      h("div", { class: "modal-header" }, h("h2", { class: "modal-title" }, title)),
      h("div", { class: "modal-body" }, error, body),
      h("div", { class: "modal-footer" }, button(cancelLabel || (submit ? "Cancel" : "Close"), { kind: "ghost", onClick: () => dlg.close() }), submit),
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (!onSubmit) {
        dlg.close();
        return;
      }
      submit.disabled = true;
      error.hidden = true;
      try {
        await onSubmit(form, dlg);
      } catch (e) {
        error.textContent = e.message;
        error.hidden = false;
      } finally {
        submit.disabled = false;
      }
    });
    dlg.append(form);
    dlg.addEventListener("close", () => dlg.remove());
    document.body.append(dlg);
    dlg.showModal();
    const first = form.querySelector("input, select");
    if (first) first.focus();
    return dlg;
  }

  // confirmTyped asks the user to type `expected` before a destructive action.
  function confirmTyped({ title, message, expected, actionLabel, onConfirm }) {
    const box = input({ name: "confirm", autocomplete: "off", spellcheck: "false" });
    const dlg = modal({
      title,
      body: h("div", { class: "form" }, h("p", null, message), field(`Type ${expected} to confirm`, box)),
      submitLabel: actionLabel,
      submitKind: "danger",
      onSubmit: async () => {
        if (box.value.trim() !== expected) throw new Error(`Type ${expected} exactly to confirm.`);
        await onConfirm();
        dlg.close();
      },
    });
  }

  function confirmAction({ title, message, actionLabel, danger, onConfirm }) {
    const dlg = modal({
      title,
      body: h("p", null, message),
      submitLabel: actionLabel,
      submitKind: danger ? "danger" : "primary",
      onSubmit: async () => {
        await onConfirm();
        dlg.close();
      },
    });
  }

  function showSecret(title, secret, note) {
    modal({
      title,
      cancelLabel: "Done",
      body: h(
        "div",
        { class: "form" },
        h("div", { class: "notice notice-warning" }, icon("alert"), h("span", null, "Copy this token now. It won't be shown again.")),
        h("div", { class: "secret" }, h("code", null, secret), copyButton(secret, "Copy token")),
        note ? h("p", null, note) : null,
      ),
    });
  }

  function errorState(err) {
    if (err.status === 404) return panel({ body: emptyState("lock", "Not found", "It doesn't exist, or you don't have access to it.", button("Back to repositories", { onClick: () => go("#/repos") })) });
    if (err.status === 403) return panel({ body: emptyState("lock", "Permission denied", "Your role doesn't allow this.") });
    return panel({ body: emptyState("alert", "Something went wrong", err.message) });
  }

  // ---------- Chrome ----------

  function setChrome(section, crumbs) {
    document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("active", a.dataset.section === section));
    const nodes = [];
    crumbs.forEach((c, i) => {
      if (i) nodes.push(h("span", { class: "sep" }, "/"));
      nodes.push(i === crumbs.length - 1 ? h("span", { class: "current" }, c.label) : h("a", { href: c.href }, c.label));
    });
    document.getElementById("breadcrumb").replaceChildren(...nodes);
    document.title = `${crumbs[crumbs.length - 1].label} · hextrap Artifacts`;
  }

  const closeNav = () => document.body.classList.remove("nav-open");

  // ---------- Repositories ----------

  const upstreamLabel = (u) => (u.firewall ? `hextrap firewall (${hostOf(u.url)})` : `${hostOf(u.url)}, no policy`);

  async function newRepoDialog() {
    let upstreams = {};
    try {
      upstreams = (await get("/api/v1/upstreams")) || {};
    } catch (e) {
      upstreams = {};
    }
    const sh = await selfHosted();
    const name = input({ name: "name", required: true, pattern: "[a-z0-9][a-z0-9._\\-]{0,63}", placeholder: "internal-npm", autocomplete: "off" });
    const format = select("format", [["npm", "npm"], ["pypi", "PyPI (pip, uv, twine)"], ["maven", "Maven (mvn, Gradle)"], ["cargo", "Cargo (Rust crates)"], ["go", "Go modules (proxy only)"], ["oci", "Container images (docker, podman, helm)"]], "npm");
    const type = select("type", [["hosted", "Hosted: publish your own packages"], ["proxy", "Proxy: cache an upstream registry"]], "hosted");
    const upstream = h("select", { class: "input", name: "upstream" });
    const upstreamField = field("Upstream", upstream, "Packages are fetched from here on first install, then served from the cache.");
    const proxyNote = h("div", { class: "field-hint" });
    const anon = h("input", { type: "checkbox", name: "anonymous_read" });

    // Show the upstream choice only for proxies, and only the upstreams the
    // operator allowed for the chosen format.
    function syncType() {
      // Go has no publish command, so Go repositories are always proxies.
      const proxyOnly = format.value === "go";
      if (proxyOnly) type.value = "proxy";
      type.disabled = proxyOnly;
      // Cloud proxies must use a firewall, so only firewalls are offered.
      const choices = (upstreams[format.value] || []).filter((u) => sh || u.firewall);
      upstream.replaceChildren(...choices.map((u) => h("option", { value: u.url }, upstreamLabel(u))));
      const proxy = type.value === "proxy";
      upstreamField.hidden = !proxy || !choices.length;
      proxyNote.hidden = !proxy || choices.length > 0;
      proxyNote.textContent = sh
        ? `${FORMAT_LABEL[format.value]} proxy repositories aren't available yet.`
        : `${FORMAT_LABEL[format.value]} proxy repositories need a hextrap firewall, which doesn't support ${FORMAT_LABEL[format.value]} yet.`;
      name.placeholder = proxy ? `${format.value}-proxy` : `internal-${format.value}`;
    }
    format.addEventListener("change", syncType);
    type.addEventListener("change", syncType);
    syncType();

    const dlg = modal({
      title: "New repository",
      body: h(
        "div",
        { class: "form" },
        field("Name", name, "Lowercase letters, digits, '.', '_' and '-'. It appears in client URLs."),
        h("div", { class: "form-row" }, field("Format", format), field("Type", type)),
        upstreamField,
        proxyNote,
        h("label", { class: "checkbox" }, anon, "Allow anyone to install without signing in"),
      ),
      submitLabel: "Create repository",
      onSubmit: async () => {
        const body = { name: name.value.trim(), format: format.value, type: type.value, anonymous_read: anon.checked };
        if (type.value === "proxy") body.upstream = upstream.value;
        await api("POST", "/api/v1/repos", body);
        dlg.close();
        toast(`Created ${body.name}`);
        go(`${repoHref(body.name)}/setup`);
      },
    });
  }

  async function reposPage() {
    setChrome("repos", [{ label: "Repositories" }]);
    const repos = (await get("/api/v1/repos")) || [];
    const newButton = button("New repository", { kind: "primary", icon: "plus", onClick: newRepoDialog });
    const header = pageHeader("Repositories", "npm and Python package repositories you have access to.", newButton);
    if (!repos.length) {
      return frag(header, panel({ body: emptyState("box", "No repositories yet", "Create a repository to publish and install npm or Python packages.", button("New repository", { kind: "primary", icon: "plus", onClick: newRepoDialog })) }));
    }
    const rows = repos.map((r) => ({
      onClick: () => go(repoHref(r.name)),
      cells: [
        h("a", { href: repoHref(r.name), class: "cell-primary" }, r.name),
        formatBadge(r.format),
        typeCell(r),
        roleBadge(r.role),
        r.anonymous_read ? badge("Public read", "warning") : badge("Private"),
        timeCell(r.created_at),
      ],
    }));
    return frag(header, panel({ body: table(["Name", "Format", "Type", "Your role", "Visibility", "Created"], rows) }));
  }

  const REPO_TABS = [
    { id: "packages", label: "Packages", icon: "box", min: "reader" },
    { id: "setup", label: "Setup", icon: "terminal", min: "reader" },
    { id: "access", label: "Access", icon: "shield", min: "admin" },
    { id: "audit", label: "Audit log", icon: "history", min: "admin" },
    { id: "trash", label: "Trash", icon: "trash", min: "admin" },
    { id: "settings", label: "Settings", icon: "sliders", min: "admin" },
  ];

  async function repoPage(name, tab, pkg) {
    const [repo, sh] = await Promise.all([get(`/api/v1/repos/${enc(name)}`), selfHosted()]);
    const tabs = REPO_TABS.filter((t) => can(repo.role, t.min));
    if (!tabs.some((t) => t.id === tab)) tab = "packages";

    const crumbs = [{ label: "Repositories", href: "#/repos" }, { label: repo.name, href: repoHref(repo.name) }];
    if (tab === "packages" && pkg) crumbs.push({ label: pkg });
    else if (tab !== "packages") crumbs.push({ label: tabs.find((t) => t.id === tab).label });
    setChrome("repos", crumbs);

    const header = h(
      "div",
      { class: "page-header" },
      h(
        "div",
        null,
        h("div", { class: "title-row" }, h("h1", { class: "page-title" }, repo.name), formatBadge(repo.format), isProxy(repo) ? badge("Proxy", "proxy") : null, policyBadge(repo, sh), roleBadge(repo.role)),
        h(
          "div",
          { class: "page-subtitle" },
          isProxy(repo)
            ? `${FORMAT_LABEL[repo.format]} proxy of ${repo.upstream} · created ${relTime(repo.created_at)} by ${repo.created_by}`
            : `${FORMAT_LABEL[repo.format]} repository · created ${relTime(repo.created_at)} by ${repo.created_by}`,
        ),
      ),
    );
    const tabBar = h(
      "nav",
      { class: "tabs", "aria-label": "Repository" },
      tabs.map((t) => h("a", { class: t.id === tab ? "tab active" : "tab", href: `${repoHref(repo.name)}/${t.id}` }, icon(t.icon), t.label)),
    );
    const views = { packages: packagesTab, setup: setupTab, access: accessTab, audit: auditTab, trash: trashTab, settings: settingsTab };
    repo.unchecked = sh && isProxy(repo) && !repo.firewall;
    return frag(header, tabBar, await views[tab](repo, pkg));
  }

  // connectNotice invites a self-hosted proxy without a firewall to connect
  // one. Nothing about the packages is sent anywhere to show it.
  function connectNotice(repo) {
    if (!repo.unchecked) return null;
    const settings = can(repo.role, "admin")
      ? h("a", { href: `${repoHref(repo.name)}/settings` }, "Connect a hextrap firewall")
      : "An admin can connect a hextrap firewall";
    return h(
      "div",
      { class: "notice notice-warning" },
      icon("shield"),
      h(
        "span",
        null,
        `Policy: none. Packages are cached from ${hostOf(repo.upstream)} without checks for malware, typosquats or new releases. `,
        settings,
        " to apply your hextrap policy to every download.",
      ),
    );
  }

  // ---------- Packages ----------

  async function packagesTab(repo, pkg) {
    if (pkg) return versionsView(repo, pkg);
    const pkgs = (await get(`/api/v1/repos/${enc(repo.name)}/packages`)) || [];
    if (!pkgs.length) {
      const [title, text] = isProxy(repo)
        ? ["Nothing cached yet", `Packages appear here the first time someone installs them through this repository. They're fetched from ${hostOf(repo.upstream)}.`]
        : ["No packages yet", "Publish a package to see it here."];
      return frag(
        connectNotice(repo),
        panel({
          body: emptyState("box", title, text, button("Setup instructions", { icon: "terminal", onClick: () => go(`${repoHref(repo.name)}/setup`) })),
        }),
      );
    }
    const rows = pkgs.map((s) => {
      const href = `${repoHref(repo.name)}/packages/${enc(s.name)}`;
      return {
        onClick: () => go(href),
        cells: [
          h("a", { href, class: "cell-primary mono" }, s.display_name || s.name),
          sourceBadge(s.source, s.origin, repo.unchecked),
          s.versions,
          h("span", { class: "mono" }, s.latest),
          timeCell(s.updated),
          fmtBytes(s.size),
        ],
      };
    });
    const cached = pkgs.filter((s) => s.source === "upstream").length;
    const subtitle = isProxy(repo)
      ? `${pkgs.length} ${pkgs.length === 1 ? "package" : "packages"} cached from ${hostOf(repo.upstream)}`
      : `${pkgs.length} ${pkgs.length === 1 ? "package" : "packages"}${cached ? `, ${cached} cached from upstream` : ""}`;
    return frag(connectNotice(repo), panel({ title: "Packages", subtitle, body: table(["Package", "Source", "Versions", "Latest", "Updated", "Size"], rows) }));
  }

  function versionAction(repo, action, body) {
    return api("POST", `/api/v1/repos/${enc(repo.name)}/versions/${action}`, body);
  }

  async function versionsView(repo, pkg) {
    const versions = ((await get(`/api/v1/repos/${enc(repo.name)}/versions?package=${enc(pkg)}`)) || []).slice().reverse();
    const back = h("a", { href: `${repoHref(repo.name)}/packages`, class: "button button-ghost button-small" }, icon("arrowLeft"), "All packages");
    if (!versions.length) return panel({ title: pkg, actions: back, body: emptyState("box", "No versions", "Every version of this package has been deleted.") });

    const rows = versions.map((v) => {
      const size = v.files.reduce((n, f) => n + f.size, 0);
      const files = v.files.filter((f) => !f.filename.endsWith(".metadata"));
      const actions = [];
      // A proxy's index carries upstream's yanks, so local yanks wouldn't show.
      if (can(repo.role, "maintainer") && !isProxy(repo) && !["maven", "oci"].includes(repo.format)) {
        actions.push(
          v.yanked
            ? button("Unyank", { small: true, onClick: () => unyank(repo, v) })
            : button(repo.format === "npm" ? "Deprecate" : "Yank", { small: true, onClick: () => yank(repo, v) }),
        );
      }
      if (can(repo.role, "admin")) {
        actions.push(button("Delete", { small: true, kind: "text-danger", onClick: () => deleteVersion(repo, v) }));
      }
      return {
        actionsLast: true,
        cells: [
          h("span", { class: "cell-primary mono" }, v.version),
          sourceBadge(v.source, v.origin, repo.unchecked),
          timeCell(v.published_at),
          h("span", { class: "cell-secondary" }, v.source === "upstream" ? "—" : v.publisher),
          h("span", { title: files.map((f) => f.filename).join("\n") }, `${files.length} ${files.length === 1 ? "file" : "files"} · ${fmtBytes(size)}`),
          v.yanked ? h("span", { title: v.yank_reason || "" }, badge(repo.format === "npm" ? "Deprecated" : "Yanked", "warning")) : badge("Available", "success"),
          actions,
        ],
      };
    });
    return panel({
      title: h("span", { class: "mono" }, pkg),
      subtitle: isProxy(repo)
        ? `${versions.length} cached ${versions.length === 1 ? "version" : "versions"}. Only files someone has installed are cached.`
        : `${versions.length} ${versions.length === 1 ? "version" : "versions"}`,
      actions: back,
      body: table(["Version", "Source", "Added", "Published by", "Files", "Status", ""], rows),
    });
  }

  function yank(repo, v) {
    const reason = input({ name: "reason", placeholder: "e.g. Broken build, use 1.2.4" });
    const npm = repo.format === "npm";
    const dlg = modal({
      title: `${npm ? "Deprecate" : "Yank"} ${v.package}@${v.version}`,
      body: h(
        "div",
        { class: "form" },
        h("p", null, npm ? "Installs show your message as a deprecation warning. Pinned installs keep working." : "Resolvers skip this version unless it's pinned exactly. Pinned installs keep working."),
        field("Reason", reason, "Shown to people installing it."),
      ),
      submitLabel: npm ? "Deprecate" : "Yank",
      onSubmit: async () => {
        await versionAction(repo, "yank", { package: v.package, version: v.version, reason: reason.value.trim() });
        dlg.close();
        toast(`${npm ? "Deprecated" : "Yanked"} ${v.version}`);
        route();
      },
    });
  }

  async function unyank(repo, v) {
    try {
      await versionAction(repo, "unyank", { package: v.package, version: v.version });
      toast(`Restored ${v.version}`);
      route();
    } catch (e) {
      toast(e.message, "error");
    }
  }

  function deleteVersion(repo, v) {
    confirmAction({
      title: `Delete ${v.package}@${v.version}?`,
      message: isProxy(repo)
        ? `It's removed from the cache and won't be fetched from ${hostOf(repo.upstream)} again, so installs of this version fail. It stays in the trash for ${graceDays(repo)} days, where you can restore it.`
        : `It stops being installable and moves to the trash, where it can be restored for ${graceDays(repo)} days. The version number can never be reused.`,
      actionLabel: "Delete version",
      danger: true,
      onConfirm: async () => {
        await versionAction(repo, "delete", { package: v.package, version: v.version });
        toast(`Deleted ${v.version}`);
        route();
      },
    });
  }

  // ---------- Setup ----------

  function setupTab(repo) {
    const url = new URL(BASE);
    const hostPath = `${url.host}`;
    const scheme = url.protocol.replace(":", "");
    const t = TOKEN_PLACEHOLDER;
    const sections = [];

    if (repo.format === "npm") {
      const reg = `${BASE}/npm/${repo.name}/`;
      sections.push(
        panel({
          title: "Install packages",
          subtitle: "npm, pnpm and Bun read .npmrc in your project or home directory.",
          body: h(
            "div",
            { class: "panel-body" },
            h("div", { class: "code-label" }, ".npmrc"),
            codeBlock(`registry=${reg}\n//${hostPath}/npm/${repo.name}/:_authToken=${t}`),
            h("div", { class: "code-label" }, "Only for one scope"),
            codeBlock(`@your-scope:registry=${reg}\n//${hostPath}/npm/${repo.name}/:_authToken=${t}`),
            h("div", { class: "code-label" }, "Yarn (Berry): .yarnrc.yml"),
            codeBlock(`npmRegistryServer: "${reg}"\nnpmAlwaysAuth: true\nnpmAuthToken: "${t}"`),
          ),
        }),
        isProxy(repo)
          ? null
          : panel({
              title: "Publish packages",
              subtitle: "Requires the Developer role or higher.",
              body: h("div", { class: "panel-body" }, codeBlock(`npm publish --registry ${reg}`)),
            }),
      );
    } else if (repo.format === "pypi") {
      const simple = `${BASE}/pypi/${repo.name}/simple/`;
      const upload = `${BASE}/pypi/${repo.name}/`;
      const authed = `${scheme}://__token__:${t}@${hostPath}/pypi/${repo.name}/simple/`;
      sections.push(
        panel({
          title: "Install packages",
          body: h(
            "div",
            { class: "panel-body" },
            h("div", { class: "code-label" }, "pip"),
            codeBlock(`pip install --index-url ${authed} <package>`),
            h("div", { class: "code-label" }, "pip.conf"),
            codeBlock(`[global]\nindex-url = ${authed}`),
            h("div", { class: "code-label" }, "uv: pyproject.toml"),
            codeBlock(`[[tool.uv.index]]\nname = "hextrap"\nurl = "${simple}"`),
            h("div", { class: "code-label" }, "uv: credentials"),
            codeBlock(`export UV_INDEX_HEXTRAP_USERNAME=__token__\nexport UV_INDEX_HEXTRAP_PASSWORD=${t}`),
          ),
        }),
        isProxy(repo)
          ? null
          : panel({
              title: "Publish packages",
              subtitle: "Requires the Developer role or higher.",
              body: h(
                "div",
                { class: "panel-body" },
                h("div", { class: "code-label" }, "twine"),
                codeBlock(`twine upload --repository-url ${upload} -u __token__ -p ${t} dist/*`),
                h("div", { class: "code-label" }, "uv"),
                codeBlock(`uv publish --publish-url ${upload} --username __token__ --password ${t}`),
              ),
            }),
      );
    } else if (repo.format === "maven") {
      const mvnURL = `${BASE}/maven/${repo.name}/`;
      const server = `<server>\n  <id>hextrap</id>\n  <username>token</username>\n  <password>${t}</password>\n</server>`;
      sections.push(
        panel({
          title: "Resolve dependencies",
          subtitle: "Maven sends credentials from settings.xml for the server with the matching id.",
          body: h(
            "div",
            { class: "panel-body" },
            h("div", { class: "code-label" }, "~/.m2/settings.xml"),
            codeBlock(
              isProxy(repo)
                ? `<settings>\n  <servers>\n    ${server.replaceAll("\n", "\n    ")}\n  </servers>\n  <mirrors>\n    <mirror>\n      <id>hextrap</id>\n      <mirrorOf>central</mirrorOf>\n      <url>${mvnURL}</url>\n    </mirror>\n  </mirrors>\n</settings>`
                : `<settings>\n  <servers>\n    ${server.replaceAll("\n", "\n    ")}\n  </servers>\n</settings>`,
            ),
            isProxy(repo) ? null : h("div", { class: "code-label" }, "pom.xml"),
            isProxy(repo) ? null : codeBlock(`<repositories>\n  <repository>\n    <id>hextrap</id>\n    <url>${mvnURL}</url>\n  </repository>\n</repositories>`),
            h("div", { class: "code-label" }, "Gradle (build.gradle.kts)"),
            codeBlock(`repositories {\n    maven {\n        url = uri("${mvnURL}")\n        credentials {\n            username = "token"\n            password = providers.environmentVariable("HEXTRAP_TOKEN").get()\n        }\n    }\n}`),
          ),
        }),
        isProxy(repo)
          ? null
          : panel({
              title: "Publish artifacts",
              subtitle: "Requires the Developer role or higher. Release files can't be overwritten; SNAPSHOT builds get unique timestamped names.",
              body: h(
                "div",
                { class: "panel-body" },
                h("div", { class: "code-label" }, "pom.xml"),
                codeBlock(`<distributionManagement>\n  <repository>\n    <id>hextrap</id>\n    <url>${mvnURL}</url>\n  </repository>\n  <snapshotRepository>\n    <id>hextrap</id>\n    <url>${mvnURL}</url>\n  </snapshotRepository>\n</distributionManagement>`),
                h("div", { class: "code-label" }, "Then"),
                codeBlock("mvn deploy"),
              ),
            }),
      );
    } else if (repo.format === "cargo") {
      const index = `sparse+${BASE}/cargo/${repo.name}/index/`;
      // Cargo refuses an authenticated registry unless a credential provider
      // is named explicitly, even with a token configured.
      const registry = `[registries.hextrap]\nindex = "${index}"\ncredential-provider = "cargo:token"`;
      const config = isProxy(repo)
        ? `[source.crates-io]\nreplace-with = "hextrap"\n\n${registry}`
        : registry;
      sections.push(
        panel({
          title: isProxy(repo) ? "Use for all crates.io dependencies" : "Install crates",
          subtitle:
            "Needs Cargo 1.74 or newer. Keep the trailing slash on the index URL (Cargo rejects it without one) and the credential-provider line (without it Cargo won't send your token).",
          body: h(
            "div",
            { class: "panel-body" },
            h("div", { class: "code-label" }, ".cargo/config.toml"),
            codeBlock(config),
            h("div", { class: "code-label" }, "Credentials (once per machine)"),
            codeBlock(`cargo login --registry hextrap ${t}\n# or, e.g. in CI: export CARGO_REGISTRIES_HEXTRAP_TOKEN=${t}`),
            isProxy(repo) ? null : h("div", { class: "code-label" }, "Cargo.toml"),
            isProxy(repo) ? null : codeBlock(`[dependencies]\nacme-utils = { version = "1", registry = "hextrap" }`),
          ),
        }),
        isProxy(repo)
          ? null
          : panel({
              title: "Publish crates",
              subtitle: "Requires the Developer role or higher.",
              body: h("div", { class: "panel-body" }, codeBlock("cargo publish --registry hextrap")),
            }),
      );
    } else if (repo.format === "go") {
      // The go command sends credentials from .netrc. With no ",direct"
      // fallback, every module comes through this proxy.
      sections.push(
        panel({
          title: "Use for all Go modules",
          subtitle:
            "The go command sends credentials only over HTTPS, so this server must be reached at an https:// address. It still checks every module against sum.golang.org.",
          body: h(
            "div",
            { class: "panel-body" },
            h("div", { class: "code-label" }, "Environment"),
            codeBlock(`go env -w GOPROXY=${BASE}/go/${repo.name}`),
            h("div", { class: "code-label" }, "~/.netrc"),
            // Go matches the machine against host:port when the URL has a port.
            codeBlock(`machine ${new URL(BASE).host} login token password ${t}`),
          ),
        }),
      );
    } else if (repo.format === "oci") {
      const host = new URL(BASE).host;
      const image = `${host}/${repo.name}/${isProxy(repo) ? "alpine:3.20" : "team/app:1.0"}`;
      sections.push(
        panel({
          title: isProxy(repo) ? "Pull images through the cache" : "Pull images",
          subtitle: "Works with docker, podman, nerdctl and helm (oci:// charts).",
          body: h(
            "div",
            { class: "panel-body" },
            h("div", { class: "code-label" }, "Sign in"),
            codeBlock(`echo ${t} | docker login ${host} -u token --password-stdin`),
            h("div", { class: "code-label" }, "Pull"),
            codeBlock(`docker pull ${image}`),
            isProxy(repo) ? h("div", { class: "field-hint" }, `Images are named as on the upstream: ${host}/${repo.name}/bitnami/redis, with Docker Hub's official images under their short name.`) : null,
          ),
        }),
        isProxy(repo)
          ? null
          : panel({
              title: "Push images",
              subtitle: "Requires the Developer role or higher.",
              body: h(
                "div",
                { class: "panel-body" },
                codeBlock(`docker tag app:1.0 ${image}\ndocker push ${image}`),
              ),
            }),
      );
    }

    const notice = h(
      "div",
      { class: "notice" },
      icon("key"),
      h("span", null, `Replace ${t} with an access token. `, h("a", { href: "#/tokens" }, "Create one"), " for yourself, or ask an admin for a CI token."),
    );
    const proxyNote = isProxy(repo)
      ? h(
          "div",
          { class: "notice" },
          icon("box"),
          h(
            "span",
            null,
            repo.firewall
              ? `This repository caches packages through your hextrap firewall (${hostOf(repo.upstream)}), which applies your policy to every download. ` +
                  `Cached files are checked with it again before they're served, and keep installing if it's unreachable. It's read-only, so publish to a hosted repository instead.`
              : `This repository caches packages from ${repo.upstream}. The first install of each file fetches it from there and checks its hash; ` +
                  `later installs come from the cache, even if ${hostOf(repo.upstream)} is down. It's read-only, so publish to a hosted repository instead.`,
          ),
        )
      : null;
    return frag(connectNotice(repo), proxyNote, notice, sections);
  }

  // ---------- Access ----------

  async function accessTab(repo) {
    const base = `/api/v1/repos/${enc(repo.name)}`;
    const [grants, ciTokens] = await Promise.all([get(`${base}/grants`), get(`${base}/service-tokens`)]);
    const people = grants.filter((g) => g.subject_kind !== "service_token");
    const tokenRoles = Object.fromEntries(grants.filter((g) => g.subject_kind === "service_token").map((g) => [g.subject, g.role]));

    const peopleRows = people.map((g) => ({
      actionsLast: true,
      cells: [
        h("span", { class: "title-row" }, icon(g.subject_kind === "group" ? "shield" : "user"), h("span", { class: "cell-primary" }, g.subject)),
        badge(g.subject_kind === "group" ? "Group" : "User"),
        roleBadge(g.role),
        button("Remove", { small: true, kind: "text-danger", onClick: () => removeGrant(repo, g) }),
      ],
    }));
    const tokenRows = ciTokens.map((tk) => ({
      actionsLast: true,
      cells: [
        h("span", { class: "cell-primary" }, tk.name || tk.id),
        roleBadge(tokenRoles[tk.id] || "none"),
        timeCell(tk.created_at),
        timeCell(tk.expires_at),
        button("Revoke", { small: true, kind: "text-danger", onClick: () => revokeCIToken(repo, tk) }),
      ],
    }));

    return frag(
      panel({
        title: "People and groups",
        subtitle: "Instance admins have Admin on every repository, in addition to these grants.",
        actions: button("Grant access", { kind: "primary", icon: "plus", onClick: () => grantDialog(repo) }),
        body: people.length ? table(["Who", "Type", "Role", ""], peopleRows) : emptyState("user", "No grants", "Grant access to people or groups."),
      }),
      panel({
        title: "CI tokens",
        subtitle: "Tokens for build systems, limited to this repository. They can't be Admin.",
        actions: button("New CI token", { icon: "plus", onClick: () => ciTokenDialog(repo) }),
        body: ciTokens.length ? table(["Name", "Role", "Created", "Expires", ""], tokenRows) : emptyState("key", "No CI tokens", "Create a token for your CI system to publish or install packages."),
      }),
      panel({
        title: "Roles",
        body: table(
          ["Role", "Can"],
          [
            ["Reader", "Install packages"],
            ["Developer", "Install and publish new versions"],
            ["Maintainer", "Also yank or deprecate versions and manage dist-tags"],
            ["Admin", "Also delete versions, manage access and settings, and view the audit log"],
          ],
        ),
      }),
    );
  }

  const roleOptions = (roles) => roles.map((r) => [r, capitalize(r)]);

  function grantDialog(repo) {
    const kind = select("subject_kind", [["user", "User"], ["group", "Group"]], "user");
    const subject = input({ name: "subject", required: true, autocomplete: "off", placeholder: "username or email" });
    kind.addEventListener("change", () => {
      subject.placeholder = kind.value === "group" ? "group name from your identity provider" : "username or email";
    });
    const role = select("role", roleOptions(ROLES), "reader");
    const dlg = modal({
      title: `Grant access to ${repo.name}`,
      body: h("div", { class: "form" }, h("div", { class: "form-row" }, field("Type", kind), field("Role", role)), field("Who", subject)),
      submitLabel: "Grant access",
      onSubmit: async () => {
        await api("PUT", `/api/v1/repos/${enc(repo.name)}/grants`, { subject_kind: kind.value, subject: subject.value.trim(), role: role.value });
        dlg.close();
        toast(`Granted ${role.value} to ${subject.value.trim()}`);
        route();
      },
    });
  }

  function removeGrant(repo, g) {
    confirmAction({
      title: `Remove ${g.subject}?`,
      message: `${g.subject} loses ${g.role} access to ${repo.name}. Access through groups or instance admin is unaffected.`,
      actionLabel: "Remove access",
      danger: true,
      onConfirm: async () => {
        await api("DELETE", `/api/v1/repos/${enc(repo.name)}/grants?subject_kind=${enc(g.subject_kind)}&subject=${enc(g.subject)}`);
        toast(`Removed ${g.subject}`);
        route();
      },
    });
  }

  const lifetimeOptions = [["30", "30 days"], ["90", "90 days"], ["180", "180 days"], ["365", "1 year"]];

  function ciTokenDialog(repo) {
    const name = input({ name: "name", required: true, placeholder: "github-actions", autocomplete: "off" });
    const role = select("role", roleOptions(["reader", "developer", "maintainer"]), "developer");
    const lifetime = select("lifetime", lifetimeOptions, "90");
    const dlg = modal({
      title: `New CI token for ${repo.name}`,
      body: h("div", { class: "form" }, field("Name", name, "Where it's used, so you can recognize it later."), h("div", { class: "form-row" }, field("Role", role), field("Expires after", lifetime))),
      submitLabel: "Create token",
      onSubmit: async () => {
        const res = await api("POST", `/api/v1/repos/${enc(repo.name)}/service-tokens`, { name: name.value.trim(), role: role.value, lifetime_days: Number(lifetime.value) });
        dlg.close();
        route();
        showSecret(`Token for ${name.value.trim()}`, res.token, "Store it as a secret in your CI system, then use it as shown on the Setup tab.");
      },
    });
  }

  function revokeCIToken(repo, tk) {
    confirmAction({
      title: `Revoke ${tk.name || tk.id}?`,
      message: "Anything using this token stops working immediately.",
      actionLabel: "Revoke token",
      danger: true,
      onConfirm: async () => {
        await api("DELETE", `/api/v1/repos/${enc(repo.name)}/service-tokens/${enc(tk.id)}`);
        toast("Token revoked");
        route();
      },
    });
  }

  // ---------- Audit, trash, settings ----------

  async function auditTab(repo) {
    const entries = (await get(`/api/v1/repos/${enc(repo.name)}/audit?limit=200`)) || [];
    if (!entries.length) return panel({ body: emptyState("history", "No activity yet", "Changes to this repository are recorded here.") });
    const rows = entries.map((e) => [
      timeCell(e.time),
      h("span", { class: "cell-primary" }, e.actor),
      h("code", null, e.action),
      h("span", { class: "mono" }, e.target),
      e.before || e.after ? h("span", { class: "cell-secondary" }, `${e.before || "—"} → ${e.after || "—"}`) : "",
      h("span", { class: "cell-secondary mono" }, e.source_ip || ""),
    ]);
    return panel({ title: "Audit log", subtitle: `The ${entries.length} most recent changes`, body: table(["When", "Who", "Action", "Target", "Change", "IP address"], rows) });
  }

  async function trashTab(repo) {
    const versions = (await get(`/api/v1/repos/${enc(repo.name)}/trash`)) || [];
    const days = graceDays(repo);
    const intro = h("div", { class: "notice" }, icon("trash"), h("span", null, `Deleted versions can be restored for ${days} days, then they're purged permanently. Version numbers are never reused.`));
    if (!versions.length) return frag(intro, panel({ body: emptyState("trash", "Trash is empty", "Deleted versions appear here.") }));
    const rows = versions.map((v) => {
      const purgeAt = new Date(new Date(v.deleted_at).getTime() + (repo.delete_grace || 0) / 1e6);
      return {
        actionsLast: true,
        cells: [
          h("span", { class: "cell-primary mono" }, v.package),
          h("span", { class: "mono" }, v.version),
          timeCell(v.deleted_at),
          timeCell(purgeAt.toISOString()),
          [
            button("Restore", { small: true, onClick: () => restore(repo, v) }),
            button("Purge now", { small: true, kind: "text-danger", onClick: () => purge(repo, v) }),
          ],
        ],
      };
    });
    return frag(intro, panel({ title: "Trash", body: table(["Package", "Version", "Deleted", "Purged", ""], rows) }));
  }

  async function restore(repo, v) {
    try {
      await versionAction(repo, "restore", { package: v.package, version: v.version });
      toast(`Restored ${v.package}@${v.version}`);
      route();
    } catch (e) {
      toast(e.message, "error");
    }
  }

  function purge(repo, v) {
    const id = `${v.package}@${v.version}`;
    confirmTyped({
      title: `Permanently delete ${id}?`,
      message: "Its files are removed and it can't be restored.",
      expected: id,
      actionLabel: "Purge",
      onConfirm: async () => {
        await versionAction(repo, "purge", { package: v.package, version: v.version, confirm: id });
        toast(`Purged ${id}`);
        route();
      },
    });
  }

  // The hextrap firewall's formats; others can't be connected yet.
  const FIREWALL_FORMATS = ["pypi", "npm", "go", "cargo"];

  // connectPanel explains how a self-hosted proxy gets policy: the firewall
  // credential goes in the config file, then the repository switches to it.
  function connectPanel(repo, firewallChoice) {
    if (!repo.unchecked) return null;
    let body;
    if (!FIREWALL_FORMATS.includes(repo.format)) {
      body = h("p", null, `The hextrap firewall doesn't support ${FORMAT_LABEL[repo.format]} yet, so this repository caches without policy.`);
    } else if (firewallChoice) {
      body = h("p", null, `Choose "${upstreamLabel(firewallChoice)}" as the upstream above and save. Files already cached are checked with the firewall before they're served again.`);
    } else {
      body = frag(
        h("p", null, "Add your hextrap firewall credential to the server's config file and restart it. Then choose the firewall as this repository's upstream."),
        codeBlock(`hextrap_firewall:\n  username: <credential username>\n  # password: set HEXTRAP_FIREWALL_PASSWORD`),
      );
    }
    return panel({
      title: "Connect to hextrap",
      subtitle: "Apply your hextrap policy (malware, typosquats, soak time, allow and deny lists) to every download. The names of packages this repository fetches are then sent to hextrap.",
      body: h("div", { class: "panel-body" }, body),
    });
  }

  async function settingsTab(repo) {
    const anon = h("input", { type: "checkbox", name: "anonymous_read", checked: repo.anonymous_read });
    const grace = input({ type: "number", name: "delete_grace_days", min: 0, max: 3650, value: graceDays(repo) });
    const save = button("Save changes", { kind: "primary", type: "submit" });
    let upstreamField = null;
    let upstream = null;
    let firewallChoice = null;
    if (isProxy(repo)) {
      const sh = await selfHosted();
      const all = ((await get("/api/v1/upstreams")) || {})[repo.format] || [];
      // Cloud proxies must use a firewall, so only firewalls are offered.
      const choices = all.filter((u) => sh || u.firewall);
      if (!choices.some((u) => u.url === repo.upstream)) choices.unshift({ url: repo.upstream, firewall: repo.firewall });
      firewallChoice = choices.find((u) => u.firewall) || null;
      upstream = h("select", { class: "input", name: "upstream" }, choices.map((u) => h("option", { value: u.url, selected: u.url === repo.upstream }, upstreamLabel(u))));
      upstreamField = field("Upstream", upstream, "Where files are fetched on first install. Files already cached stay.");
    }
    const form = h(
      "form",
      { class: "form panel-body" },
      upstreamField,
      h("label", { class: "checkbox" }, anon, h("span", null, "Allow anyone to install packages without signing in")),
      field("Days deleted versions stay in the trash", grace, "After this, they're purged automatically."),
      h("div", null, save),
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      save.disabled = true;
      try {
        const body = { anonymous_read: anon.checked, delete_grace_days: Number(grace.value) };
        if (upstream && upstream.value !== repo.upstream) body.upstream = upstream.value;
        await api("PATCH", `/api/v1/repos/${enc(repo.name)}`, body);
        toast("Settings saved");
        route();
      } catch (e) {
        toast(e.message, "error");
      } finally {
        save.disabled = false;
      }
    });

    const del = button("Delete repository", {
      kind: "danger",
      onClick: () =>
        confirmTyped({
          title: `Delete ${repo.name}?`,
          message: "This removes the repository, its access grants and its CI tokens. Only empty repositories can be deleted: purge every version first.",
          expected: repo.name,
          actionLabel: "Delete repository",
          onConfirm: async () => {
            await api("DELETE", `/api/v1/repos/${enc(repo.name)}`);
            toast(`Deleted ${repo.name}`);
            go("#/repos");
          },
        }),
    });

    return frag(
      panel({ title: "General", body: form }),
      connectPanel(repo, firewallChoice),
      panel({ title: "Danger zone", danger: true, body: h("div", { class: "panel-body page-header" }, h("div", null, h("div", { class: "cell-primary" }, "Delete this repository"), h("div", { class: "cell-secondary" }, "Only possible once it has no packages.")), del) }),
    );
  }

  // ---------- Tokens ----------

  function newTokenDialog() {
    const name = input({ name: "name", required: true, placeholder: "work laptop", autocomplete: "off" });
    const lifetime = select("lifetime", lifetimeOptions, "90");
    const dlg = modal({
      title: "Create access token",
      body: h("div", { class: "form" }, h("p", null, "The token acts as you, with your current access, for npm, pip, uv and twine."), field("Name", name, "Where you'll use it."), field("Expires after", lifetime)),
      submitLabel: "Create token",
      onSubmit: async () => {
        const res = await api("POST", "/api/v1/tokens", { name: name.value.trim(), lifetime_days: Number(lifetime.value) });
        dlg.close();
        route();
        showSecret("Your new access token", res.token, "Each repository's Setup tab shows where to put it.");
      },
    });
  }

  async function tokensPage() {
    setChrome("tokens", [{ label: "Access tokens" }]);
    const tokens = (await get("/api/v1/tokens")) || [];
    const header = pageHeader("Access tokens", "Personal tokens for package managers. Each one acts as you.", button("Create token", { kind: "primary", icon: "plus", onClick: newTokenDialog }));
    if (!tokens.length) {
      return frag(header, panel({ body: emptyState("key", "No access tokens", "Create a token to use npm, pip, uv or twine with your repositories.", button("Create token", { kind: "primary", icon: "plus", onClick: newTokenDialog })) }));
    }
    const rows = tokens.map((tk) => ({
      actionsLast: true,
      cells: [
        h("span", { class: "cell-primary" }, tk.name || tk.id),
        timeCell(tk.created_at),
        timeCell(tk.expires_at),
        button("Revoke", {
          small: true,
          kind: "text-danger",
          onClick: () =>
            confirmAction({
              title: `Revoke ${tk.name || tk.id}?`,
              message: "Package managers using this token stop working immediately.",
              actionLabel: "Revoke token",
              danger: true,
              onConfirm: async () => {
                await api("DELETE", `/api/v1/tokens/${enc(tk.id)}`);
                toast("Token revoked");
                route();
              },
            }),
        }),
      ],
    }));
    return frag(header, panel({ body: table(["Name", "Created", "Expires", ""], rows) }));
  }

  // ---------- Account ----------

  async function accountPage() {
    setChrome("account", [{ label: "Account" }]);
    const [me, usage] = await Promise.all([get("/api/v1/me"), get("/api/v1/usage")]);
    const groups = me.groups && me.groups.length ? h("div", { class: "chips" }, me.groups.map((g) => badge(g))) : h("span", { class: "cell-secondary" }, "None");
    return frag(
      pageHeader("Account", "Your identity and access."),
      h(
        "div",
        { class: "stats" },
        h("div", { class: "stat" }, h("div", { class: "stat-label" }, "Role"), h("div", { class: "stat-value" }, me.instance_admin ? "Instance admin" : "Member")),
        h("div", { class: "stat" }, h("div", { class: "stat-label" }, "Storage used"), h("div", { class: "stat-value" }, fmtBytes(usage.storage_bytes))),
      ),
      panel({
        title: "Profile",
        body: h(
          "div",
          { class: "panel-body" },
          h(
            "dl",
            { class: "dl" },
            h("dt", null, "User"),
            h("dd", { class: "mono" }, me.subject),
            h("dt", null, "Email"),
            h("dd", null, me.email || "—"),
            h("dt", null, "Groups"),
            h("dd", null, groups),
            h("dt", null, "Instance admin"),
            h("dd", null, me.instance_admin ? badge("Yes", "admin") : "No"),
          ),
        ),
      }),
    );
  }

  // ---------- Router ----------

  const content = document.getElementById("content");
  let renderSeq = 0;

  async function route() {
    const seq = ++renderSeq;
    closeNav();
    const parts = (window.location.hash.replace(/^#\/?/, "") || "repos").split("/").map((s) => decodeURIComponent(s));
    try {
      let view;
      if (parts[0] === "repos" && parts.length === 1) view = await reposPage();
      else if (parts[0] === "repos") view = await repoPage(parts[1], parts[2] || "packages", parts[2] === "packages" ? parts[3] : undefined);
      else if (parts[0] === "tokens") view = await tokensPage();
      else if (parts[0] === "account") view = await accountPage();
      else view = errorState(new ApiError(404, "Not found"));
      if (seq === renderSeq) content.replaceChildren(view);
    } catch (err) {
      if (seq === renderSeq) content.replaceChildren(errorState(err));
    }
  }

  document.querySelectorAll("svg[data-icon]").forEach((svg) => fillIcon(svg, svg.dataset.icon));
  document.getElementById("menu-toggle").addEventListener("click", () => document.body.classList.toggle("nav-open"));
  document.getElementById("scrim").addEventListener("click", closeNav);
  window.addEventListener("hashchange", route);
  if (!window.location.hash) window.history.replaceState(null, "", "#/repos");
  route();
})();
