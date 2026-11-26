// MiniSeal customer UI. Plain JS, no build step, no third-party code.
// Safety rule for this file: server data goes into the page with
// textContent / text nodes only, never parsed as HTML.
"use strict";

const $ = (id) => document.getElementById(id);

// ---------- tiny DOM helpers ----------

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else n.setAttribute(k, v);
  }
  n.append(...kids); // strings become text nodes: safe
  return n;
}

function show(node, on = true) { node.hidden = !on; }

function fillKv(dl, pairs) {
  dl.replaceChildren();
  for (const [k, v] of pairs) {
    if (v === null || v === undefined) continue;
    dl.append(el("dt", { text: k }), el("dd", {}, v));
  }
}

function pill(label) {
  return el("span", { class: `pill ${label}`, text: label === "likely_real" ? "likely real" : "suspicious" });
}

const when = (iso) => new Date(iso).toLocaleString();
const mono = (s) => el("span", { class: "mono", text: s });

function showError(box, err) {
  box.textContent = err.message || String(err);
  show(box);
}

// ---------- API ----------

// The key is kept in sessionStorage: it survives a page reload but is
// forgotten when the tab closes. (localStorage would keep it forever on
// this computer.) Either way, any script on the page could read it, which
// is why the server sends a strict Content-Security-Policy.
const KEY_STORE = "miniseal.apiKey";
const state = { key: sessionStorage.getItem(KEY_STORE), owner: null, sealed: null };

async function api(path, { auth = false, ...opts } = {}) {
  const headers = { ...(opts.headers || {}) };
  if (auth) headers["X-API-Key"] = state.key;
  const resp = await fetch(path, { ...opts, headers });
  if (!resp.ok) {
    let message = `${resp.status} ${resp.statusText}`;
    try {
      const { detail } = await resp.json();
      if (typeof detail === "string") message = detail;
      else if (Array.isArray(detail)) message = detail.map((d) => d.msg).join("; ");
      else if (detail && detail.message) message = detail.message;
    } catch { /* not JSON */ }
    const err = new Error(message);
    err.status = resp.status;
    if (auth && resp.status === 401) signOut("Your API key is no longer valid (revoked?). Sign in again.");
    throw err;
  }
  return resp;
}

// ---------- account ----------

function renderWho() {
  const who = $("who");
  who.replaceChildren();
  if (state.owner) {
    const out = el("button", { class: "link", text: "Sign out" });
    out.onclick = () => signOut();
    who.append("Signed in as ", el("b", { text: state.owner }), out);
  } else {
    who.append("Not signed in");
  }
  show($("account"), !state.owner);
  show($("sealing"), !!state.owner && $("newkey").hidden);
}

async function signIn(key) {
  state.key = key;
  const { owner } = await (await api("/me", { auth: true })).json();
  state.owner = owner;
  sessionStorage.setItem(KEY_STORE, key);
  renderWho();
  loadSeals();
}

function signOut(message) {
  sessionStorage.removeItem(KEY_STORE);
  Object.assign(state, { key: null, owner: null, sealed: null });
  show($("seal-result"), false);
  renderWho();
  if (message) showError($("account-error"), new Error(message));
}

function accountMode(mode) {
  show($("signup-form"), mode === "signup");
  show($("login-form"), mode === "login");
  $("mode-signup").classList.toggle("primary", mode === "signup");
  $("mode-login").classList.toggle("primary", mode === "login");
  show($("account-error"), false);
}

$("mode-signup").onclick = () => accountMode("signup");
$("mode-login").onclick = () => accountMode("login");

$("signup-form").onsubmit = async (e) => {
  e.preventDefault();
  show($("account-error"), false);
  try {
    const resp = await api("/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ owner: $("signup-name").value.trim() }),
    });
    const { key } = await resp.json();
    $("newkey-value").textContent = key;
    show($("newkey"));
    await signIn(key);
  } catch (err) {
    if (err.status === 404) {
      err.message = "Sign-up is turned off on this server. Ask the operator for a key " +
        "(python -m app.auth create <name>) and use “I have an API key”.";
    } else if (err.status === 422) {
      err.message = "Names are 1-64 characters: letters, digits, '_', '.', '-'.";
    }
    showError($("account-error"), err);
  }
};

$("login-form").onsubmit = async (e) => {
  e.preventDefault();
  show($("account-error"), false);
  try {
    await signIn($("login-key").value.trim());
    $("login-key").value = "";
  } catch (err) {
    state.key = null;
    showError($("account-error"), err);
  }
};

$("copy-key").onclick = async () => {
  await navigator.clipboard.writeText($("newkey-value").textContent);
  $("copy-key").textContent = "Copied";
};

$("newkey-done").onclick = () => {
  $("newkey-value").textContent = ""; // don't leave it on screen
  $("copy-key").textContent = "Copy";
  show($("newkey"), false);
  renderWho();
};

// ---------- seal ----------

function filenameFrom(resp, fallback) {
  const m = /filename="([^"]+)"/.exec(resp.headers.get("Content-Disposition") || "");
  return m ? m[1] : fallback;
}

async function sealFile(file) {
  show($("seal-error"), false);
  show($("seal-result"), false);
  const form = new FormData();
  form.append("file", file);
  try {
    const resp = await api("/seal", { method: "POST", body: form, auth: true });
    const blob = await resp.blob();
    const h = (n) => resp.headers.get(n);
    state.sealed = { blob, name: filenameFrom(resp, "sealed.png") };

    $("seal-img").src = URL.createObjectURL(blob);
    const label = h("X-Miniseal-Detector-Label");
    fillKv($("seal-kv"), [
      ["Seal ID", mono(h("X-Miniseal-Seal-Id"))],
      ["Owner", state.owner],
      ["Signed with", mono(`service key ${h("X-Miniseal-Key-Id")}`)],
      ["Content check", label
        ? el("span", {}, pill(label), ` score ${Number(h("X-Miniseal-Detector-Score")).toFixed(3)}`)
        : "unavailable (the seal is still valid)"],
    ]);
    show($("seal-result"));
    loadSeals();
  } catch (err) {
    showError($("seal-error"), err);
  }
}

function download(blob, name) {
  const a = el("a", { href: URL.createObjectURL(blob), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

$("seal-download").onclick = () => download(state.sealed.blob, state.sealed.name);
$("seal-verify").onclick = () => { selectTab("verify"); verifyFile(state.sealed.blob, state.sealed.name); };

async function loadSeals() {
  const box = $("seals-list");
  try {
    const seals = await (await api("/seals", { auth: true })).json();
    if (!seals.length) {
      box.replaceChildren(el("p", { class: "note", text: "No seals yet. Seal your first image above." }));
      return;
    }
    const rows = seals.map((s) => el("tr", {},
      el("td", { text: when(s.created_at) }),
      el("td", { title: s.seal_id }, mono(s.seal_id.slice(0, 12) + "…")),
      el("td", {}, s.detector_at_seal ? pill(s.detector_at_seal.label) : "–"),
    ));
    box.replaceChildren(el("table", {},
      el("thead", {}, el("tr", {}, el("th", { text: "Sealed" }), el("th", { text: "Seal ID" }), el("th", { text: "Content check at sealing" }))),
      el("tbody", {}, ...rows)));
  } catch (err) {
    box.replaceChildren(el("div", { class: "error", text: err.message }));
  }
}
$("refresh-seals").onclick = loadSeals;

// ---------- demo: what happens to a sealed file in the wild ----------
// A PNG is a list of chunks: [length][type][data][crc]. The seal is one
// iTXt chunk whose data starts with "miniseal\0".

function pngChunks(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunks = [];
  for (let p = 8; p + 12 <= bytes.length;) {
    const len = view.getUint32(p);
    const type = String.fromCharCode(...bytes.subarray(p + 4, p + 8));
    chunks.push({ type, start: p, end: p + 12 + len, data: bytes.subarray(p + 8, p + 8 + len) });
    p += 12 + len;
    if (type === "IEND") break;
  }
  return chunks;
}

function sealChunk(bytes) {
  const tag = new TextEncoder().encode("miniseal\0");
  const c = pngChunks(bytes).find((c) => c.type === "iTXt" && tag.every((b, i) => c.data[i] === b));
  return c ? bytes.slice(c.start, c.end) : null; // copied whole, CRC included
}

async function redraw(blob, edit, type = "image/png", quality) {
  const bitmap = await createImageBitmap(blob, { colorSpaceConversion: "none", premultiplyAlpha: "none" });
  const canvas = el("canvas", { width: bitmap.width, height: bitmap.height });
  const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0);
  if (edit) edit(ctx);
  return new Promise((ok) => canvas.toBlob(ok, type, quality));
}

// Attacker: change one pixel, then put the original seal chunk back.
$("demo-tamper").onclick = async () => {
  const original = new Uint8Array(await state.sealed.blob.arrayBuffer());
  const chunk = sealChunk(original);
  const edited = new Uint8Array(await (await redraw(state.sealed.blob, (ctx) => {
    const px = ctx.getImageData(0, 0, 1, 1);
    for (let i = 0; i < 3; i++) px.data[i] = 255 - px.data[i];
    ctx.putImageData(px, 0, 0);
  })).arrayBuffer());
  const iend = pngChunks(edited).find((c) => c.type === "IEND").start;
  const forged = new Blob([edited.subarray(0, iend), chunk, edited.subarray(iend)], { type: "image/png" });
  selectTab("verify");
  verifyFile(forged, "edited-one-pixel.png");
};

// Social media: decode and re-encode as JPEG. Metadata (our seal) is dropped.
$("demo-strip").onclick = async () => {
  const resaved = await redraw(state.sealed.blob, null, "image/jpeg", 0.85);
  selectTab("verify");
  verifyFile(resaved, "resaved.jpg");
};

// ---------- verify ----------

const REASONS = {
  pixels_modified: "The image was changed after it was sealed.",
  invalid_signature: "The seal was forged or altered: its signature doesn't match this image and seal.",
  malformed_seal: "The seal data is damaged, or in a format we don't accept.",
  unknown_key: "It was sealed with a key that isn't ours.",
  unknown_seal: "The signature is valid, but this seal is not in our registry.",
  registry_mismatch: "Our record of this seal doesn't match the seal in the image.",
};

async function verifyFile(file, name) {
  show($("verify-error"), false);
  show($("verify-result"), false);
  const form = new FormData();
  form.append("file", file, name || file.name || "image");
  try {
    const r = await (await api("/verify", { method: "POST", body: form })).json();
    $("verify-img").src = URL.createObjectURL(file);
    renderVerdict(r);
    show($("verify-result"));
  } catch (err) {
    showError($("verify-error"), err);
  }
}

function renderVerdict(r) {
  const s = r.seal;
  const box = $("verdict");
  if (r.status === "sealed_intact") {
    box.className = "verdict ok";
    $("verdict-title").textContent = "✓ Sealed and unchanged";
    $("verdict-why").textContent = `Sealed by ${s.owner} on ${when(s.created_at)}. Every pixel is exactly as it was when sealed.`;
  } else if (r.status === "sealed_tampered") {
    box.className = "verdict bad";
    $("verdict-title").textContent = "✗ Tampered";
    $("verdict-why").textContent = (REASONS[r.reason] || r.reason) +
      (s ? ` The seal itself is genuine: ${s.owner} sealed the original on ${when(s.created_at)}.` : "");
  } else {
    box.className = "verdict none";
    $("verdict-title").textContent = "No seal found";
    $("verdict-why").textContent = "This file carries no MiniSeal seal. That alone doesn't make it fake: " +
      "re-saving, converting or screenshotting an image removes its seal.";
  }
  fillKv($("verify-kv"), s ? [
    ["Sealed by", s.owner],
    ["Sealed at", when(s.created_at)],
    ["Seal ID", mono(s.seal_id)],
    ["Signed with", mono(`service key ${s.key_id}`)],
  ] : r.reason ? [["Reason code", mono(r.reason)]] : []);

  const d = r.detector;
  const det = $("detector");
  det.replaceChildren(el("h3", { style: "margin:0 0 6px;font-size:15px", text: "Content check" }));
  if (!d) {
    det.append(el("p", { class: "note", text: "Unavailable right now. The seal result above is still valid." }));
    return;
  }
  const meter = el("div", { class: "meter" }, el("i", { style: `width:${(d.score * 100).toFixed(1)}%` }));
  det.append(
    el("div", {}, pill(d.label), ` score ${d.score.toFixed(3)} · ${d.latency_ms} ms`),
    meter,
    el("p", { class: "note", text: "0 = looks real, 1 = looks generated or edited. Independent of the seal: " +
      "a sealed image can still be fake, and an unsealed one can be real." }),
  );
  if (s && s.detector_at_seal) {
    const a = s.detector_at_seal;
    det.append(el("p", { class: "note" }, "At sealing: ", pill(a.label), ` score ${a.score.toFixed(3)} (${a.model})`));
  }
  if (d.model.startsWith("dummy")) {
    det.append(el("p", { class: "warn", text: `Model “${d.model}” is a placeholder: its score is derived from a hash of the pixels, not from their content.` }));
  }
}

// ---------- tabs, file inputs, drag and drop ----------

function selectTab(name) {
  for (const t of ["seal", "verify"]) {
    $(`tab-${t}`).setAttribute("aria-selected", String(t === name));
    show($(`panel-${t}`), t === name);
  }
}
$("tab-seal").onclick = () => selectTab("seal");
$("tab-verify").onclick = () => selectTab("verify");

function fileDrop(dropId, inputId, handler) {
  const drop = $(dropId), input = $(inputId);
  input.onchange = () => { if (input.files[0]) handler(input.files[0]); input.value = ""; };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]);
  };
}
fileDrop("seal-drop", "seal-file", sealFile);
fileDrop("verify-drop", "verify-file", (f) => verifyFile(f));

// ---------- start ----------

accountMode("signup");
renderWho();
if (state.key) signIn(state.key).catch(() => signOut());
