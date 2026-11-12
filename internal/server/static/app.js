"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const COLORS = { user: "#60a5fa", computer: "#34d399", group: "#fb923c", domain: "#c084fc" };
const cv = $("cv"), ctx = cv.getContext("2d");
let G, target, result, removed = [], selected = null, nodes = [], byId = {}, W = 800, H = 600, drag = null;

async function analyze() {
  const r = await fetch("/api/analyze", { method: "POST", body: JSON.stringify({ removed }) });
  result = await r.json();
  if (selected && !result.paths[selected]) selected = null;
  if (!selected) selected = Object.keys(result.paths).sort((a, b) => result.paths[a].edges.length - result.paths[b].edges.length)[0] || null;
  panel(); draw();
}

function shortName(n) { return n.name.split("@")[0].split(".")[0]; }

function layout() {
  let seed = 12345; const rnd = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296;
  nodes = G.nodes.map((n) => ({ ...n, x: W / 2 + (rnd() - 0.5) * W * 0.6, y: H / 2 + (rnd() - 0.5) * H * 0.6, vx: 0, vy: 0 }));
  byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  for (let it = 0; it < 450; it++) {
    const cool = 1 - it / 450;
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j]; let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01;
      const f = 5200 / d2, d = Math.sqrt(d2); dx /= d; dy /= d;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    for (const e of G.edges) {
      const a = byId[e.from], b = byId[e.to]; const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01;
      const f = (d - 90) * 0.02; a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
    for (const n of nodes) {
      n.vx += (W / 2 - n.x) * 0.004; n.vy += (H / 2 - n.y) * 0.004;
      n.x += Math.max(-12, Math.min(12, n.vx)) * cool; n.y += Math.max(-12, Math.min(12, n.vy)) * cool; n.vx *= 0.6; n.vy *= 0.6;
      n.x = Math.max(30, Math.min(W - 30, n.x)); n.y = Math.max(30, Math.min(H - 30, n.y));
    }
  }
}

function arrow(a, b, color, width, dash) {
  const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1, ux = dx / d, uy = dy / d;
  const sx = a.x + ux * 9, sy = a.y + uy * 9, ex = b.x - ux * 12, ey = b.y - uy * 12;
  ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = width; ctx.setLineDash(dash || []);
  ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(ex, ey); ctx.stroke(); ctx.setLineDash([]);
  ctx.beginPath(); ctx.moveTo(ex + ux * 7, ey + uy * 7); ctx.lineTo(ex - uy * 4, ey + ux * 4); ctx.lineTo(ex + uy * 4, ey - ux * 4); ctx.fill();
}

function draw() {
  const dpr = window.devicePixelRatio || 1;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
  const onPath = new Set(selected && result.paths[selected] ? result.paths[selected].edges : []);
  const pathNodes = new Set();
  for (const id of onPath) { pathNodes.add(G.edges[id].from); pathNodes.add(G.edges[id].to); }
  for (const e of G.edges) {
    if (onPath.has(e.id)) continue;
    arrow(byId[e.from], byId[e.to], removed.includes(e.id) ? "#3a465e" : "#27334b", 1, removed.includes(e.id) ? [4, 4] : null);
  }
  for (const id of onPath) {
    const e = G.edges[id]; arrow(byId[e.from], byId[e.to], "#f87171", 2.8);
    const a = byId[e.from], b = byId[e.to]; ctx.fillStyle = "#fecaca"; ctx.font = "11px system-ui"; ctx.textAlign = "center";
    ctx.fillText(e.type, (a.x + b.x) / 2, (a.y + b.y) / 2 - 6);
  }
  for (const n of nodes) {
    const r = n.type === "user" ? 6 : 8;
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 7); ctx.fillStyle = COLORS[n.type]; ctx.fill();
    if (n.id === target || n.high_value) { ctx.lineWidth = 2.5; ctx.strokeStyle = "#f59e0b"; ctx.stroke(); }
    if (n.id === selected) { ctx.lineWidth = 3; ctx.strokeStyle = "#fff"; ctx.beginPath(); ctx.arc(n.x, n.y, r + 4, 0, 7); ctx.stroke(); }
    const atRisk = n.type === "user" && result.paths[n.id];
    if (atRisk && !pathNodes.has(n.id)) { ctx.beginPath(); ctx.arc(n.x, n.y, r + 3, 0, 7); ctx.strokeStyle = "#f8717166"; ctx.lineWidth = 1.5; ctx.stroke(); }
    if (pathNodes.has(n.id) || n.high_value || n.type !== "user") { ctx.fillStyle = pathNodes.has(n.id) ? "#fff" : "#8fa1c0"; ctx.font = "11px system-ui"; ctx.textAlign = "center"; ctx.fillText(shortName(n), n.x, n.y + r + 13); }
  }
}

function panel() {
  const s = result.summary;
  $("pct").textContent = Math.round(s.percent_risk) + "%"; $("pct").className = "big" + (s.at_risk === 0 ? " ok" : "");
  $("counts").textContent = `${s.at_risk} of ${s.users} users` + (s.at_risk ? ` · shortest path ${s.shortest_hops} hops` : "");
  const p = $("path"); p.replaceChildren();
  const path = selected && result.paths[selected];
  if (!path) p.append(el("p", "mute", s.at_risk ? "Select a user node." : "No user can reach the target. Well done."));
  else {
    p.append(el("p", "mute", `${shortName(byId[selected])} reaches the target in ${path.edges.length} steps (attack cost ${path.cost}):`));
    path.steps.forEach((st, i) => { const row = el("div", "step"); row.append(el("b", "", String(i + 1)), el("span", "", st.text)); p.append(row); });
  }
  const c = $("chokes"); c.replaceChildren();
  if (!(result.chokepoints || []).length) c.append(el("p", "mute", "Nothing left to fix."));
  for (const k of result.chokepoints || []) {
    const box = el("div", "choke"); box.append(el("div", "t", k.fix));
    const m = el("div", "m"); const b = el("button", "fix", "Apply fix");
    b.addEventListener("click", () => { removed.push(k.edge); analyze(); });
    m.append(el("span", "", `${k.paths} paths run through it · cuts off ${k.impact} users`), b); box.append(m); c.append(box);
  }
  $("fixed").textContent = removed.length ? `${removed.length} fix(es) applied` : "";
}

function fit() {
  const r = cv.parentElement.getBoundingClientRect(); const dpr = window.devicePixelRatio || 1;
  W = r.width; H = r.height; cv.width = W * dpr; cv.height = H * dpr;
}
function pick(ev) {
  const r = cv.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
  return nodes.find((n) => (n.x - x) ** 2 + (n.y - y) ** 2 < 144);
}
cv.addEventListener("mousedown", (e) => { drag = pick(e); if (drag) cv.style.cursor = "grabbing"; });
window.addEventListener("mouseup", (e) => { if (drag && !drag.moved) { if (drag.type === "user" && result.paths[drag.id]) { selected = drag.id; panel(); draw(); } } if (drag) drag.moved = false; drag = null; cv.style.cursor = "default"; });
cv.addEventListener("mousemove", (e) => { if (drag) { const r = cv.getBoundingClientRect(); drag.x = e.clientX - r.left; drag.y = e.clientY - r.top; drag.moved = true; draw(); } else cv.style.cursor = pick(e) ? "pointer" : "default"; });
$("reset").addEventListener("click", () => { removed = []; analyze(); });

(async () => {
  const d = await (await fetch("/api/graph")).json();
  G = d.graph; target = d.target; $("target").textContent = target.split("@")[0];
  fit(); layout(); await analyze();
  window.addEventListener("resize", () => { fit(); layout(); draw(); });
})();
