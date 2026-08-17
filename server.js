const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const DxfParser = require('dxf-parser');
const db = require('./db');
const { generatePdf } = require('./pdf');
const { FORMATS, detectFormat, parseToDxfShape } = require('./cadformats');
const { parseIfc } = require('./cadifc');
const MAX_UPLOAD_MB = 20;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 } });

// multer rejects oversized files before the route runs, and by default that
// surfaces as an HTML error page rather than JSON. Turn it into a clear message.
const uploadOne = field => (req, res, next) => upload.single(field)(req, res, err => {
  if (!err) return next();
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      error: `That file is larger than the ${MAX_UPLOAD_MB} MB upload limit.`,
      detail: 'Large drawings are usually full of 3D geometry or images. Try exporting just the floor plan sheet, purging unused blocks (PURGE in AutoCAD), or saving a 2D-only copy.',
    });
  }
  return res.status(400).json({ error: 'That file could not be uploaded: ' + err.message });
});

const app = express();
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;
const DEPARTMENTS = ['Technical Services', 'Maintenance Services', 'Infrastructure Services', 'Development Services'];

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Errors thrown as UserError carry a message meant for the person using the
// app, so it's safe (and useful) to send it back. Anything else is unexpected,
// so the user gets a reference code and the real detail goes to the log.
class UserError extends Error {
  constructor(message, detail) { super(message); this.expose = true; this.detail = detail || null; }
}
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  if (e && e.expose) return res.status(400).json({ error: e.message, detail: e.detail || undefined });
  const ref = Math.random().toString(36).slice(2, 8).toUpperCase();
  console.error('[' + ref + ']', e);
  res.status(500).json({
    error: 'Something went wrong on the server (reference ' + ref + ').',
    detail: 'If this keeps happening, quote reference ' + ref + ' so the log can be checked.',
  });
});

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, SECRET);
    const user = await db.get('SELECT id, email, name, role, department, designation, phone, dob, signature, status, must_change_password FROM users WHERE id = ?', [payload.id]);
    if (!user || user.status !== 'ACTIVE') return res.status(401).json({ error: 'Account not active' });
    req.user = user; req.user.id = Number(req.user.id);
    next();
  } catch { return res.status(401).json({ error: 'Invalid session' }); }
}
// Roles:
//   ADMIN     - full access
//   MANAGER   - like a normal user, except they may manage the master item list
//   ARCHITECT - like a normal user, except they may manage CAD Quantify materials
//   USER      - standard access
const ROLES = ['ADMIN', 'MANAGER', 'ARCHITECT', 'USER'];
const adminOnly = (req, res, next) => req.user.role === 'ADMIN' ? next() : res.status(403).json({ error: 'Admin only' });
// add/edit/delete items in the master list
const itemManager = (req, res, next) => ['ADMIN', 'MANAGER'].includes(req.user.role)
  ? next() : res.status(403).json({ error: 'Only admins and managers can change the item list' });
// add/edit/delete CAD Quantify materials
const materialManager = (req, res, next) => ['ADMIN', 'ARCHITECT'].includes(req.user.role)
  ? next() : res.status(403).json({ error: 'Only admins and architects can change CAD materials' });

app.post('/api/register', wrap(async (req, res) => {
  const { email, name, password } = req.body || {};
  if (!email || !name || !password) return res.status(400).json({ error: 'All fields required' });
  if (!/^[a-zA-Z0-9._%+-]+@fdc\.mv$/i.test(email.trim())) return res.status(400).json({ error: 'Registration requires an @fdc.mv work email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    await db.run('INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)',
      [email.trim().toLowerCase(), name.trim(), bcrypt.hashSync(password, 10)]);
    res.json({ ok: true, message: 'Registration submitted. An admin must approve your account and assign your department before you can log in.' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(400).json({ error: 'Email already registered' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const user = await db.get('SELECT * FROM users WHERE email = ?', [(email || '').trim().toLowerCase()]);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
  if (user.status === 'PENDING') return res.status(403).json({ error: 'Account awaiting admin approval' });
  if (user.status === 'DISABLED') return res.status(403).json({ error: 'Account disabled. Contact admin.' });
  const token = jwt.sign({ id: Number(user.id) }, SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: Number(user.id), email: user.email, name: user.name, role: user.role, department: user.department, designation: user.designation, phone: user.phone, dob: user.dob, signature: user.signature, must_change_password: Number(user.must_change_password) ? 1 : 0 } });
}));

app.get('/api/me', auth, (req, res) => res.json(req.user));

app.post('/api/me/password', auth, wrap(async (req, res) => {
  const { current, next: nextPw } = req.body || {};
  if (!nextPw || nextPw.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const u = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(current || '', u.password_hash)) return res.status(400).json({ error: 'Current password is incorrect' });
  // changing the password clears any admin-forced reset flag
  await db.run('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?', [bcrypt.hashSync(nextPw, 10), req.user.id]);
  res.json({ ok: true });
}));

app.put('/api/me/profile', auth, wrap(async (req, res) => {
  const { name, designation, phone, dob, signature } = req.body || {};
  if (name !== undefined && !String(name).trim()) return res.status(400).json({ error: 'Name cannot be empty' });
  if (signature !== undefined && signature !== null && signature !== '') {
    if (!String(signature).startsWith('data:image/png;base64,')) return res.status(400).json({ error: 'Signature must be a PNG image' });
    if (String(signature).length > 1500000) return res.status(400).json({ error: 'Signature image too large (max 1MB)' });
  }
  await db.run(`UPDATE users SET name = COALESCE(?, name), designation = COALESCE(?, designation),
                phone = COALESCE(?, phone), dob = COALESCE(?, dob), signature = COALESCE(?, signature) WHERE id = ?`,
    [name !== undefined ? String(name).trim() : null, designation ?? null, phone ?? null, dob ?? null, signature ?? null, req.user.id]);
  res.json({ ok: true });
}));

app.get('/api/items', auth, wrap(async (req, res) => {
  const q = (req.query.q || '').trim();
  let rows;
  if (q) {
    // word-based search: every word must appear somewhere in the name ("18 mm" matches "18mm Marin Plywood")
    const words = q.toLowerCase().split(/\s+/).filter(Boolean).slice(0, 6);
    const where = words.map(() => "LOWER(name) LIKE ?").join(' AND ');
    rows = await db.all('SELECT id, name, unit, price FROM items WHERE active = 1 AND ' + where + ' ORDER BY name LIMIT 20',
      words.map(w => '%' + w + '%'));
  } else {
    rows = await db.all('SELECT id, name, unit, price FROM items WHERE active = 1 ORDER BY name');
  }
  res.json(rows);
}));

async function audit(user, action, details) {
  try { await db.run('INSERT INTO audit_log (user_id, user_name, action, details) VALUES (?,?,?,?)',
    [user.id, user.name, action, details]); } catch (e) { console.error('audit failed', e); }
}

// Tokenize an item name for duplicate comparison. Short but meaningful distinguishing tokens -
// sizes (2", 3mm, 20A), and short type/model codes (SP, PH) - are kept and compared for EXACT
// equality elsewhere, so "Wall Scrapper 2"" vs "Wall Scrapper 3"" and "Quick Coupler SP" vs
// "Quick Coupler PH" are correctly treated as different items, not near-duplicates. Only true
// single-character filler tokens (e.g. a stray "x") are dropped.
const itemNorm = n => n.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const itemWords = n => itemNorm(n).split(' ').filter(w => w.length > 1 || /\d/.test(w));

async function similarItems(name) {
  const norm = itemNorm(name);
  const words = itemWords(name);
  const allItems = await db.all('SELECT id, name, unit, price FROM items WHERE active = 1');
  return allItems.filter(i => {
    const inorm = itemNorm(i.name);
    if (inorm === norm) return true;
    if (words.length === 0) return false;
    const iwords = itemWords(i.name);
    if (iwords.length !== words.length) return false; // different number of significant tokens (e.g. missing/extra size) -> not a duplicate
    const iwordSet = new Set(iwords);
    const hits = words.filter(w => iwordSet.has(w)).length; // exact token match, not substring, so "2" never matches inside "12"
    return hits / words.length >= 0.85;
  }).slice(0, 8);
}

// ---------- CAD drawing takeoff (ported from the CAD Quantify BETA engine) ----------
// Block expansion (INSERT/BLOCK), raster room detection from open wall lines, legend-key /
// block-name symbol labeling, and standalone ingredient-recipe materials. Table/route names
// keep the live app's existing /api/cad/* prefix and cad_ table prefix; the underlying schema
// and calculation logic are BETA's (materials are standalone — no legend concept, see db.js).
const CAD_UNIT_FACTORS = { mm: 0.001, cm: 0.01, m: 1, ft: 0.3048, in: 0.0254 };
const CAD_INSUNITS_MAP = { 1: 'in', 2: 'ft', 4: 'mm', 5: 'cm', 6: 'm' };

function cadDist(a, b) { return Math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2); }
function cadEntityLength(e) {
  const verts = e.vertices || [];
  if (verts.length < 2) return 0;
  let len = 0;
  for (let i = 1; i < verts.length; i++) len += cadDist(verts[i - 1], verts[i]);
  if (e.shape) len += cadDist(verts[verts.length - 1], verts[0]);
  return len;
}
function cadPolygonArea(e) {
  const verts = e.vertices || [];
  if (!e.shape || verts.length < 3) return 0;
  let area = 0;
  for (let i = 0; i < verts.length; i++) {
    const a = verts[i], b = verts[(i + 1) % verts.length];
    area += a.x * b.y - b.x * a.y;
  }
  return Math.abs(area) / 2;
}
function cadDetectUnit(dxf) {
  try {
    const raw = dxf.header && dxf.header['$INSUNITS'];
    const code = raw && typeof raw === 'object' ? raw.value : raw;
    return CAD_INSUNITS_MAP[Number(code)] || null;
  } catch { return null; }
}
// AutoCAD auto-generates a block name when one wasn't given by the person who drew it. A block
// someone actually typed a name for is a real, human-chosen label worth surfacing.
function isReadableBlockName(name) {
  const s = String(name || '').trim();
  if (!s) return false;
  if (/^A\$C[0-9a-f]{6,}$/i.test(s)) return false;
  if (/^\*[A-Za-z_]*\d+$/.test(s)) return false;
  return true;
}
function cadNameMatch(a, b) {
  const norm = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]+/g, ' ').trim();
  const na = norm(a), nb = norm(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  const wa = na.split(' ').filter(Boolean), wb = nb.split(' ').filter(Boolean);
  if (!wa.length || !wb.length) return false;
  const hits = wb.filter(w => wa.includes(w)).length;
  return hits / wb.length >= 0.6;
}

// ---------- color resolution ----------
const CAD_ACI_NAMES = { 1: 'red', 2: 'yellow', 3: 'green', 4: 'cyan', 5: 'blue', 6: 'magenta', 7: 'white', 8: 'dark gray', 9: 'light gray' };
function cadResolveColor(e, layerTable) {
  let colorIndex = e.colorIndex, colorDec = e.color;
  if (colorIndex == null) {
    const layerDef = layerTable && layerTable[e.layer];
    if (layerDef) { colorIndex = layerDef.colorIndex; colorDec = layerDef.color; }
  }
  const hex = colorDec != null ? '#' + Number(colorDec).toString(16).padStart(6, '0') : null;
  const name = colorIndex != null ? (CAD_ACI_NAMES[colorIndex] || ('color ' + colorIndex)) : 'default';
  return { colorIndex: colorIndex != null ? colorIndex : null, hex, name };
}

// ---------- block/INSERT expansion ----------
function cadTransformPt(pt, ins) {
  const sx = ins.xScale != null ? ins.xScale : 1;
  const sy = ins.yScale != null ? ins.yScale : 1;
  let x = pt.x * sx, y = pt.y * sy;
  const rot = ((ins.rotation || 0) * Math.PI) / 180;
  if (rot) {
    const rx = x * Math.cos(rot) - y * Math.sin(rot);
    const ry = x * Math.sin(rot) + y * Math.cos(rot);
    x = rx; y = ry;
  }
  return { x: x + ins.position.x, y: y + ins.position.y, z: pt.z || 0 };
}
function cadTransformEntity(e, ins) {
  const out = { ...e };
  if (e.vertices) out.vertices = e.vertices.map(v => cadTransformPt(v, ins));
  if (e.position) out.position = cadTransformPt(e.position, ins);
  if (e.center) out.center = cadTransformPt(e.center, ins);
  if (e.insertionPoint) out.insertionPoint = cadTransformPt(e.insertionPoint, ins);
  if (e.startPoint) out.startPoint = cadTransformPt(e.startPoint, ins);
  if (e.endPoint) out.endPoint = cadTransformPt(e.endPoint, ins);
  if (e.radius != null) out.radius = e.radius * Math.max(Math.abs(ins.xScale || 1), Math.abs(ins.yScale || 1));
  return out;
}
function cadExpandInserts(entities, blocks, depth) {
  depth = depth || 0;
  const out = [];
  const maxDepth = 6;
  for (const e of entities) {
    const block = e.type === 'INSERT' && e.name && depth < maxDepth ? blocks[e.name] : null;
    if (block && block.entities && block.entities.length) {
      const ins = { position: e.position || { x: 0, y: 0 }, xScale: e.xScale, yScale: e.yScale, rotation: e.rotation };
      const basePt = block.position || { x: 0, y: 0 };
      const local = block.entities.map(be => {
        const shifted = { ...be };
        const sub = v => ({ x: v.x - basePt.x, y: v.y - basePt.y, z: v.z || 0 });
        if (be.vertices) shifted.vertices = be.vertices.map(sub);
        if (be.position) shifted.position = sub(be.position);
        if (be.center) shifted.center = sub(be.center);
        if (be.insertionPoint) shifted.insertionPoint = sub(be.insertionPoint);
        if (be.startPoint) shifted.startPoint = sub(be.startPoint);
        if (be.endPoint) shifted.endPoint = sub(be.endPoint);
        if ((be.layer || '0') === '0' && e.layer) shifted.layer = e.layer;
        return shifted;
      });
      const transformed = local.map(be => cadTransformEntity(be, ins));
      out.push(...cadExpandInserts(transformed, blocks, depth + 1));
    } else {
      out.push(e);
    }
  }
  return out;
}

// ---------- room reconstruction from unclosed wall lines ----------
function cadBridgeWallGaps(segments, diag) {
  const snapTol = Math.max(diag * 0.0015, 1e-6);
  const key = pt => Math.round(pt.x / snapTol) + ',' + Math.round(pt.y / snapTol);
  const counts = {};
  for (const [a, b] of segments) {
    for (const pt of [a, b]) { const k = key(pt); (counts[k] = counts[k] || []).push(pt); }
  }
  const dangling = Object.values(counts).filter(list => list.length === 1).map(list => list[0]);
  const maxGap = diag * 0.25;
  const used = new Set();
  const bridges = [];
  for (let i = 0; i < dangling.length; i++) {
    if (used.has(i)) continue;
    let best = -1, bestDist = Infinity;
    for (let j = 0; j < dangling.length; j++) {
      if (i === j || used.has(j)) continue;
      const d = Math.hypot(dangling[i].x - dangling[j].x, dangling[i].y - dangling[j].y);
      if (d < bestDist) { bestDist = d; best = j; }
    }
    if (best >= 0 && bestDist > 0 && bestDist <= maxGap) {
      bridges.push([dangling[i], dangling[best]]);
      used.add(i); used.add(best);
    }
  }
  return bridges.length ? segments.concat(bridges) : segments;
}
function cadReconstructRoomsFromLines(segments) {
  if (segments.length < 4) return [];
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const [a, b] of segments) {
    if (a.x < minX) minX = a.x; if (b.x < minX) minX = b.x;
    if (a.x > maxX) maxX = a.x; if (b.x > maxX) maxX = b.x;
    if (a.y < minY) minY = a.y; if (b.y < minY) minY = b.y;
    if (a.y > maxY) maxY = a.y; if (b.y > maxY) maxY = b.y;
  }
  const w = maxX - minX, h = maxY - minY;
  if (!(w > 0) || !(h > 0)) return [];
  segments = cadBridgeWallGaps(segments, Math.hypot(w, h));
  const targetCells = 240;
  const cell = Math.max(w, h) / targetCells;
  if (!(cell > 0)) return [];
  const pad = 2;
  const gw = Math.ceil(w / cell) + pad * 2;
  const gh = Math.ceil(h / cell) + pad * 2;
  if (gw * gh > 500000 || gw < 3 || gh < 3) return [];
  const originX = minX - pad * cell, originY = minY - pad * cell;
  const idx = (x, y) => y * gw + x;
  const wallMask = new Uint8Array(gw * gh);
  const toG = (x, y) => [(x - originX) / cell, (y - originY) / cell];
  for (const [a, b] of segments) {
    const [x0, y0] = toG(a.x, a.y), [x1, y1] = toG(b.x, b.y);
    const steps = Math.ceil(Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0))) * 2 + 1;
    for (let s = 0; s <= steps; s++) {
      const t = s / steps;
      const px = Math.round(x0 + (x1 - x0) * t), py = Math.round(y0 + (y1 - y0) * t);
      for (const [dx, dy] of [[0, 0], [1, 0], [-1, 0], [0, 1], [0, -1]]) {
        const gx = px + dx, gy = py + dy;
        if (gx >= 0 && gx < gw && gy >= 0 && gy < gh) wallMask[idx(gx, gy)] = 1;
      }
    }
  }
  const label = new Int32Array(gw * gh);
  const stack = [];
  const seedExterior = (x, y) => { const i = idx(x, y); if (!wallMask[i] && label[i] === 0) { label[i] = -1; stack.push([x, y]); } };
  for (let x = 0; x < gw; x++) { seedExterior(x, 0); seedExterior(x, gh - 1); }
  for (let y = 0; y < gh; y++) { seedExterior(0, y); seedExterior(gw - 1, y); }
  while (stack.length) {
    const [x, y] = stack.pop();
    for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
      const nx = x + dx, ny = y + dy;
      if (nx < 0 || nx >= gw || ny < 0 || ny >= gh) continue;
      const i = idx(nx, ny);
      if (wallMask[i] || label[i] !== 0) continue;
      label[i] = -1; stack.push([nx, ny]);
    }
  }
  let nextRegion = 1;
  const regions = {};
  for (let y = 0; y < gh; y++) for (let x = 0; x < gw; x++) {
    const i0 = idx(x, y);
    if (wallMask[i0] || label[i0] !== 0) continue;
    const id = nextRegion++;
    const cells = [];
    const q = [[x, y]]; label[i0] = id;
    while (q.length) {
      const [cx, cy] = q.pop(); cells.push([cx, cy]);
      for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
        const nx = cx + dx, ny = cy + dy;
        if (nx < 0 || nx >= gw || ny < 0 || ny >= gh) continue;
        const i = idx(nx, ny);
        if (wallMask[i] || label[i] !== 0) continue;
        label[i] = id; q.push([nx, ny]);
      }
    }
    regions[id] = cells;
  }
  const regionList = Object.values(regions);
  if (!regionList.length || regionList.length > 12) return [];
  const results = [];
  for (const cells of regionList) {
    if (cells.length < 4) continue;
    const inSet = new Set(cells.map(([x, y]) => x + ',' + y));
    const has = (x, y) => inSet.has(x + ',' + y);
    const DIRS = ['N', 'E', 'S', 'W'];
    const DELTA = { N: [0, -1], E: [1, 0], S: [0, 1], W: [-1, 0] };
    const REV = { N: 'S', E: 'W', S: 'N', W: 'E' };
    const outgoing = new Map();
    const addDir = (x, y, dir) => {
      const key = x + ',' + y;
      if (!outgoing.has(key)) outgoing.set(key, []);
      outgoing.get(key).push(dir);
    };
    for (const [cx, cy] of cells) {
      if (!has(cx, cy - 1)) addDir(cx, cy, 'E');
      if (!has(cx + 1, cy)) addDir(cx + 1, cy, 'S');
      if (!has(cx, cy + 1)) addDir(cx + 1, cy + 1, 'W');
      if (!has(cx - 1, cy)) addDir(cx, cy + 1, 'N');
    }
    const usedEdges = new Set();
    let bestLoop = null, bestLoopArea = 0;
    for (const [startKey, dirs] of outgoing) {
      for (const startDir of dirs) {
        const startToken = startKey + '>' + startDir;
        if (usedEdges.has(startToken)) continue;
        const loop = [];
        let curKey = startKey, curDir = startDir, guard = 0;
        while (guard++ < 100000) {
          const token = curKey + '>' + curDir;
          if (usedEdges.has(token)) break;
          usedEdges.add(token);
          const [cx, cy] = curKey.split(',').map(Number);
          loop.push([cx, cy]);
          const [dx, dy] = DELTA[curDir];
          const nextKey = (cx + dx) + ',' + (cy + dy);
          const candidates = outgoing.get(nextKey) || [];
          const revIdx = DIRS.indexOf(REV[curDir]);
          let picked = null;
          for (let k = 1; k <= 4; k++) {
            const cand = DIRS[(revIdx + k) % 4];
            if (candidates.includes(cand) && !usedEdges.has(nextKey + '>' + cand)) { picked = cand; break; }
          }
          if (!picked) break;
          curKey = nextKey; curDir = picked;
          if (curKey === startKey && curDir === startDir) break;
        }
        if (loop.length < 4) continue;
        let a = 0;
        for (let i = 0; i < loop.length; i++) { const p = loop[i], q = loop[(i + 1) % loop.length]; a += p[0] * q[1] - q[0] * p[1]; }
        a = Math.abs(a) / 2;
        if (a > bestLoopArea) { bestLoop = loop; bestLoopArea = a; }
      }
    }
    if (!bestLoop) continue;
    const simplified = [];
    for (let i = 0; i < bestLoop.length; i++) {
      const prev = bestLoop[(i - 1 + bestLoop.length) % bestLoop.length];
      const cur = bestLoop[i];
      const next = bestLoop[(i + 1) % bestLoop.length];
      const d1x = cur[0] - prev[0], d1y = cur[1] - prev[1];
      const d2x = next[0] - cur[0], d2y = next[1] - cur[1];
      if (d1x * d2y - d1y * d2x !== 0) simplified.push(cur);
    }
    const verts = (simplified.length >= 4 ? simplified : bestLoop).map(([gx, gy]) => ({ x: originX + gx * cell, y: originY + gy * cell }));
    let shoelace = 0;
    for (let i = 0; i < verts.length; i++) { const p = verts[i], q = verts[(i + 1) % verts.length]; shoelace += p.x * q.y - q.x * p.y; }
    if (Math.abs(shoelace) <= 0) continue;
    results.push(verts);
  }
  return results;
}

// ---------- drawing preview geometry ----------
function cadBuildPreviewGeometry(entities, layerTable) {
  const out = [];
  for (const e of entities) {
    const col = cadResolveColor(e, layerTable);
    if (['LINE', 'LWPOLYLINE', 'POLYLINE'].includes(e.type) && e.vertices && e.vertices.length >= 2) {
      out.push({ t: 'poly', pts: e.vertices.map(v => [cadRound2(v.x), cadRound2(v.y)]), closed: !!e.shape, color: col.hex });
    } else if (e.type === 'CIRCLE' && e.center && e.radius) {
      out.push({ t: 'circle', x: cadRound2(e.center.x), y: cadRound2(e.center.y), r: cadRound2(e.radius), color: col.hex });
    } else if ((e.type === 'INSERT' || e.type === 'POINT') && cadEntityPos(e)) {
      const p = cadEntityPos(e);
      out.push({ t: 'point', x: cadRound2(p.x), y: cadRound2(p.y), color: col.hex });
    } else if (CAD_TEXT_TYPES.includes(e.type)) {
      const p = cadEntityPos(e);
      const text = cadCleanMText(e.text);
      if (p && text) out.push({ t: 'text', x: cadRound2(p.x), y: cadRound2(p.y), s: text, h: Number(e.height) || 0 });
    }
  }
  return out;
}
function cadRound2(n) { return Math.round(n * 100) / 100; }
function cadGeometryBounds(geo) {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  const consider = (x, y) => { if (x < minX) minX = x; if (x > maxX) maxX = x; if (y < minY) minY = y; if (y > maxY) maxY = y; };
  const polys = geo.filter(g => g.t === 'poly');
  const circles = geo.filter(g => g.t === 'circle');
  const source = polys.length ? polys : (circles.length ? circles : geo.filter(g => g.t !== 'text'));
  for (const g of source.length ? source : geo) {
    if (g.t === 'poly') g.pts.forEach(([x, y]) => consider(x, y));
    else if (g.t === 'circle') { consider(g.x - g.r, g.y - g.r); consider(g.x + g.r, g.y + g.r); }
    else consider(g.x, g.y);
  }
  if (!isFinite(minX)) return null;
  return { minX, minY, maxX, maxY };
}

// ---------- symbol/legend-key detection ----------
const CAD_TEXT_TYPES = ['TEXT', 'MTEXT'];
function cadCleanMText(s) {
  return String(s || '')
    .replace(/\\P/gi, ' ')
    .replace(/\\[A-Za-z][^;]*;/g, '')
    .replace(/[{}]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}
const CAD_SYMBOL_TYPES = ['CIRCLE', 'INSERT', 'POINT', 'LINE', 'LWPOLYLINE', 'POLYLINE'];
function cadEntityPos(e) {
  if (e.startPoint) return e.startPoint;
  if (e.position) return e.position;
  if (e.center) return e.center;
  if (e.insertionPoint) return e.insertionPoint;
  if (e.vertices && e.vertices.length) {
    const vs = e.vertices;
    return { x: vs.reduce((s, v) => s + v.x, 0) / vs.length, y: vs.reduce((s, v) => s + v.y, 0) / vs.length };
  }
  return null;
}
function cadEntitySignature(e, layerTable) {
  const col = cadResolveColor(e, layerTable);
  const layer = e.layer || '0';
  if (e.type === 'INSERT' && e.name) return 'LAYER:' + layer + '|BLOCK:' + e.name + '|COLOR:' + col.colorIndex;
  return 'LAYER:' + layer + '|COLOR:' + col.colorIndex;
}
function cadEntityLabel(e, layerTable) {
  const col = cadResolveColor(e, layerTable);
  const colorTag = col.colorIndex != null ? ' (' + col.name + ')' : '';
  if (e.type === 'INSERT' && e.name) return 'Block "' + e.name + '"' + colorTag + ' on ' + (e.layer || '0');
  if (e.type === 'CIRCLE') return 'Circle' + colorTag + ' on ' + (e.layer || '0');
  if (e.type === 'POINT') return 'Point' + colorTag + ' on ' + (e.layer || '0');
  if (['LINE', 'LWPOLYLINE', 'POLYLINE'].includes(e.type)) return (e.shape ? 'Shape' : 'Line') + colorTag + ' on ' + (e.layer || '0');
  return e.type + colorTag + ' on ' + (e.layer || '0');
}
function cadBboxDiagonal(e) {
  const verts = e.vertices;
  if (!verts || verts.length < 2) return 0;
  const xs = verts.map(v => v.x), ys = verts.map(v => v.y);
  return Math.hypot(Math.max(...xs) - Math.min(...xs), Math.max(...ys) - Math.min(...ys));
}
function cadDetectLegendKey(entities, layerTable) {
  const texts = entities.filter(e => CAD_TEXT_TYPES.includes(e.type)).map(e => ({ p: cadEntityPos(e), text: cadCleanMText(e.text), height: Number(e.height) || 0 })).filter(t => t.p && t.text);
  const symbols = entities.filter(e => CAD_SYMBOL_TYPES.includes(e.type)).map(e => ({ e, p: cadEntityPos(e), size: cadBboxDiagonal(e) })).filter(s => s.p);
  if (!texts.length || !symbols.length) return {};
  const ys = texts.map(t => t.p.y).sort((a, b) => a - b);
  const gaps = [];
  for (let i = 1; i < ys.length; i++) { const g = ys[i] - ys[i - 1]; if (g > 0.01) gaps.push(g); }
  gaps.sort((a, b) => a - b);
  let typicalGap = gaps.length ? gaps[Math.floor(gaps.length / 2)] : Infinity;
  if (!isFinite(typicalGap)) typicalGap = texts[0].height * 2 || 50;
  const pairs = [];
  const used = new Set();
  for (const t of texts) {
    const maxDy = Math.max(typicalGap * 0.4, t.height * 0.6, 5);
    const maxDx = Math.max(typicalGap * 8, t.height * 12, 200);
    const maxSize = Math.max(t.height * 15, 150);
    let best = null, bestDist = Infinity;
    for (let i = 0; i < symbols.length; i++) {
      if (used.has(i)) continue;
      const s = symbols[i];
      if (s.size > maxSize) continue;
      const dx = t.p.x - s.p.x, dy = Math.abs(t.p.y - s.p.y);
      if (dx < -maxDx * 0.2 || dx > maxDx || dy > maxDy) continue;
      const d = Math.hypot(dx, dy);
      if (d < bestDist) { bestDist = d; best = { idx: i, s }; }
    }
    if (best) { used.add(best.idx); pairs.push({ text: t.text, symbol: best.s.e }); }
  }
  const bySig = {};
  const keyEntities = new Set();
  for (const p of pairs) {
    const sig = cadEntitySignature(p.symbol, layerTable);
    if (!bySig[sig]) bySig[sig] = { signature: sig, label: p.text };
    keyEntities.add(p.symbol);
  }
  return { bySig, keyEntities };
}
function cadGroupBySignature(entities, layerTable, keyEntities) {
  const groups = {};
  for (const e of entities) {
    if (!CAD_SYMBOL_TYPES.includes(e.type)) continue;
    if (keyEntities && keyEntities.has(e)) continue;
    const sig = cadEntitySignature(e, layerTable);
    if (!groups[sig]) {
      const col = cadResolveColor(e, layerTable);
      groups[sig] = { signature: sig, types: new Set(), layer: e.layer || '0', blockName: e.type === 'INSERT' ? e.name : null, description: cadEntityLabel(e, layerTable), colorName: col.name, colorHex: col.hex, count: 0, length: 0, area: 0 };
    }
    groups[sig].types.add(e.type);
    groups[sig].count++;
    if (['LINE', 'LWPOLYLINE', 'POLYLINE'].includes(e.type)) {
      groups[sig].length += cadEntityLength(e);
      groups[sig].area += cadPolygonArea(e);
    }
  }
  for (const g of Object.values(groups)) {
    const typeList = [...g.types];
    g.type = typeList.length === 1 ? typeList[0] : typeList.join('+');
    if (typeList.length > 1) g.description += ' (mixed geometry: ' + typeList.join(', ') + ')';
    delete g.types;
  }
  return groups;
}

// ---------- room / floor-area detection ----------
function cadPointInPolygon(pt, verts) {
  let inside = false;
  for (let i = 0, j = verts.length - 1; i < verts.length; j = i++) {
    const xi = verts[i].x, yi = verts[i].y, xj = verts[j].x, yj = verts[j].y;
    if (((yi > pt.y) !== (yj > pt.y)) && (pt.x < (xj - xi) * (pt.y - yi) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}
const CAD_TOILET_WORDS = /\b(TOILET|BATH|BATHROOM|WC|WASHROOM|LAVATORY|POWDER|ENSUITE|EN-SUITE|SHOWER)\b/i;
function cadBboxOf(verts) {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const v of verts) {
    if (v.x < minX) minX = v.x; if (v.x > maxX) maxX = v.x;
    if (v.y < minY) minY = v.y; if (v.y > maxY) maxY = v.y;
  }
  return { minX, minY, maxX, maxY };
}
function cadEstimateRoomArea(verts) {
  const box = cadBboxOf(verts);
  const grossArea = (box.maxX - box.minX) * (box.maxY - box.minY);
  const round = n => Math.round(n * 100) / 100;
  const xs = [...new Set(verts.map(v => round(v.x)))].sort((a, b) => a - b);
  const ys = [...new Set(verts.map(v => round(v.y)))].sort((a, b) => a - b);
  if (xs.length < 3 || ys.length < 3) return { area: grossArea, grossArea, netArea: null, innerBox: null };
  const innerMinX = xs[1], innerMaxX = xs[xs.length - 2];
  const innerMinY = ys[1], innerMaxY = ys[ys.length - 2];
  const tXmin = innerMinX - box.minX, tXmax = box.maxX - innerMaxX;
  const tYmin = innerMinY - box.minY, tYmax = box.maxY - innerMaxY;
  const thicknesses = [tXmin, tXmax, tYmin, tYmax];
  if (thicknesses.some(t => t <= 0)) return { area: grossArea, grossArea, netArea: null, innerBox: null };
  const maxT = Math.max(...thicknesses), minT = Math.min(...thicknesses);
  if (maxT > minT * 3) return { area: grossArea, grossArea, netArea: null, innerBox: null };
  const netW = innerMaxX - innerMinX, netH = innerMaxY - innerMinY;
  if (netW <= 0 || netH <= 0) return { area: grossArea, grossArea, netArea: null, innerBox: null };
  const netArea = netW * netH;
  const innerBox = { minX: innerMinX, maxX: innerMaxX, minY: innerMinY, maxY: innerMaxY };
  return { area: netArea, grossArea, netArea, innerBox };
}
function cadRectPolygon(box) {
  return [{ x: box.minX, y: box.minY }, { x: box.maxX, y: box.minY }, { x: box.maxX, y: box.maxY }, { x: box.minX, y: box.maxY }];
}
function cadShoelaceArea(verts) {
  let a = 0;
  for (let i = 0; i < verts.length; i++) {
    const p = verts[i], q = verts[(i + 1) % verts.length];
    a += p.x * q.y - q.x * p.y;
  }
  return Math.abs(a) / 2;
}
function cadFindSubRoomBounds(outerBox, partitionEntities, label) {
  const box = { ...outerBox };
  const farFace = { minX: null, maxX: null, minY: null, maxY: null };
  const minWallSpan = Math.max(outerBox.maxX - outerBox.minX, outerBox.maxY - outerBox.minY) * 0.1;
  let constrained = false, changed = true, iterations = 0;
  while (changed && iterations < 6) {
    changed = false; iterations++;
    for (const pe of partitionEntities) {
      const b = cadBboxOf(pe.vertices);
      const w = b.maxX - b.minX, h = b.maxY - b.minY;
      if (Math.max(w, h) < minWallSpan) continue;
      if (h > w) {
        const pad = h * 0.2;
        if (b.maxY < box.minY - pad || b.minY > box.maxY + pad) continue;
        if (label.x > b.maxX && b.maxX > box.minX) { box.minX = b.maxX; farFace.minX = b.minX; changed = true; constrained = true; }
        else if (label.x < b.minX && b.minX < box.maxX) { box.maxX = b.minX; farFace.maxX = b.maxX; changed = true; constrained = true; }
      } else {
        const pad = w * 0.2;
        if (b.maxX < box.minX - pad || b.minX > box.maxX + pad) continue;
        if (label.y > b.maxY && b.maxY > box.minY) { box.minY = b.maxY; farFace.minY = b.minY; changed = true; constrained = true; }
        else if (label.y < b.minY && b.minY < box.maxY) { box.maxY = b.minY; farFace.maxY = b.maxY; changed = true; constrained = true; }
      }
    }
  }
  if (!constrained || !(box.maxX > box.minX) || !(box.maxY > box.minY)) return null;
  return { box, farFace };
}
function cadSubtractCornerRect(outer, sub) {
  const L = Math.abs(sub.minX - outer.minX) < 1e-6, R = Math.abs(sub.maxX - outer.maxX) < 1e-6;
  const B = Math.abs(sub.minY - outer.minY) < 1e-6, T = Math.abs(sub.maxY - outer.maxY) < 1e-6;
  if (L && R && !(B && T)) {
    return T
      ? [{ x: outer.minX, y: outer.minY }, { x: outer.maxX, y: outer.minY }, { x: outer.maxX, y: sub.minY }, { x: outer.minX, y: sub.minY }]
      : [{ x: outer.minX, y: sub.maxY }, { x: outer.maxX, y: sub.maxY }, { x: outer.maxX, y: outer.maxY }, { x: outer.minX, y: outer.maxY }];
  }
  if (B && T && !(L && R)) {
    return R
      ? [{ x: outer.minX, y: outer.minY }, { x: sub.minX, y: outer.minY }, { x: sub.minX, y: outer.maxY }, { x: outer.minX, y: outer.maxY }]
      : [{ x: sub.maxX, y: outer.minY }, { x: outer.maxX, y: outer.minY }, { x: outer.maxX, y: outer.maxY }, { x: sub.maxX, y: outer.maxY }];
  }
  if (T && R && !L && !B) return [{ x: outer.minX, y: outer.minY }, { x: outer.maxX, y: outer.minY }, { x: outer.maxX, y: sub.minY }, { x: sub.minX, y: sub.minY }, { x: sub.minX, y: outer.maxY }, { x: outer.minX, y: outer.maxY }];
  if (T && L && !R && !B) return [{ x: outer.minX, y: outer.minY }, { x: outer.maxX, y: outer.minY }, { x: outer.maxX, y: outer.maxY }, { x: sub.maxX, y: outer.maxY }, { x: sub.maxX, y: sub.minY }, { x: outer.minX, y: sub.minY }];
  if (B && R && !L && !T) return [{ x: outer.minX, y: outer.minY }, { x: sub.minX, y: outer.minY }, { x: sub.minX, y: sub.maxY }, { x: outer.maxX, y: sub.maxY }, { x: outer.maxX, y: outer.maxY }, { x: outer.minX, y: outer.maxY }];
  if (B && L && !R && !T) return [{ x: sub.maxX, y: outer.minY }, { x: outer.maxX, y: outer.minY }, { x: outer.maxX, y: outer.maxY }, { x: outer.minX, y: outer.maxY }, { x: outer.minX, y: sub.maxY }, { x: sub.maxX, y: sub.maxY }];
  return null;
}
function cadComputeWallOpenings(vertices, layer, wallLikeEntities, roomBox) {
  const margin = Math.max(roomBox.maxX - roomBox.minX, roomBox.maxY - roomBox.minY) * 0.05;
  const candidates = wallLikeEntities.filter(e => {
    if (e.layer !== layer) return false;
    const b = cadBboxOf(e.vertices);
    return b.minX <= roomBox.maxX + margin && b.maxX >= roomBox.minX - margin && b.minY <= roomBox.maxY + margin && b.maxY >= roomBox.minY - margin;
  });
  const segments = [];
  for (const e of candidates) {
    for (let i = 1; i < e.vertices.length; i++) segments.push([e.vertices[i - 1], e.vertices[i]]);
    if (e.shape && e.vertices.length > 2) segments.push([e.vertices[e.vertices.length - 1], e.vertices[0]]);
  }
  let perimeter = 0, openings = 0;
  for (let i = 0; i < vertices.length; i++) {
    const a = vertices[i], b = vertices[(i + 1) % vertices.length];
    const edgeLen = Math.hypot(b.x - a.x, b.y - a.y);
    if (edgeLen <= 0) continue;
    perimeter += edgeLen;
    const horizontal = Math.abs(a.y - b.y) < Math.abs(a.x - b.x);
    const lo = horizontal ? Math.min(a.x, b.x) : Math.min(a.y, b.y);
    const hi = horizontal ? Math.max(a.x, b.x) : Math.max(a.y, b.y);
    const fixed = horizontal ? (a.y + b.y) / 2 : (a.x + b.x) / 2;
    const covered = [];
    for (const [p, q] of segments) {
      const segHoriz = Math.abs(p.y - q.y) < Math.abs(p.x - q.x);
      if (segHoriz !== horizontal) continue;
      const segFixed = segHoriz ? (p.y + q.y) / 2 : (p.x + q.x) / 2;
      if (Math.abs(segFixed - fixed) > margin) continue;
      const segLo = segHoriz ? Math.min(p.x, q.x) : Math.min(p.y, q.y);
      const segHi = segHoriz ? Math.max(p.x, q.x) : Math.max(p.y, q.y);
      const from = Math.max(lo, segLo), to = Math.min(hi, segHi);
      if (to > from) covered.push([from, to]);
    }
    covered.sort((x, y) => x[0] - y[0]);
    let coveredLen = 0, cursor = lo;
    for (const [from, to] of covered) {
      if (to <= cursor) continue;
      const start = Math.max(from, cursor);
      if (to > start) { coveredLen += to - start; cursor = to; }
    }
    openings += Math.max(0, edgeLen - coveredLen);
  }
  return { perimeter, openingsLength: openings, netWallLength: Math.max(0, perimeter - openings) };
}
function cadDetectRooms(entities, keyEntities, labelEntities) {
  const textSource = labelEntities || entities;
  const texts = textSource.filter(e => CAD_TEXT_TYPES.includes(e.type)).map(e => ({ p: cadEntityPos(e), text: cadCleanMText(e.text) })).filter(t => t.p && t.text);
  const polys = entities.filter(e =>
    ['LWPOLYLINE', 'POLYLINE'].includes(e.type) && e.shape && e.vertices && e.vertices.length >= 3 && !(keyEntities && keyEntities.has(e))
  );
  const wallLikeEntities = entities.filter(e =>
    ['LINE', 'LWPOLYLINE', 'POLYLINE'].includes(e.type) && e.vertices && e.vertices.length >= 2
  );
  const WALL_LAYER_HINT = /\b(WALL|WALLS|PARTITION|BOUNDARY)\b/i;
  const NON_WALL_LAYER_HINT = /\b(DOOR|WINDOW|JOINERY|FURNITURE|FIXTURE|SANITARY|ELECTRICAL|PLUMBING|FURN|MEP)\b/i;
  const realPolyLayers = new Set(polys.map(p => p.layer || '0'));
  const wallLayerGroups = {};
  for (const e of wallLikeEntities) { const l = e.layer || '0'; (wallLayerGroups[l] = wallLayerGroups[l] || []).push(e); }
  const syntheticPolys = [];
  for (const [layer, ents] of Object.entries(wallLayerGroups)) {
    if (realPolyLayers.has(layer) || ents.length < 6) continue;
    if (!WALL_LAYER_HINT.test(layer) || NON_WALL_LAYER_HINT.test(layer)) continue;
    const segments = [];
    for (const e of ents) {
      for (let i = 1; i < e.vertices.length; i++) segments.push([e.vertices[i - 1], e.vertices[i]]);
      if (e.shape && e.vertices.length > 2) segments.push([e.vertices[e.vertices.length - 1], e.vertices[0]]);
    }
    for (const verts of cadReconstructRoomsFromLines(segments)) {
      syntheticPolys.push({ type: 'LWPOLYLINE', shape: true, layer, vertices: verts, synthetic: true });
    }
  }
  const allPolys = polys.concat(syntheticPolys);
  const maxRealPolyArea = polys.reduce((m, p) => Math.max(m, cadPolygonArea(p)), 0);
  const candidates = [];
  for (const poly of allPolys) {
    const rawArea = poly.synthetic
      ? Math.abs((() => { let a = 0; const v = poly.vertices; for (let i = 0; i < v.length; i++) { const p = v[i], q = v[(i + 1) % v.length]; a += p.x * q.y - q.x * p.y; } return a; })()) / 2
      : cadPolygonArea(poly);
    if (rawArea <= 0) continue;
    const box = cadBboxOf(poly.vertices);
    const inside = texts.filter(t =>
      cadPointInPolygon(t.p, poly.vertices) ||
      (t.p.x >= box.minX && t.p.x <= box.maxX && t.p.y >= box.minY && t.p.y <= box.maxY)
    );
    const { area, grossArea, netArea, innerBox } = poly.synthetic
      ? { area: rawArea, grossArea: rawArea, netArea: rawArea, innerBox: null }
      : cadEstimateRoomArea(poly.vertices);
    const label = inside.length ? inside.map(t => t.text).join(' / ') : null;
    let multi = null;
    if (!poly.synthetic && inside.length === 0 && rawArea >= maxRealPolyArea * 0.15
      && WALL_LAYER_HINT.test(poly.layer || '0') && !NON_WALL_LAYER_HINT.test(poly.layer || '0')) {
      const margin = Math.max(box.maxX - box.minX, box.maxY - box.minY) * 0.02;
      const innerPartitions = wallLikeEntities.filter(e => {
        if (e === poly || e.layer !== poly.layer) return false;
        const b = cadBboxOf(e.vertices);
        return b.minX >= box.minX - margin && b.maxX <= box.maxX + margin && b.minY >= box.minY - margin && b.maxY <= box.maxY + margin;
      });
      if (innerPartitions.length) {
        const segments = [];
        for (let i = 0; i < poly.vertices.length; i++) segments.push([poly.vertices[i], poly.vertices[(i + 1) % poly.vertices.length]]);
        for (const e of innerPartitions) {
          for (let i = 1; i < e.vertices.length; i++) segments.push([e.vertices[i - 1], e.vertices[i]]);
          if (e.shape && e.vertices.length > 2) segments.push([e.vertices[e.vertices.length - 1], e.vertices[0]]);
        }
        const regions = cadReconstructRoomsFromLines(segments);
        if (regions.length >= 2) multi = regions;
      }
    }
    let split = null;
    if (!poly.synthetic && !multi && inside.length === 1 && innerBox) {
      const margin = Math.max(box.maxX - box.minX, box.maxY - box.minY) * 0.02;
      const partitionEntities = wallLikeEntities.filter(e => {
        if (e === poly || e.layer !== poly.layer) return false;
        const b = cadBboxOf(e.vertices);
        return b.minX >= box.minX - margin && b.maxX <= box.maxX + margin && b.minY >= box.minY - margin && b.maxY <= box.maxY + margin;
      });
      if (partitionEntities.length) {
        const result = cadFindSubRoomBounds(innerBox, partitionEntities, inside[0].p);
        if (result) {
          const { box: subBox, farFace } = result;
          const notchBox = {
            minX: farFace.minX != null ? farFace.minX : subBox.minX,
            maxX: farFace.maxX != null ? farFace.maxX : subBox.maxX,
            minY: farFace.minY != null ? farFace.minY : subBox.minY,
            maxY: farFace.maxY != null ? farFace.maxY : subBox.maxY,
          };
          const leftoverPoly = cadSubtractCornerRect(innerBox, notchBox);
          if (leftoverPoly) {
            split = {
              sub: { area: (subBox.maxX - subBox.minX) * (subBox.maxY - subBox.minY), vertices: cadRectPolygon(subBox), label: inside[0].text },
              leftover: { area: cadShoelaceArea(leftoverPoly), vertices: leftoverPoly },
            };
          }
        }
      }
    }
    candidates.push({ poly, area, grossArea, netArea, innerBox, label, hasLabel: !!inside.length, split, multi });
  }
  const maxGross = candidates.reduce((m, c) => Math.max(m, c.grossArea || 0), 0);
  const sizeThreshold = maxGross * 0.15;
  const rooms = [];
  const roomEntities = new Set();
  let idx = 0, unnamedIdx = 0;
  for (const c of candidates) {
    if (c.split) {
      idx++;
      roomEntities.add(c.poly);
      const subLabel = c.split.sub.label;
      const subType = CAD_TOILET_WORDS.test(subLabel) ? 'TOILET' : 'ROOM';
      rooms.push({
        signature: 'ROOM:' + subType + ':' + subLabel.toUpperCase().replace(/[^A-Z0-9]+/g, '_') + ':' + idx,
        label: subLabel, type: subType, layer: c.poly.layer || '0', area: c.split.sub.area, grossArea: c.split.sub.area, netArea: c.split.sub.area, autoLabel: false,
        vertices: c.split.sub.vertices,
      });
      unnamedIdx++;
      const leftoverLabel = 'Area ' + unnamedIdx;
      rooms.push({
        signature: 'ROOM:ROOM:' + leftoverLabel.toUpperCase().replace(/[^A-Z0-9]+/g, '_') + ':' + idx,
        label: leftoverLabel, type: 'ROOM', layer: c.poly.layer || '0', area: c.split.leftover.area, grossArea: c.split.leftover.area, netArea: c.split.leftover.area, autoLabel: true,
        vertices: c.split.leftover.vertices,
      });
      continue;
    }
    if (c.multi) {
      idx++;
      roomEntities.add(c.poly);
      for (const verts of c.multi) {
        let shoelace = 0;
        for (let i = 0; i < verts.length; i++) { const p = verts[i], q = verts[(i + 1) % verts.length]; shoelace += p.x * q.y - q.x * p.y; }
        const regionArea = Math.abs(shoelace) / 2;
        unnamedIdx++;
        const label = 'Area ' + unnamedIdx;
        rooms.push({
          signature: 'ROOM:ROOM:' + label.toUpperCase().replace(/[^A-Z0-9]+/g, '_') + ':' + idx + ':' + unnamedIdx,
          label, type: 'ROOM', layer: c.poly.layer || '0', area: regionArea, grossArea: regionArea, netArea: regionArea, autoLabel: true,
          vertices: verts,
        });
      }
      continue;
    }
    if (!c.poly.synthetic && !c.hasLabel && c.grossArea < sizeThreshold) continue;
    idx++;
    roomEntities.add(c.poly);
    let label = c.label, type;
    if (c.hasLabel) {
      type = CAD_TOILET_WORDS.test(label) ? 'TOILET' : 'ROOM';
    } else {
      unnamedIdx++;
      label = 'Area ' + unnamedIdx;
      type = 'ROOM';
    }
    rooms.push({
      signature: 'ROOM:' + type + ':' + label.toUpperCase().replace(/[^A-Z0-9]+/g, '_') + ':' + idx,
      label, type, layer: c.poly.layer || '0', area: c.area, grossArea: c.grossArea, netArea: c.netArea, autoLabel: !c.hasLabel,
      vertices: c.innerBox ? cadRectPolygon(c.innerBox) : c.poly.vertices.map(v => ({ x: v.x, y: v.y })),
    });
  }
  for (const room of rooms) {
    Object.assign(room, cadComputeWallOpenings(room.vertices, room.layer, wallLikeEntities, cadBboxOf(room.vertices)));
  }
  return { rooms, roomEntities };
}

// ---------- materials ----------
function cadMaterialFields(b) {
  b = b || {};
  return {
    name: b.name && String(b.name).trim(),
    unit: (b.unit && String(b.unit).trim()) || 'Nos',
    length_mm: b.length_mm !== undefined && b.length_mm !== '' ? Number(b.length_mm) : null,
    width_mm: b.width_mm !== undefined && b.width_mm !== '' ? Number(b.width_mm) : null,
    height_mm: b.height_mm !== undefined && b.height_mm !== '' ? Number(b.height_mm) : null,
    thickness_mm: b.thickness_mm !== undefined && b.thickness_mm !== '' ? Number(b.thickness_mm) : null,
    coverage_m2: b.coverage_m2 !== undefined && b.coverage_m2 !== '' ? Number(b.coverage_m2) : null,
    waste_pct: b.waste_pct !== undefined && b.waste_pct !== '' ? Number(b.waste_pct) : 10,
    price: b.price !== undefined && b.price !== '' ? Number(b.price) : null,
    // optional link to a master-list item, so this material's price is pulled live from the
    // items table instead of relying on the manually-typed `price` above. Purely additive: a
    // material with no item_id keeps behaving exactly as before (uses its own stored price).
    item_id: b.item_id !== undefined && b.item_id !== '' && b.item_id != null ? Number(b.item_id) : null,
  };
}

// an ingredient row is either linked to a master-list item (item_id set, live price used) or a
// plain manually-typed entry (custom_name/custom_price) for anything not on the master list yet.
async function cadSaveIngredients(materialId, ingredients) {
  for (const ing of (Array.isArray(ingredients) ? ingredients : [])) {
    const hasItem = !!ing.item_id;
    const customName = (ing.custom_name || '').trim();
    if (!hasItem && !customName) continue; // skip empty rows (no item picked and no manual name typed)
    await db.run('INSERT INTO cad_material_ingredients (material_id, item_id, qty_per_unit, price_override, custom_name, custom_price) VALUES (?,?,?,?,?,?)', [
      materialId,
      hasItem ? Number(ing.item_id) : null,
      Number(ing.qty_per_unit) || 0,
      ing.price_override !== '' && ing.price_override != null ? Number(ing.price_override) : null,
      hasItem ? null : customName,
      (!hasItem && ing.custom_price !== '' && ing.custom_price != null) ? Number(ing.custom_price) : null,
    ]);
  }
}
app.get('/api/cad/materials', auth, wrap(async (req, res) => {
  const materials = await db.all(`SELECT m.*, i.name AS item_name, i.unit AS item_unit, i.price AS item_price
    FROM cad_materials m LEFT JOIN items i ON i.id = m.item_id AND i.active = 1 ORDER BY m.name`);
  for (const m of materials) {
    // flag when a material is linked to a master item that's been removed/deactivated since linking
    m.itemLinkBroken = !!(m.item_id && !m.item_name);
    const rows = await db.all('SELECT mi.*, i.name AS item_name, i.unit AS item_unit, i.price AS item_price FROM cad_material_ingredients mi LEFT JOIN items i ON i.id = mi.item_id AND i.active = 1 WHERE mi.material_id = ?', [m.id]);
    m.ingredients = rows.map(r => ({
      ...r,
      itemLinkBroken: !!(r.item_id && !r.item_name), // was linked, item since removed/deactivated
      isCustom: !r.item_id, // manually-typed, not on the master list
      // unify display fields regardless of which mode this row is
      item_name: r.item_id ? r.item_name : r.custom_name,
      item_unit: r.item_id ? r.item_unit : null,
      item_price: r.item_id ? r.item_price : r.custom_price,
    }));
  }
  res.json(materials);
}));
app.post('/api/cad/materials', auth, materialManager, wrap(async (req, res) => {
  const f = cadMaterialFields(req.body);
  if (!f.name) return res.status(400).json({ error: 'Material name required' });
  const info = await db.run(
    'INSERT INTO cad_materials (name, unit, length_mm, width_mm, height_mm, thickness_mm, coverage_m2, waste_pct, price, item_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
    [f.name, f.unit, f.length_mm, f.width_mm, f.height_mm, f.thickness_mm, f.coverage_m2, f.waste_pct, f.price, f.item_id]
  );
  const matId = info.lastInsertRowid;
  await cadSaveIngredients(matId, req.body.ingredients);
  res.json({ ok: true, id: matId });
}));
app.put('/api/cad/materials/:id', auth, materialManager, wrap(async (req, res) => {
  const f = cadMaterialFields(req.body);
  if (!f.name) return res.status(400).json({ error: 'Material name required' });
  await db.run(
    'UPDATE cad_materials SET name=?, unit=?, length_mm=?, width_mm=?, height_mm=?, thickness_mm=?, coverage_m2=?, waste_pct=?, price=?, item_id=? WHERE id=?',
    [f.name, f.unit, f.length_mm, f.width_mm, f.height_mm, f.thickness_mm, f.coverage_m2, f.waste_pct, f.price, f.item_id, req.params.id]
  );
  await db.run('DELETE FROM cad_material_ingredients WHERE material_id = ?', [req.params.id]);
  await cadSaveIngredients(req.params.id, req.body.ingredients);
  res.json({ ok: true });
}));
app.delete('/api/cad/materials/:id', auth, materialManager, wrap(async (req, res) => {
  await db.run('DELETE FROM cad_materials WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
}));

// remembered signature -> material mapping, so re-analyzing a similar drawing pre-fills whichever
// material was picked for that exact symbol/room last time. Any logged-in user can save these
// (matches the old cad_settings behavior — not an admin-only action).
app.get('/api/cad/symbol-names', auth, wrap(async (req, res) => res.json(await db.all('SELECT * FROM cad_symbol_names'))));
app.put('/api/cad/symbol-names', auth, wrap(async (req, res) => {
  const { map } = req.body || {};
  for (const [sig, v] of Object.entries(map || {})) {
    const materialId = v && typeof v === 'object' ? v.materialId : v;
    await db.run(
      'INSERT INTO cad_symbol_names (signature, material_id) VALUES (?,?) ON CONFLICT(signature) DO UPDATE SET material_id = excluded.material_id',
      [sig, materialId || null]
    );
  }
  res.json({ ok: true });
}));

// ---------- parse ----------
// Turn an IFC read into the same response shape the takeoff page consumes.
// IFC quantities are already in metres/m², so areas are converted up to the
// mm-based numbers the rest of the pipeline expects (unit is reported as mm).
async function buildIfcResponse(ifc) {
  const allMaterials = await db.all('SELECT * FROM cad_materials');
  const savedNames = await db.all('SELECT * FROM cad_symbol_names');
  const savedMap = {}; savedNames.forEach(r => { savedMap[r.signature] = r.material_id; });
  const M2_TO_MM2 = 1e6, M_TO_MM = 1e3;

  const matchMaterial = (sig, label) => {
    if (savedMap[sig]) return savedMap[sig];
    const m = allMaterials.find(x => cadNameMatch(label, x.name));
    return m ? m.id : null;
  };

  const items = [];

  ifc.rooms.forEach((r, i) => {
    if (r.area == null) return; // no quantity, nothing trustworthy to report
    const sig = `IFC:SPACE:${(r.label || 'space').toUpperCase().replace(/[^A-Z0-9]+/g, '_')}:${i + 1}`;
    const area = r.area * M2_TO_MM2;
    items.push({
      kind: 'ROOM', roomType: /toilet|wc|bath|rest\s*room/i.test(r.label || '') ? 'TOILET' : 'ROOM',
      signature: sig, type: 'ROOM', layer: 'IFC', blockName: null,
      description: `Room — "${r.label}" (from IFC)`,
      colorName: null, colorHex: null,
      detectedLabel: r.label, autoLabel: false, count: 0, length: 0,
      area, grossArea: area, netArea: area,
      vertices: null,
      materialId: matchMaterial(sig, r.label),
    });
  });

  // Walls are reported in aggregate: IFC wall quantities are exact, so there's
  // no need for the perimeter-minus-openings estimation used on DXF drawings.
  const walled = ifc.walls.filter(w => w.area != null || w.length != null);
  if (walled.length) {
    const totalArea = walled.reduce((s, w) => s + (w.area || 0), 0);
    const totalLen = walled.reduce((s, w) => s + (w.length || 0), 0);
    const sig = 'IFC:WALLS:ALL';
    items.push({
      kind: 'WALL', roomType: 'ROOM', signature: sig, type: 'WALL', layer: 'IFC', blockName: null,
      description: `Walls — ${walled.length} from IFC`,
      colorName: null, colorHex: null, detectedLabel: 'Walls (IFC)',
      count: 0, length: 0, area: 0,
      perimeter: Number((totalLen * M_TO_MM).toFixed(2)),
      openingsLength: 0,
      netWallLength: Number((totalLen * M_TO_MM).toFixed(2)),
      heightM: totalLen > 0 ? Number((totalArea / totalLen).toFixed(3)) : 2.7,
      materialId: matchMaterial(sig, 'wall'),
    });
  }

  // Doors and windows are real counted objects in IFC
  for (const [label, n] of [['Doors', ifc.counts.doors], ['Windows', ifc.counts.windows]]) {
    if (!n) continue;
    const sig = `IFC:${label.toUpperCase()}`;
    items.push({
      kind: 'SYMBOL', signature: sig, type: label.toUpperCase(), layer: 'IFC', blockName: null,
      description: `${label} — counted from IFC`,
      colorName: null, colorHex: null, detectedLabel: label, labelSource: 'ifc',
      count: n, length: 0, area: 0,
      materialId: matchMaterial(sig, label),
    });
  }

  return {
    items,
    detectedUnit: 'mm',
    legendKeyCount: 0,
    roomCount: items.filter(i => i.kind === 'ROOM').length,
    preview: { geometry: [], rooms: [] }, // IFC geometry is 3D; no 2D preview yet
    source: 'IFC',
    ifc: { schema: ifc.schema, counts: ifc.counts, quality: ifc.quality, notes: ifc.notes },
  };
}

app.post('/api/cad/parse', auth, uploadOne('file'), wrap(async (req, res) => {
  if (!req.file) throw new UserError('No file was uploaded.', 'Choose a drawing file, then press Analyze Drawing.');
  const buf = req.file.buffer;
  const name = req.file.originalname || 'the file';
  const ext = (name.match(/\.[^.]+$/) || [''])[0].toLowerCase();
  const sizeKb = Math.round(buf.length / 1024);
  // tiny files round to "0 KB", which reads like a bug — show bytes instead
  const sizeText = buf.length < 1024 ? `${buf.length} bytes` : `${sizeKb} KB`;

  if (!buf.length) {
    throw new UserError(`"${name}" is empty (0 bytes).`, 'The file may not have finished saving or copying. Re-save it from your CAD software and try again.');
  }

  const format = detectFormat(name, buf);

  // Binary DXF is a real format but dxf-parser only reads the ASCII flavour,
  // and it's an easy mistake to make since both use the .dxf extension.
  if (buf.slice(0, 22).toString('latin1').includes('AutoCAD Binary DXF')) {
    throw new UserError(
      `"${name}" is a binary DXF, which cannot be read.`,
      'In AutoCAD choose Save As → "AutoCAD DXF (*.dxf)" and make sure the format is ASCII, not binary. Alternatively just upload the DWG directly — the app reads DWG now.'
    );
  }

  if (format === FORMATS.PDF) {
    throw new UserError(
      'PDF drawings cannot be analysed automatically.',
      'A PDF has no drawing units or room data, so quantities cannot be read from it reliably. Use the "Measure a PDF instead" button to set a scale and measure it by hand.'
    );
  }

  if (format === FORMATS.UNKNOWN) {
    throw new UserError(
      `"${name}" is not a drawing file the app recognises.`,
      `It was checked by both its contents and its extension (${ext || "no extension"}, ${sizeText}) and matched none of DXF, DWG or IFC. Supported: .dxf (ASCII), .dwg, .ifc. If this is a ZIP or RAR, extract it first.`
    );
  }

  // Warn when the extension lies about the contents — the file is still read
  // correctly (detection is content-first), but it's worth telling the user.
  const extFormat = { '.dxf': FORMATS.DXF, '.dwg': FORMATS.DWG, '.ifc': FORMATS.IFC }[ext];
  const mismatch = extFormat && extFormat !== format
    ? `Note: "${name}" is named ${ext} but its contents are ${format}. It was read as ${format}.`
    : null;

  // IFC is a different kind of file: it carries real building objects, so it
  // gets its own reader rather than being forced through the line-work engine.
  if (format === FORMATS.IFC) {
    if (buf.slice(0, 2).toString('latin1') === 'PK') {
      throw new UserError(
        `"${name}" is a compressed IFC (ifcZIP), which cannot be read directly.`,
        'Unzip it first and upload the plain .ifc file inside.'
      );
    }
    let ifc;
    try { ifc = await parseIfc(buf); }
    catch (e) {
      throw new UserError(
        `"${name}" could not be read as IFC.`,
        `The reader stopped with: ${e.message}. The file may be truncated or use a schema the reader doesn't support (IFC2X3 and IFC4 are supported). Size read: ${sizeText}.`
      );
    }
    const out = await buildIfcResponse(ifc);
    if (mismatch) out.warning = mismatch;
    return res.json(out);
  }

  let dxf;
  try { dxf = await parseToDxfShape(format, buf); }
  catch (e) {
    throw new UserError(
      `"${name}" could not be read as ${format}.`,
      format === FORMATS.DWG
        ? `The DWG reader stopped with: ${e.message}. Very old (pre-R13) or very new DWG versions, and password-protected files, cannot be read. Try re-saving as "AutoCAD 2018 DWG" or exporting to DXF (ASCII). Size read: ${sizeText}.`
        : `The DXF reader stopped with: ${e.message}. Make sure it was exported as DXF (ASCII) rather than binary, and that the export completed. Size read: ${sizeText}.`
    );
  }

  const entities = dxf.entities || [];
  if (!entities.length) {
    throw new UserError(
      `"${name}" was read successfully but contains no drawing entities.`,
      'The file opened cleanly but there is nothing in model space to measure. This usually means the drawing is empty, everything sits in a paper-space layout only, or the export excluded the geometry.'
    );
  }
  req._cadWarning = mismatch;
  const layerTable = (dxf.tables && dxf.tables.layer && dxf.tables.layer.layers) || {};
  const expandedEntities = cadExpandInserts(entities, dxf.blocks || {});
  const { bySig: legendKey, keyEntities } = cadDetectLegendKey(entities, layerTable);
  const { rooms, roomEntities } = cadDetectRooms(expandedEntities, keyEntities, entities);
  const excludeFromGeneric = new Set([...keyEntities, ...roomEntities]);
  const groups = cadGroupBySignature(entities, layerTable, excludeFromGeneric);
  const allMaterials = await db.all('SELECT * FROM cad_materials');
  const savedNames = await db.all('SELECT * FROM cad_symbol_names');
  const savedMaterialMap = {}; savedNames.forEach(r => { savedMaterialMap[r.signature] = r.material_id; });

  const items = Object.values(groups).map(g => {
    const blockLabel = g.blockName && isReadableBlockName(g.blockName) ? g.blockName : null;
    const legendLabel = legendKey[g.signature] ? legendKey[g.signature].label : null;
    const detectedLabel = legendLabel || blockLabel;
    let materialId = savedMaterialMap[g.signature] || null;
    if (!materialId) {
      const guessSource = detectedLabel || g.layer;
      const match = allMaterials.find(m => cadNameMatch(guessSource, m.name));
      materialId = match ? match.id : null;
    }
    return {
      kind: 'SYMBOL',
      signature: g.signature, type: g.type, layer: g.layer, blockName: g.blockName, description: g.description,
      colorName: g.colorName, colorHex: g.colorHex,
      detectedLabel, labelSource: legendLabel ? 'legend' : (blockLabel ? 'block' : null),
      count: g.count, length: Number(g.length.toFixed(2)), area: Number(g.area.toFixed(2)),
      materialId,
    };
  }).sort((a, b) => (b.detectedLabel ? 1 : 0) - (a.detectedLabel ? 1 : 0) || b.count - a.count);

  const roomItems = rooms.map(r => {
    let materialId = savedMaterialMap[r.signature] || null;
    if (!materialId) {
      const match = allMaterials.find(m => cadNameMatch(r.label, m.name));
      materialId = match ? match.id : null;
    }
    return {
      kind: 'ROOM', roomType: r.type,
      signature: r.signature, type: 'ROOM', layer: r.layer, blockName: null,
      description: `${r.type === 'TOILET' ? 'Toilet' : 'Room'} — "${r.label}"`,
      colorName: null, colorHex: null,
      detectedLabel: r.label, autoLabel: !!r.autoLabel, count: 0, length: 0,
      area: Number(r.area.toFixed(2)),
      grossArea: r.grossArea != null ? Number(r.grossArea.toFixed(2)) : null,
      netArea: r.netArea != null ? Number(r.netArea.toFixed(2)) : null,
      vertices: r.vertices,
      materialId,
    };
  }).sort((a, b) => a.roomType === b.roomType ? a.detectedLabel.localeCompare(b.detectedLabel) : (a.roomType === 'ROOM' ? -1 : 1));

  const wallItems = rooms.map(r => {
    let materialId = savedMaterialMap['WALL:' + r.signature] || null;
    if (!materialId) {
      const match = allMaterials.find(m => cadNameMatch(r.label, m.name) || /\bWALL\b/i.test(m.name));
      materialId = match ? match.id : null;
    }
    return {
      kind: 'WALL', roomType: r.type,
      signature: 'WALL:' + r.signature, type: 'WALL', layer: r.layer, blockName: null,
      description: `Wall — "${r.label}"`,
      colorName: null, colorHex: null,
      detectedLabel: r.label, count: 0, length: 0, area: 0,
      perimeter: Number(r.perimeter.toFixed(2)),
      openingsLength: Number(r.openingsLength.toFixed(2)),
      netWallLength: Number(r.netWallLength.toFixed(2)),
      heightM: 2.7,
      materialId,
    };
  });

  const previewGeometry = cadBuildPreviewGeometry(expandedEntities, layerTable);
  const previewBounds = cadGeometryBounds(previewGeometry);
  const detectedUnit = cadDetectUnit(dxf);
  const warnings = [];
  if (req._cadWarning) warnings.push(req._cadWarning);
  if (!detectedUnit) warnings.push('This drawing does not record its units, so millimetres have been assumed. Check the unit selector below and change it if the drawing was made in metres, feet or inches.');
  if (!rooms.length) warnings.push('No rooms were detected. Rooms are found from closed outlines and nearby labels, so drawings where rooms are only implied by wall lines may find none. You can still measure symbols and lengths, or add areas manually in the preview.');

  res.json({
    items: [...roomItems, ...wallItems, ...items], detectedUnit, legendKeyCount: Object.keys(legendKey).length, roomCount: rooms.length,
    preview: { geometry: previewGeometry, bounds: previewBounds },
    warnings: warnings.length ? warnings : undefined,
    stats: { format, entities: entities.length, layers: Object.keys(layerTable).length, blocks: Object.keys(dxf.blocks || {}).length, sizeKb },
  });
}));

// ---------- calculate ----------
app.post('/api/cad/calculate', auth, wrap(async (req, res) => {
  const b = req.body || {};
  const factor = CAD_UNIT_FACTORS[b.drawingUnit] || 0.001;
  const heights = b.heights && typeof b.heights === 'object' ? b.heights : {};

  const agg = {};
  for (const it of (Array.isArray(b.items) ? b.items : [])) {
    if (!it.materialId) continue;
    const g = agg[it.materialId] || (agg[it.materialId] = { length: 0, area: 0, count: 0 });
    g.length += (Number(it.length) || 0) * factor;
    g.area += (Number(it.area) || 0) * factor * factor;
    g.count += Number(it.count) || 0;
  }
  const materialIds = Object.keys(agg).map(Number);
  if (!materialIds.length) return res.json({ groups: [] });
  const materials = await db.all(`SELECT m.*, i.name AS item_name, i.price AS item_price FROM cad_materials m
    LEFT JOIN items i ON i.id = m.item_id AND i.active = 1 WHERE m.id IN (${materialIds.map(() => '?').join(',')})`, materialIds);

  const groups = [];
  for (const mat of materials) {
    const raw = agg[mat.id];
    const wastePct = Number(mat.waste_pct) || 0;
    const waste = 1 + wastePct / 100;

    let basisQty, basisUnit, note;
    const height = Number(heights[mat.id]) || (Number(mat.height_mm) || 0) / 1000;
    if (height > 0 && raw.length > 0) {
      basisQty = raw.length * height; basisUnit = 'm²';
      note = `${raw.length.toFixed(2)}m run x ${height}m height`;
    } else if (raw.area > 0) {
      basisQty = raw.area; basisUnit = 'm²'; note = `${raw.area.toFixed(2)}m² raw area`;
    } else if (raw.length > 0) {
      basisQty = raw.length; basisUnit = 'm'; note = `${raw.length.toFixed(2)}m raw length`;
    } else {
      basisQty = raw.count; basisUnit = 'Nos'; note = `${raw.count} counted`;
    }
    let qty, unit = mat.unit || basisUnit;
    const pieceArea = mat.coverage_m2 || ((mat.length_mm && mat.width_mm) ? (mat.length_mm / 1000) * (mat.width_mm / 1000) : null);
    if (pieceArea && (basisUnit === 'm²')) {
      qty = Math.ceil((basisQty / pieceArea) * waste);
      note += `, ${pieceArea.toFixed(3)}m² coverage per ${unit}` + (mat.thickness_mm ? ` at ${mat.thickness_mm}mm` : '') + `, +${wastePct}% waste`;
    } else {
      if (mat.thickness_mm && basisUnit === 'm²') {
        basisQty = basisQty * (Number(mat.thickness_mm) / 1000); basisUnit = 'm³';
        note += `, x ${mat.thickness_mm}mm thickness`;
      }
      qty = unit === 'Nos' ? Math.ceil(basisQty * waste) : Number((basisQty * waste).toFixed(3));
      note += `, +${wastePct}% waste`;
    }
    if (qty <= 0) continue;

    const rows = await db.all('SELECT mi.*, i.name AS item_name, i.unit AS item_unit, i.price AS item_price FROM cad_material_ingredients mi LEFT JOIN items i ON i.id = mi.item_id AND i.active = 1 WHERE mi.material_id = ?', [mat.id]);
    const ingredients = rows.map(r => {
      const name = r.item_id ? r.item_name : r.custom_name;
      const basePrice = r.item_id ? r.item_price : r.custom_price;
      return { item: name, unit: r.item_id ? r.item_unit : null, price: r.price_override != null ? r.price_override : basePrice, note: r.note, qty: Number((r.qty_per_unit * qty).toFixed(2)) };
    });

    // prefer the live master-list price when this material is linked to an item; fall back to
    // the material's own stored price if unlinked, or if the linked item was since deleted.
    const price = (mat.item_id && mat.item_price != null) ? mat.item_price : mat.price;
    groups.push({ materialId: mat.id, material: mat.name, qty: Number(qty.toFixed(2)), unit, price, priceSource: (mat.item_id && mat.item_price != null) ? 'masterList' : (mat.item_id ? 'brokenLink' : 'manual'), note, ingredients });
  }
  res.json({ groups });
}));

// scan the whole list for likely duplicate groups (admin tool)
app.get('/api/items/duplicates', auth, itemManager, wrap(async (req, res) => {
  const items = await db.all('SELECT id, name, unit, price FROM items WHERE active = 1 ORDER BY id');
  const groups = [];
  const used = new Set();
  for (let i = 0; i < items.length; i++) {
    if (used.has(i)) continue;
    const a = itemNorm(items[i].name), wa = itemWords(items[i].name), waSet = new Set(wa);
    const grp = [items[i]];
    for (let j = i + 1; j < items.length; j++) {
      if (used.has(j)) continue;
      const b = itemNorm(items[j].name);
      let match = a === b;
      if (!match && wa.length) {
        const wb = itemWords(items[j].name), wbSet = new Set(wb);
        // same number of significant tokens required, so a differing size/dimension token (e.g. 2" vs 3") can never be "missing" from the comparison
        if (wa.length === wb.length && wa.length >= 2) {
          const hits = wa.filter(w => wbSet.has(w)).length; // exact token match, not substring
          match = hits / wa.length >= 0.85;
        }
      }
      if (match) { grp.push(items[j]); used.add(j); }
    }
    if (grp.length > 1) { groups.push(grp); used.add(i); }
  }
  res.json(groups);
}));

// bulk add from spreadsheet (admin): body { items: [{name, unit, price}] }
app.post('/api/items/bulk', auth, itemManager, wrap(async (req, res) => {
  const list = Array.isArray(req.body?.items) ? req.body.items : [];
  if (!list.length) return res.status(400).json({ error: 'No rows found' });
  if (list.length > 2000) return res.status(400).json({ error: 'Too many rows (max 2000)' });
  const existing = await db.all('SELECT name FROM items WHERE active = 1');
  const have = new Set(existing.map(e => e.name.toLowerCase().trim()));
  let added = 0; const skipped = [], invalid = [];
  for (const r of list) {
    const name = String(r.name || '').trim();
    const price = Number(r.price);
    if (!name || isNaN(price)) { if (name) invalid.push(name); continue; }
    if (have.has(name.toLowerCase())) { skipped.push(name); continue; }
    await db.run('INSERT INTO items (name, unit, price) VALUES (?, ?, ?)', [name, String(r.unit || 'Nos').trim() || 'Nos', price]);
    have.add(name.toLowerCase()); added++;
  }
  await audit(req.user, 'ITEM_BULK', 'Bulk upload: ' + added + ' added, ' + skipped.length + ' skipped (already exist), ' + invalid.length + ' invalid');
  res.json({ ok: true, added, skipped, invalid });
}));

app.post('/api/items', auth, itemManager, wrap(async (req, res) => {
  const { name, unit, price, force } = req.body || {};
  if (!name || price === undefined || isNaN(price)) return res.status(400).json({ error: 'Name and valid price required' });
  if (!force) {
    const dupes = await similarItems(name.trim());
    if (dupes.length) return res.status(409).json({ duplicates: dupes, message: 'Possible duplicate items found. Confirm to add anyway.' });
  }
  const info = await db.run('INSERT INTO items (name, unit, price) VALUES (?, ?, ?)', [name.trim(), unit || 'Nos', Number(price)]);
  await audit(req.user, 'ITEM_ADD', name.trim() + ' @ ' + Number(price) + (force ? ' (forced past duplicate warning)' : ''));
  res.json({ ok: true, id: info.lastInsertRowid });
}));

app.put('/api/items/:id', auth, itemManager, wrap(async (req, res) => {
  const { name, unit, price } = req.body || {};
  const before = await db.get('SELECT name, unit, price FROM items WHERE id = ?', [req.params.id]);
  await db.run('UPDATE items SET name = COALESCE(?, name), unit = COALESCE(?, unit), price = COALESCE(?, price) WHERE id = ?',
    [name ?? null, unit ?? null, price !== undefined ? Number(price) : null, req.params.id]);
  const after = await db.get('SELECT name, unit, price FROM items WHERE id = ?', [req.params.id]);
  if (before && after) await audit(req.user, 'ITEM_EDIT',
    before.name + ' [' + before.unit + ', ' + before.price + '] -> ' + after.name + ' [' + after.unit + ', ' + after.price + ']');
  res.json({ ok: true });
}));

app.delete('/api/items/:id', auth, itemManager, wrap(async (req, res) => {
  const it = await db.get('SELECT name, price FROM items WHERE id = ?', [req.params.id]);
  await db.run('UPDATE items SET active = 0 WHERE id = ?', [req.params.id]);
  if (it) await audit(req.user, 'ITEM_DELETE', it.name + ' @ ' + it.price);
  res.json({ ok: true });
}));

const DEPTS_OK = d => DEPARTMENTS.includes(d);
// SERVICE = work requested by other departments (maintenance / renovation)
// PR      = purchase requests
// CAD     = produced by the CAD Quantify module (kept in its own tab)
const QUANT_TYPES = ['SERVICE', 'PR', 'CAD'];
const normalizeType = t => QUANT_TYPES.includes(t) ? t : 'SERVICE';

const canEdit = (user, q) => user.role === 'ADMIN' || Number(q.created_by) === user.id;

async function loadQuant(id) {
  const q = await db.get('SELECT q.*, u.name AS creator_name, u.email AS creator_email, u.signature AS creator_signature FROM quantifications q JOIN users u ON u.id = q.created_by WHERE q.id = ?', [id]);
  if (!q) return null;
  q.lines = await db.all('SELECT * FROM quantification_lines WHERE quantification_id = ? ORDER BY position', [id]);
  return q;
}

app.get('/api/quantifications', auth, wrap(async (req, res) => {
  const dept = req.query.department;
  const source = req.query.source;
  const createdBy = req.query.created_by;
  const base = 'SELECT q.id, q.title, q.department, q.created_at, q.updated_at, q.created_by, q.source, u.name AS creator_name, (SELECT ROUND(SUM(qty*rate),2) FROM quantification_lines l WHERE l.quantification_id = q.id) AS subtotal, q.gst_rate FROM quantifications q JOIN users u ON u.id = q.created_by';
  const conds = [], args = [];
  if (dept && DEPTS_OK(dept)) { conds.push('q.department = ?'); args.push(dept); }
  if (QUANT_TYPES.includes(source)) { conds.push('q.source = ?'); args.push(source); }
  if (createdBy) { conds.push('q.created_by = ?'); args.push(Number(createdBy)); }
  const where = conds.length ? ' WHERE ' + conds.join(' AND ') : '';
  const rows = await db.all(base + where + ' ORDER BY q.updated_at DESC', args);
  res.json(rows);
}));

// distinct creators, for the "filter by user" dropdown on the list screens
app.get('/api/quantifications/creators', auth, wrap(async (req, res) => {
  res.json(await db.all('SELECT DISTINCT u.id, u.name FROM quantifications q JOIN users u ON u.id = q.created_by ORDER BY u.name'));
}));

app.get('/api/quantifications/:id', auth, wrap(async (req, res) => {
  const q = await loadQuant(req.params.id);
  if (!q) return res.status(404).json({ error: 'Not found' });
  q.can_edit = canEdit(req.user, q);
  res.json(q);
}));

async function saveLines(qid, lines) {
  await db.run('DELETE FROM quantification_lines WHERE quantification_id = ?', [qid]);
  let pos = 0;
  for (const l of (lines || [])) {
    if (l.description && String(l.description).trim()) {
      await db.run('INSERT INTO quantification_lines (quantification_id, position, description, unit, qty, rate) VALUES (?,?,?,?,?,?)',
        [qid, pos++, String(l.description).trim(), l.unit || 'Nos', Number(l.qty) || 0, Number(l.rate) || 0]);
    }
  }
}

app.post('/api/quantifications', auth, wrap(async (req, res) => {
  const { title, department, gst_rate, lines, checked_by, checked_designation, approved_by, approved_designation, source } = req.body || {};
  if (!title || !DEPTS_OK(department)) return res.status(400).json({ error: 'Title and valid department required' });
  const info = await db.run('INSERT INTO quantifications (title, department, gst_rate, checked_by, checked_designation, approved_by, approved_designation, created_by, source) VALUES (?,?,?,?,?,?,?,?,?)',
    [title.trim(), department, gst_rate !== undefined ? Number(gst_rate) : 8, checked_by || '', checked_designation || '', approved_by || '', approved_designation || '', req.user.id, normalizeType(source)]);
  await saveLines(info.lastInsertRowid, lines);
  res.json({ ok: true, id: info.lastInsertRowid });
}));

app.put('/api/quantifications/:id', auth, wrap(async (req, res) => {
  const q = await db.get('SELECT * FROM quantifications WHERE id = ?', [req.params.id]);
  if (!q) return res.status(404).json({ error: 'Not found' });
  if (!canEdit(req.user, q)) return res.status(403).json({ error: 'Only the creator or an admin can edit this quantification' });
  const { title, department, gst_rate, lines, checked_by, checked_designation, approved_by, approved_designation } = req.body || {};
  if (department && !DEPTS_OK(department)) return res.status(400).json({ error: 'Invalid department' });
  await db.run("UPDATE quantifications SET title = COALESCE(?, title), department = COALESCE(?, department), gst_rate = COALESCE(?, gst_rate), checked_by = COALESCE(?, checked_by), checked_designation = COALESCE(?, checked_designation), approved_by = COALESCE(?, approved_by), approved_designation = COALESCE(?, approved_designation), updated_at = datetime('now') WHERE id = ?",
    [title ?? null, department ?? null, gst_rate !== undefined ? Number(gst_rate) : null,
     checked_by ?? null, checked_designation ?? null, approved_by ?? null, approved_designation ?? null, req.params.id]);
  if (lines) await saveLines(req.params.id, lines);
  res.json({ ok: true });
}));

app.delete('/api/quantifications/:id', auth, adminOnly, wrap(async (req, res) => {
  const q = await db.get('SELECT title FROM quantifications WHERE id = ?', [req.params.id]);
  await db.run('DELETE FROM quantification_lines WHERE quantification_id = ?', [req.params.id]);
  await db.run('DELETE FROM quantifications WHERE id = ?', [req.params.id]);
  if (q) await audit(req.user, 'QUANT_DELETE', q.title);
  res.json({ ok: true });
}));

app.get('/api/quantifications/:id/pdf', auth, wrap(async (req, res) => {
  const q = await loadQuant(req.params.id);
  if (!q) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/pdf');
  const safe = (q.title || 'Quantification').replace(/[^a-zA-Z0-9 _().-]+/g, '').trim().slice(0, 80) || 'Quantification';
  res.setHeader('Content-Disposition', 'attachment; filename="' + safe + '.pdf"');
  generatePdf(q, res);
}));

app.get('/api/admin/users', auth, adminOnly, wrap(async (req, res) => {
  res.json(await db.all('SELECT id, email, name, role, department, designation, status, created_at FROM users ORDER BY created_at DESC'));
}));

app.put('/api/admin/users/:id', auth, adminOnly, wrap(async (req, res) => {
  const { role, department, status, designation } = req.body || {};
  if (role && !ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (department && !DEPARTMENTS.includes(department)) return res.status(400).json({ error: 'Invalid department' });
  if (status && !['PENDING', 'ACTIVE', 'DISABLED'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  await db.run('UPDATE users SET role = COALESCE(?, role), department = COALESCE(?, department), status = COALESCE(?, status), designation = COALESCE(?, designation) WHERE id = ?',
    [role ?? null, department ?? null, status ?? null, designation ?? null, req.params.id]);
  const target = await db.get('SELECT email FROM users WHERE id = ?', [req.params.id]);
  await audit(req.user, 'USER_UPDATE', (target ? target.email : req.params.id) + ' -> ' + JSON.stringify({ role, department, status }));
  res.json({ ok: true });
}));

// Admin-initiated password reset. There's no mail service wired up, so instead of
// emailing a link we generate a one-off temporary password, hand it back to the
// admin exactly once, and force the user to pick a new one at their next login.
function tempPassword() {
  // avoid look-alike characters (0/O, 1/l/I) so it can be read out or written down
  const abc = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from(crypto.randomBytes(10)).map(b => abc[b % abc.length]).join('');
}

app.post('/api/admin/users/:id/reset-password', auth, adminOnly, wrap(async (req, res) => {
  const target = await db.get('SELECT id, email, name FROM users WHERE id = ?', [req.params.id]);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const pw = tempPassword();
  await db.run('UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?',
    [bcrypt.hashSync(pw, 10), req.params.id]);
  await audit(req.user, 'USER_PASSWORD_RESET', target.email);
  // returned once, never stored in plain text anywhere
  res.json({ ok: true, tempPassword: pw, name: target.name, email: target.email });
}));

app.delete('/api/admin/users/:id', auth, adminOnly, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account' });
  const target = await db.get('SELECT id, email, role, status FROM users WHERE id = ?', [id]);
  if (!target) return res.status(404).json({ error: 'User not found' });
  // Deleting someone who authored quantifications would orphan those records
  // (the list view joins on created_by), so refuse and suggest disabling instead.
  const owned = await db.get('SELECT COUNT(*) c FROM quantifications WHERE created_by = ?', [id]);
  if (Number(owned.c) > 0) {
    return res.status(400).json({
      error: `This user has ${owned.c} quantification(s) and cannot be deleted. Set their status to DISABLED instead — that blocks login while keeping their records intact.`
    });
  }
  // only guard against removing the final *active* admin — deleting an already
  // disabled admin doesn't reduce the number of people who can administer the app
  if (target.role === 'ADMIN' && target.status === 'ACTIVE') {
    const admins = await db.get("SELECT COUNT(*) c FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'");
    if (Number(admins.c) <= 1) return res.status(400).json({ error: 'Cannot delete the last active admin' });
  }
  await db.run('DELETE FROM users WHERE id = ?', [id]);
  await audit(req.user, 'USER_DELETE', target.email);
  res.json({ ok: true });
}));

app.get('/api/admin/audit', auth, adminOnly, wrap(async (req, res) => {
  res.json(await db.all('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300'));
}));

app.get('/api/departments', (req, res) => res.json(DEPARTMENTS));

db.init().then(() => {
  app.listen(PORT, () => console.log('QuantiFy running on http://localhost:' + PORT));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
