const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const DxfParser = require('dxf-parser');
const db = require('./db');
const { generatePdf } = require('./pdf');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

const app = express();
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;
const DEPARTMENTS = ['Technical Services', 'Maintenance Services', 'Infrastructure Services', 'Development Services'];

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, SECRET);
    const user = await db.get('SELECT id, email, name, role, department, designation, phone, dob, signature, status FROM users WHERE id = ?', [payload.id]);
    if (!user || user.status !== 'ACTIVE') return res.status(401).json({ error: 'Account not active' });
    req.user = user; req.user.id = Number(req.user.id);
    next();
  } catch { return res.status(401).json({ error: 'Invalid session' }); }
}
const adminOnly = (req, res, next) => req.user.role === 'ADMIN' ? next() : res.status(403).json({ error: 'Admin only' });

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
  res.json({ token, user: { id: Number(user.id), email: user.email, name: user.name, role: user.role, department: user.department, designation: user.designation, phone: user.phone, dob: user.dob, signature: user.signature } });
}));

app.get('/api/me', auth, (req, res) => res.json(req.user));

app.post('/api/me/password', auth, wrap(async (req, res) => {
  const { current, next: nextPw } = req.body || {};
  if (!nextPw || nextPw.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const u = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(current || '', u.password_hash)) return res.status(400).json({ error: 'Current password is incorrect' });
  await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(nextPw, 10), req.user.id]);
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

// ---------- CAD drawing takeoff ----------
const CAD_UNIT_FACTORS = { mm: 0.001, cm: 0.01, m: 1, ft: 0.3048, in: 0.0254 };
const CAD_MEASURE_TYPES = ['LENGTH', 'AREA', 'COUNT'];

function cadDist(a, b) { return Math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2); }
function cadEntityLength(e) {
  const verts = e.vertices || [];
  if (verts.length < 2) return 0;
  let len = 0;
  for (let i = 1; i < verts.length; i++) len += cadDist(verts[i - 1], verts[i]);
  if (e.shape) len += cadDist(verts[verts.length - 1], verts[0]); // closed polyline
  return len;
}
// shoelace formula; only meaningful for closed polylines
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
// fuzzy word-overlap match between a CAD layer name and a legend name
function cadNameMatch(layerName, legendName) {
  const norm = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]+/g, ' ').trim();
  const a = norm(layerName), b = norm(legendName);
  if (!a || !b) return false;
  if (a === b) return true;
  const wa = a.split(' ').filter(Boolean), wb = b.split(' ').filter(Boolean);
  if (!wa.length || !wb.length) return false;
  const hits = wb.filter(w => wa.includes(w)).length;
  return hits / wb.length >= 0.8;
}
function cadGuessLegend(layerName, legends) {
  for (const lg of legends) if (cadNameMatch(layerName, lg.name)) return lg.name;
  return null;
}

// legend library: types of items a drawing can be quantified for (Fire, Plumbing, Roofing, cabling, etc.)
app.get('/api/cad/legends', auth, wrap(async (req, res) => {
  res.json(await db.all('SELECT * FROM cad_legends ORDER BY name'));
}));
app.post('/api/cad/legends', auth, adminOnly, wrap(async (req, res) => {
  const { name, measure_type, output_unit, detail, waste_pct, coverage_len_mm, coverage_wid_mm, coverage_gap_mm, thickness_mm } = req.body || {};
  if (!name || !String(name).trim() || !CAD_MEASURE_TYPES.includes(measure_type)) return res.status(400).json({ error: 'Name and a valid measure type (Length/Area/Count) are required' });
  try {
    const info = await db.run(`INSERT INTO cad_legends (name, measure_type, output_unit, detail, waste_pct, coverage_len_mm, coverage_wid_mm, coverage_gap_mm, thickness_mm) VALUES (?,?,?,?,?,?,?,?,?)`,
      [String(name).trim(), measure_type, (output_unit && String(output_unit).trim()) || (measure_type === 'LENGTH' ? 'm' : measure_type === 'AREA' ? 'm²' : 'Nos'),
       detail || '', waste_pct !== undefined && waste_pct !== '' ? Number(waste_pct) : 5,
       coverage_len_mm ? Number(coverage_len_mm) : null, coverage_wid_mm ? Number(coverage_wid_mm) : null,
       coverage_gap_mm !== undefined && coverage_gap_mm !== '' ? Number(coverage_gap_mm) : null, thickness_mm ? Number(thickness_mm) : null]);
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(400).json({ error: 'A legend with this name already exists' });
    throw e;
  }
}));
app.put('/api/cad/legends/:id', auth, adminOnly, wrap(async (req, res) => {
  const { name, measure_type, output_unit, detail, waste_pct, coverage_len_mm, coverage_wid_mm, coverage_gap_mm, thickness_mm } = req.body || {};
  if (!name || !String(name).trim() || !CAD_MEASURE_TYPES.includes(measure_type)) return res.status(400).json({ error: 'Name and a valid measure type (Length/Area/Count) are required' });
  try {
    await db.run(`UPDATE cad_legends SET name=?, measure_type=?, output_unit=?, detail=?, waste_pct=?, coverage_len_mm=?, coverage_wid_mm=?, coverage_gap_mm=?, thickness_mm=? WHERE id=?`,
      [String(name).trim(), measure_type, (output_unit && String(output_unit).trim()) || 'Nos', detail || '', waste_pct !== undefined && waste_pct !== '' ? Number(waste_pct) : 5,
       coverage_len_mm ? Number(coverage_len_mm) : null, coverage_wid_mm ? Number(coverage_wid_mm) : null,
       coverage_gap_mm !== undefined && coverage_gap_mm !== '' ? Number(coverage_gap_mm) : null, thickness_mm ? Number(thickness_mm) : null, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(400).json({ error: 'A legend with this name already exists' });
    throw e;
  }
}));
app.delete('/api/cad/legends/:id', auth, adminOnly, wrap(async (req, res) => {
  await db.run('DELETE FROM cad_legends WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
}));

// upload + parse a DXF file, return detected layers (length/area/count) with a suggested legend match each.
// body field "legends" (JSON array of legend names the user tagged for this drawing) narrows auto-matching.
app.post('/api/cad/parse', auth, upload.single('file'), wrap(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  if (!/\.dxf$/i.test(req.file.originalname || '')) {
    return res.status(400).json({ error: 'Only DXF files are supported. In your CAD software, use "Save As" / "Export" and choose DXF (ASCII) format — DWG binary files cannot be read directly.' });
  }
  let dxf;
  try {
    dxf = new DxfParser().parseSync(req.file.buffer.toString('utf8'));
  } catch (e) {
    return res.status(400).json({ error: 'Could not read this file as DXF. Make sure it was exported/saved as DXF (ASCII), not a binary DWG.' });
  }
  const byLayer = {};
  for (const e of (dxf.entities || [])) {
    const ly = e.layer || '0';
    if (!byLayer[ly]) byLayer[ly] = { count: 0, length: 0, area: 0 };
    if (['LINE', 'LWPOLYLINE', 'POLYLINE'].includes(e.type)) {
      byLayer[ly].count++;
      byLayer[ly].length += cadEntityLength(e);
      byLayer[ly].area += cadPolygonArea(e);
    } else if (['INSERT', 'POINT', 'CIRCLE'].includes(e.type)) {
      byLayer[ly].count++;
    }
  }
  const allLegends = await db.all('SELECT * FROM cad_legends ORDER BY name');
  let requested = [];
  try { requested = req.body.legends ? JSON.parse(req.body.legends) : []; } catch { requested = []; }
  const scope = requested.length ? allLegends.filter(lg => requested.includes(lg.name)) : allLegends;
  const saved = await db.all('SELECT layer_name, category FROM cad_layers');
  const savedMap = {}; saved.forEach(r => { savedMap[r.layer_name.toUpperCase()] = r.category; });
  const layers = Object.keys(byLayer).map(name => {
    const savedLegend = savedMap[name.toUpperCase()];
    const legend = (savedLegend && scope.some(lg => lg.name === savedLegend)) ? savedLegend : cadGuessLegend(name, scope);
    return {
      name, count: byLayer[name].count, length: Number(byLayer[name].length.toFixed(2)), area: Number(byLayer[name].area.toFixed(2)),
      legend: legend || null,
    };
  }).sort((a, b) => b.length - a.length);
  if (!layers.length) return res.status(400).json({ error: 'No usable geometry found in this drawing.' });
  res.json({ layers, legends: scope });
}));

// saved defaults (e.g. drawing unit) + remembered layer-name -> legend mappings
app.get('/api/cad/settings', auth, wrap(async (req, res) => {
  const rows = await db.all('SELECT key, value FROM cad_settings');
  const settings = {}; rows.forEach(r => { try { settings[r.key] = JSON.parse(r.value); } catch { settings[r.key] = r.value; } });
  const layerMap = await db.all('SELECT layer_name, category AS legend FROM cad_layers ORDER BY layer_name');
  res.json({ settings, layerMap });
}));
app.put('/api/cad/settings', auth, wrap(async (req, res) => {
  const { settings, layerMap } = req.body || {};
  if (settings && typeof settings === 'object') {
    for (const [k, v] of Object.entries(settings)) {
      await db.run('INSERT INTO cad_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [k, JSON.stringify(v)]);
    }
  }
  if (Array.isArray(layerMap)) {
    for (const l of layerMap) {
      if (!l.name || !l.legend) continue;
      await db.run('INSERT INTO cad_layers (layer_name, category) VALUES (?, ?) ON CONFLICT(layer_name) DO UPDATE SET category = excluded.category',
        [String(l.name).trim(), String(l.legend).trim()]);
    }
  }
  res.json({ ok: true });
}));

// given per-layer legend assignments + raw length/area/count, compute a suggested quantity takeoff per legend
app.post('/api/cad/calculate', auth, wrap(async (req, res) => {
  const b = req.body || {};
  const factor = CAD_UNIT_FACTORS[b.drawingUnit] || 0.001;
  const agg = {}; // legend name -> raw {length(m), area(m2), count}
  for (const l of (Array.isArray(b.layers) ? b.layers : [])) {
    if (!l.legend || l.legend === 'IGNORE' || !String(l.legend).trim()) continue;
    const g = agg[l.legend] || (agg[l.legend] = { length: 0, area: 0, count: 0 });
    g.length += (Number(l.length) || 0) * factor;
    g.area += (Number(l.area) || 0) * factor * factor;
    g.count += Number(l.count) || 0;
  }
  const legendNames = Object.keys(agg);
  if (!legendNames.length) return res.json({ items: [] });
  const legendRows = await db.all(`SELECT * FROM cad_legends WHERE name IN (${legendNames.map(() => '?').join(',')})`, legendNames);
  const items = [];
  for (const lg of legendRows) {
    const raw = agg[lg.name];
    const wastePct = Number(lg.waste_pct) || 0;
    const waste = 1 + wastePct / 100;
    let qty, unit = lg.output_unit, detail;
    if (lg.measure_type === 'LENGTH') {
      qty = Number((raw.length * waste).toFixed(2));
      detail = `${raw.length.toFixed(2)}m raw length, +${wastePct}% waste/slack`;
    } else if (lg.measure_type === 'AREA') {
      const areaM2 = raw.area;
      if (lg.coverage_len_mm && lg.coverage_wid_mm) {
        const coverM2 = ((Number(lg.coverage_len_mm) + (Number(lg.coverage_gap_mm) || 0)) * (Number(lg.coverage_wid_mm) + (Number(lg.coverage_gap_mm) || 0))) / 1e6;
        qty = coverM2 > 0 ? Math.ceil((areaM2 / coverM2) * waste) : 0;
        detail = `${areaM2.toFixed(2)}m² ÷ ${coverM2.toFixed(4)}m² per unit, +${wastePct}% waste`;
      } else if (lg.thickness_mm) {
        const volM3 = areaM2 * (Number(lg.thickness_mm) / 1000);
        qty = Number((volM3 * waste).toFixed(3));
        detail = `${areaM2.toFixed(2)}m² x ${lg.thickness_mm}mm thickness = ${volM3.toFixed(3)}m³, +${wastePct}% waste`;
      } else {
        qty = Number((areaM2 * waste).toFixed(2));
        detail = `${areaM2.toFixed(2)}m² area, +${wastePct}% waste`;
      }
    } else { // COUNT
      qty = Math.ceil(raw.count * waste);
      detail = `${raw.count} counted, +${wastePct}% waste`;
    }
    if (qty > 0) {
      items.push({ label: lg.name, legend: lg.name, qty, unit, detail: detail + (lg.detail ? ' — ' + lg.detail : '') });
    }
  }
  for (const it of items) {
    const matches = await similarItems(it.legend);
    it.suggested = matches[0] || null;
  }
  res.json({ items });
}));

// scan the whole list for likely duplicate groups (admin tool)
app.get('/api/items/duplicates', auth, adminOnly, wrap(async (req, res) => {
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
app.post('/api/items/bulk', auth, adminOnly, wrap(async (req, res) => {
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

app.post('/api/items', auth, adminOnly, wrap(async (req, res) => {
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

app.put('/api/items/:id', auth, adminOnly, wrap(async (req, res) => {
  const { name, unit, price } = req.body || {};
  const before = await db.get('SELECT name, unit, price FROM items WHERE id = ?', [req.params.id]);
  await db.run('UPDATE items SET name = COALESCE(?, name), unit = COALESCE(?, unit), price = COALESCE(?, price) WHERE id = ?',
    [name ?? null, unit ?? null, price !== undefined ? Number(price) : null, req.params.id]);
  const after = await db.get('SELECT name, unit, price FROM items WHERE id = ?', [req.params.id]);
  if (before && after) await audit(req.user, 'ITEM_EDIT',
    before.name + ' [' + before.unit + ', ' + before.price + '] -> ' + after.name + ' [' + after.unit + ', ' + after.price + ']');
  res.json({ ok: true });
}));

app.delete('/api/items/:id', auth, adminOnly, wrap(async (req, res) => {
  const it = await db.get('SELECT name, price FROM items WHERE id = ?', [req.params.id]);
  await db.run('UPDATE items SET active = 0 WHERE id = ?', [req.params.id]);
  if (it) await audit(req.user, 'ITEM_DELETE', it.name + ' @ ' + it.price);
  res.json({ ok: true });
}));

const DEPTS_OK = d => DEPARTMENTS.includes(d);
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
  const base = 'SELECT q.id, q.title, q.department, q.created_at, q.updated_at, q.created_by, q.source, u.name AS creator_name, (SELECT ROUND(SUM(qty*rate),2) FROM quantification_lines l WHERE l.quantification_id = q.id) AS subtotal, q.gst_rate FROM quantifications q JOIN users u ON u.id = q.created_by';
  const conds = [], args = [];
  if (dept && DEPTS_OK(dept)) { conds.push('q.department = ?'); args.push(dept); }
  if (source === 'CAD' || source === 'MANUAL') { conds.push('q.source = ?'); args.push(source); }
  const where = conds.length ? ' WHERE ' + conds.join(' AND ') : '';
  const rows = await db.all(base + where + ' ORDER BY q.updated_at DESC', args);
  res.json(rows);
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
    [title.trim(), department, gst_rate !== undefined ? Number(gst_rate) : 8, checked_by || '', checked_designation || '', approved_by || '', approved_designation || '', req.user.id, source === 'CAD' ? 'CAD' : 'MANUAL']);
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
  if (role && !['ADMIN', 'USER'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (department && !DEPARTMENTS.includes(department)) return res.status(400).json({ error: 'Invalid department' });
  if (status && !['PENDING', 'ACTIVE', 'DISABLED'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  await db.run('UPDATE users SET role = COALESCE(?, role), department = COALESCE(?, department), status = COALESCE(?, status), designation = COALESCE(?, designation) WHERE id = ?',
    [role ?? null, department ?? null, status ?? null, designation ?? null, req.params.id]);
  const target = await db.get('SELECT email FROM users WHERE id = ?', [req.params.id]);
  await audit(req.user, 'USER_UPDATE', (target ? target.email : req.params.id) + ' -> ' + JSON.stringify({ role, department, status }));
  res.json({ ok: true });
}));

app.delete('/api/admin/users/:id', auth, adminOnly, wrap(async (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  await db.run('UPDATE users SET status = ? WHERE id = ?', ['DISABLED', req.params.id]);
  res.json({ ok: true });
}));

app.get('/api/admin/audit', auth, adminOnly, wrap(async (req, res) => {
  res.json(await db.all('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300'));
}));

app.get('/api/departments', (req, res) => res.json(DEPARTMENTS));

db.init().then(() => {
  app.listen(PORT, () => console.log('QuantiFy running on http://localhost:' + PORT));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
