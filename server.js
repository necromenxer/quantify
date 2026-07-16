const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./db');
const { generatePdf } = require('./pdf');

const app = express();
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;
const DEPARTMENTS = ['Technical Services', 'Maintenance Services', 'Infrastructure Services', 'Development Services'];

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, SECRET);
    const user = await db.get('SELECT id, email, name, role, department, status FROM users WHERE id = ?', [payload.id]);
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
  res.json({ token, user: { id: Number(user.id), email: user.email, name: user.name, role: user.role, department: user.department } });
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

async function similarItems(name) {
  const norm = name.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  const words = norm.split(' ').filter(w => w.length > 2);
  const allItems = await db.all('SELECT id, name, unit, price FROM items WHERE active = 1');
  return allItems.filter(i => {
    const inorm = i.name.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
    if (inorm === norm) return true;
    if (words.length === 0) return false;
    const hits = words.filter(w => inorm.includes(w)).length;
    return hits / words.length >= 0.75;
  }).slice(0, 8);
}

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
  const q = await db.get('SELECT q.*, u.name AS creator_name, u.email AS creator_email FROM quantifications q JOIN users u ON u.id = q.created_by WHERE q.id = ?', [id]);
  if (!q) return null;
  q.lines = await db.all('SELECT * FROM quantification_lines WHERE quantification_id = ? ORDER BY position', [id]);
  return q;
}

app.get('/api/quantifications', auth, wrap(async (req, res) => {
  const dept = req.query.department;
  const base = 'SELECT q.id, q.title, q.department, q.created_at, q.updated_at, q.created_by, u.name AS creator_name, (SELECT ROUND(SUM(qty*rate),2) FROM quantification_lines l WHERE l.quantification_id = q.id) AS subtotal, q.gst_rate FROM quantifications q JOIN users u ON u.id = q.created_by';
  const rows = dept && DEPTS_OK(dept)
    ? await db.all(base + ' WHERE q.department = ? ORDER BY q.updated_at DESC', [dept])
    : await db.all(base + ' ORDER BY q.updated_at DESC');
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
  const { title, department, gst_rate, lines, checked_by, checked_designation, approved_by, approved_designation } = req.body || {};
  if (!title || !DEPTS_OK(department)) return res.status(400).json({ error: 'Title and valid department required' });
  const info = await db.run('INSERT INTO quantifications (title, department, gst_rate, checked_by, checked_designation, approved_by, approved_designation, created_by) VALUES (?,?,?,?,?,?,?,?)',
    [title.trim(), department, gst_rate !== undefined ? Number(gst_rate) : 8, checked_by || '', checked_designation || '', approved_by || '', approved_designation || '', req.user.id]);
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
  res.setHeader('Content-Disposition', 'attachment; filename="Quantification-' + q.id + '.pdf"');
  generatePdf(q, res);
}));

app.get('/api/admin/users', auth, adminOnly, wrap(async (req, res) => {
  res.json(await db.all('SELECT id, email, name, role, department, status, created_at FROM users ORDER BY created_at DESC'));
}));

app.put('/api/admin/users/:id', auth, adminOnly, wrap(async (req, res) => {
  const { role, department, status } = req.body || {};
  if (role && !['ADMIN', 'USER'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (department && !DEPARTMENTS.includes(department)) return res.status(400).json({ error: 'Invalid department' });
  if (status && !['PENDING', 'ACTIVE', 'DISABLED'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  await db.run('UPDATE users SET role = COALESCE(?, role), department = COALESCE(?, department), status = COALESCE(?, status) WHERE id = ?',
    [role ?? null, department ?? null, status ?? null, req.params.id]);
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
