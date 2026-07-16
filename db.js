// Database layer using libSQL. Works two ways:
//  - Hosted (Render + Turso): set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN env vars
//  - Local: no env vars needed, uses a local file at data/quantify.db
const { createClient } = require('@libsql/client');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const url = process.env.TURSO_DATABASE_URL || 'file:' + (process.env.DB_PATH || path.join(__dirname, 'data', 'quantify.db'));
const client = createClient({ url, authToken: process.env.TURSO_AUTH_TOKEN });

async function run(sql, args = []) {
  const r = await client.execute({ sql, args });
  return { lastInsertRowid: r.lastInsertRowid ? Number(r.lastInsertRowid) : undefined, changes: r.rowsAffected };
}
async function all(sql, args = []) { return (await client.execute({ sql, args })).rows; }
async function get(sql, args = []) { return (await all(sql, args))[0]; }

async function init() {
  const stmts = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'USER',
  department TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  unit TEXT DEFAULT 'Nos',
  price REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS quantifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  department TEXT NOT NULL,
  gst_rate REAL NOT NULL DEFAULT 8,
  checked_by TEXT, checked_designation TEXT,
  approved_by TEXT, approved_designation TEXT,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS quantification_lines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quantification_id INTEGER NOT NULL REFERENCES quantifications(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  description TEXT NOT NULL,
  unit TEXT DEFAULT 'Nos',
  qty REAL NOT NULL DEFAULT 0,
  rate REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  user_name TEXT,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`;
  for (const s of stmts.split(';').map(x => x.trim()).filter(Boolean)) await client.execute(s);

  const itemCount = (await get('SELECT COUNT(*) c FROM items')).c;
  if (Number(itemCount) === 0) {
    const seedFile = path.join(__dirname, 'data', 'master_items.json');
    if (fs.existsSync(seedFile)) {
      const items = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
      await client.batch(items.map(i => ({ sql: 'INSERT INTO items (name, price) VALUES (?, ?)', args: [i.name, i.price] })), 'write');
      console.log('Seeded ' + items.length + ' master items');
    }
  }

  // Super admin on first run: username "Admin", password 654321 (change after login)
  const userCount = (await get('SELECT COUNT(*) c FROM users')).c;
  if (Number(userCount) === 0) {
    const pw = process.env.ADMIN_PASSWORD || '654321';
    await run("INSERT INTO users (email, name, password_hash, role, department, status) VALUES (?, ?, ?, 'ADMIN', 'Development Services', 'ACTIVE')",
      ['admin', 'Super Admin', bcrypt.hashSync(pw, 10)]);
    console.log('Seeded super admin - username: Admin, password: ' + pw + ' (change it from the panel after login)');
  }
}

module.exports = { run, all, get, init };
