# QuantiFy — Quick Quantification System
**Development Services Division · Fahi Dhiriulhun Corporation**
*Designed and created by necromenxer*

Web app for standardized item quantifications: type an item, pick it from the master-list dropdown, price auto-fills, enter quantity, download the finished PDF in the FDC format.

## Login
- Super admin: username **Admin**, password **654321** — change it right after first login using the "Change password" button in the top bar.
- Staff register with their @fdc.mv email; accounts stay PENDING until an admin approves them and assigns role + department in the Users panel.

## Features
- Item autocomplete from the master list (216 items pre-seeded); price and unit auto-fill.
- Quantifications stored under 4 departments: Technical, Maintenance, Infrastructure, Development Services.
- All users can view/download everything; only the creator or an admin can edit; only admins delete.
- Adjustable GST (default 8%), automatic totals, PDF export with sign-off block.
- Admin item management with duplicate detection (asks before adding similar items).
- Every user can change their own password from the top bar.

## Deploy free on Render + Turso (recommended)

**1. Create the database (Turso — free)**
1. Sign up at https://turso.tech (free plan is plenty).
2. Create a database (any name, e.g. `quantify`).
3. Copy the **Database URL** (starts with `libsql://...`).
4. Create an **auth token** for the database and copy it.

**2. Put the code on GitHub**
1. Create a free GitHub account/repo and upload this folder's contents (or push with git).

**3. Deploy on Render (free)**
1. Sign up at https://render.com and choose **New → Web Service**, connect the GitHub repo.
2. Settings: Build command `npm install`, Start command `npm start`, instance type **Free**.
3. Add Environment Variables:
   - `TURSO_DATABASE_URL` = your libsql:// URL
   - `TURSO_AUTH_TOKEN` = your token
   - `JWT_SECRET` = any long random string
   - (optional) `ADMIN_PASSWORD` = initial super-admin password (defaults to 654321)
4. Deploy. Render gives you a URL like `https://quantify.onrender.com` — share it with the division.

Notes: the free Render instance sleeps after ~15 min idle; the first visit after that takes ~30-60s to wake. Data is safe in Turso regardless of restarts/redeploys.

## Run locally instead (no accounts needed)
```bash
npm install
npm start        # uses a local file database at data/quantify.db
```
Open http://localhost:3000

## Environment variables
- `TURSO_DATABASE_URL` / `TURSO_AUTH_TOKEN` — hosted DB (omit for local file DB)
- `JWT_SECRET` — set a long random value in production
- `ADMIN_PASSWORD` — initial super-admin password (first run only; default 654321)
- `PORT` (default 3000), `DB_PATH` (custom local DB file)

## Branding
Drop your company logo as `public/logo.png` — PDFs will use it automatically.

## Backup
Turso dashboard lets you export the database; locally just copy `data/quantify.db`.
