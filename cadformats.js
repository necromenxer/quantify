// ---------------------------------------------------------------------------
// Drawing format router.
//
// The app accepts several drawing formats but the takeoff engine in server.js
// only understands one shape: the object dxf-parser produces
// ({ entities, blocks, tables, header }). Rather than teach the engine about
// every format, each reader here normalises into that same shape:
//
//   DXF  -> dxf-parser directly (unchanged behaviour)
//   DWG  -> LibreDWG (WASM) -> adapted to the dxf-parser shape
//   IFC  -> handled separately in cadifc.js, since IFC carries real objects
//           and quantities rather than raw line work
//   PDF  -> not parsed server-side; measured manually in the browser
//
// Keeping the adapter honest about the dxf-parser shape means room detection,
// block expansion, legend matching and wall measurement all work on DWG with
// no changes at all.
// ---------------------------------------------------------------------------
const DxfParser = require('dxf-parser');

const FORMATS = { DXF: 'DXF', DWG: 'DWG', IFC: 'IFC', PDF: 'PDF', UNKNOWN: 'UNKNOWN' };

// Identify by content where possible and fall back to the extension. Content
// wins because files get renamed: a .dxf that is really a DWG is common.
function detectFormat(filename, buffer) {
  const name = String(filename || '').toLowerCase();
  const head = buffer && buffer.length >= 8 ? buffer.slice(0, 8) : Buffer.alloc(0);
  const ascii = head.toString('latin1');

  // DWG files begin with a version tag such as AC1032 (AutoCAD 2018)
  if (/^AC10\d\d/.test(ascii)) return FORMATS.DWG;
  if (ascii.startsWith('%PDF')) return FORMATS.PDF;
  // IFC is a STEP physical file
  if (ascii.startsWith('ISO-10303')) return FORMATS.IFC;

  if (name.endsWith('.dwg')) return FORMATS.DWG;
  if (name.endsWith('.ifc') || name.endsWith('.ifcxml')) return FORMATS.IFC;
  if (name.endsWith('.pdf')) return FORMATS.PDF;
  if (name.endsWith('.dxf')) return FORMATS.DXF;
  return FORMATS.UNKNOWN;
}

// --------------------------- DWG -> dxf-parser shape ------------------------

// The package restricts its "exports" map, so require.resolve() can't be used
// to locate its wasm folder. Walk up from this file to find node_modules.
function findWasmDir() {
  const path = require('path'), fs = require('fs');
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, 'node_modules', '@mlightcad', 'libredwg-web', 'wasm');
    if (fs.existsSync(path.join(candidate, 'libredwg-web.wasm'))) return candidate + path.sep;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate the LibreDWG wasm files. Run "npm install" so @mlightcad/libredwg-web is present.');
}

let _libredwg = null;
async function getLibreDwg() {
  if (_libredwg) return _libredwg;
  // ESM-only package, so it has to be imported dynamically from CommonJS
  const mod = await import('@mlightcad/libredwg-web');
  _libredwg = { lib: await mod.LibreDwg.create(findWasmDir()), FileType: mod.Dwg_File_Type };
  return _libredwg;
}

const pt = p => (p ? { x: Number(p.x) || 0, y: Number(p.y) || 0, z: Number(p.z) || 0 } : { x: 0, y: 0, z: 0 });

// LibreDWG nests text payloads under `.text` on TEXT/ATTRIB/MTEXT; dxf-parser
// keeps them flat. Read either so both paths behave the same downstream.
function textOf(e) {
  if (typeof e.text === 'string') return e.text;
  if (e.text && typeof e.text.text === 'string') return e.text.text;
  return '';
}
function textPos(e) {
  const t = (e.text && typeof e.text === 'object') ? e.text : e;
  return pt(t.startPoint || t.insertionPoint || t.position || e.startPoint);
}

function adaptEntity(e) {
  if (!e || !e.type) return null;
  const base = { type: e.type, layer: e.layer || '0', handle: e.handle };
  // dxf-parser exposes the raw ACI index as `color`; keep 256 (ByLayer) semantics
  if (typeof e.colorIndex === 'number') base.color = e.colorIndex;

  switch (e.type) {
    case 'LINE':
      return { ...base, vertices: [pt(e.startPoint), pt(e.endPoint)] };

    case 'LWPOLYLINE':
    case 'POLYLINE':
      return {
        ...base,
        vertices: (e.vertices || []).map(pt),
        // bit 1 of the polyline flag marks a closed shape
        shape: !!(e.flag & 1) || !!e.isClosed || !!e.shape,
      };

    case 'CIRCLE':
      return { ...base, center: pt(e.center), radius: Number(e.radius) || 0 };

    case 'ARC':
      return {
        ...base, center: pt(e.center), radius: Number(e.radius) || 0,
        startAngle: e.startAngle, endAngle: e.endAngle,
      };

    case 'POINT':
      return { ...base, position: pt(e.position) };

    case 'TEXT':
    case 'MTEXT':
    case 'ATTRIB':
    case 'ATTDEF': {
      const s = textOf(e);
      if (!s) return null;
      // ATTRIB/ATTDEF carry values inside blocks; treat them as TEXT so labels
      // written as block attributes still get picked up as room names
      return { ...base, type: e.type === 'MTEXT' ? 'MTEXT' : 'TEXT', text: s, startPoint: textPos(e) };
    }

    case 'INSERT':
      return {
        ...base,
        name: e.name,
        position: pt(e.insertionPoint || e.position),
        xScale: e.xScale != null ? Number(e.xScale) : 1,
        yScale: e.yScale != null ? Number(e.yScale) : 1,
        rotation: Number(e.rotation) || 0,
      };

    case 'SOLID':
    case 'HATCH':
      return { ...base, vertices: (e.vertices || []).map(pt) };

    default:
      // Anything else (dimensions, leaders, viewports) is not used for takeoff.
      // Keep it with whatever vertices it has so counts stay honest.
      return e.vertices ? { ...base, vertices: e.vertices.map(pt) } : base;
  }
}

const adaptList = list => (list || []).map(adaptEntity).filter(Boolean);

async function parseDwg(buffer) {
  const { lib, FileType } = await getLibreDwg();
  const ab = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  let handle;
  try { handle = lib.dwg_read_data(ab, FileType.DWG); }
  catch (e) { throw new Error('This DWG could not be read: ' + e.message); }
  if (!handle) throw new Error('This DWG could not be read. It may be corrupt, password protected, or a newer format than the reader supports.');

  let db;
  try { db = lib.convert(handle); }
  finally { try { lib.dwg_free(handle); } catch {} }

  // layer table -> { name: { color, colorIndex } }
  const layers = {};
  for (const l of (db.tables?.LAYER?.entries || [])) {
    if (!l || !l.name) continue;
    layers[l.name] = { name: l.name, color: l.color, colorIndex: l.colorIndex };
  }

  // block definitions live on the block records; model/paper space are not blocks
  const blocks = {};
  for (const b of (db.tables?.BLOCK_RECORD?.entries || [])) {
    if (!b || !b.name || /^\*(Model|Paper)_Space/i.test(b.name)) continue;
    blocks[b.name] = { name: b.name, entities: adaptList(b.entities) };
  }

  // LibreDWG exposes header variables unprefixed (INSUNITS), dxf-parser uses
  // the DXF group name ($INSUNITS). Provide both so unit detection works
  // identically whichever reader produced the drawing.
  const header = {};
  for (const [k, v] of Object.entries(db.header || {})) {
    header[k] = v;
    if (!k.startsWith('$')) header['$' + k] = v;
  }

  return {
    entities: adaptList(db.entities),
    blocks,
    tables: { layer: { layers } },
    header,
  };
}

// --------------------------------- entry point -----------------------------

// Returns a dxf-parser-shaped object for DXF and DWG. IFC and PDF are handled
// by the caller because they don't reduce to line work.
async function parseToDxfShape(format, buffer) {
  if (format === FORMATS.DXF) {
    // rethrow the parser's own reason — the caller composes the user-facing text
    return new DxfParser().parseSync(buffer.toString('utf8'));
  }
  if (format === FORMATS.DWG) return parseDwg(buffer);
  throw new Error('Unsupported format for drawing parsing: ' + format);
}

module.exports = { FORMATS, detectFormat, parseToDxfShape, parseDwg };
