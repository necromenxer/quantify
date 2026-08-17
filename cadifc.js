// ---------------------------------------------------------------------------
// IFC reader.
//
// IFC is different in kind from DXF/DWG: it carries real building objects, so
// where the file is well formed we can read quantities the authoring tool
// already calculated instead of inferring anything from line work.
//
// Reality check: plenty of IFC files in circulation are conversions from DWG
// and contain geometry but no IfcSpace and no quantity sets. This reader does
// not pretend otherwise — it reports exactly what it found so the UI can tell
// the user why a file produced fewer rooms than expected.
// ---------------------------------------------------------------------------
let _api = null;
async function getApi() {
  if (_api) return _api;
  const wi = require('web-ifc');
  const api = new wi.IfcAPI();
  await api.Init();
  _api = { api, wi };
  return _api;
}

const valOf = o => (o && typeof o === 'object' && 'value' in o) ? o.value : o;
const nameOf = e => valOf(e?.LongName) || valOf(e?.Name) || null;

// Quantity sets and property sets both hang off IfcRelDefinesByProperties.
// Walk it once and index everything by the element it describes.
function indexDefinitions(api, wi, model) {
  const quantities = new Map();   // expressID -> { NetFloorArea: 19.27, ... }
  const properties = new Map();   // expressID -> { PsetName: { prop: value } }
  let rels;
  try { rels = api.GetLineIDsWithType(model, wi.IFCRELDEFINESBYPROPERTIES); }
  catch { return { quantities, properties }; }

  for (let i = 0; i < rels.size(); i++) {
    let rel;
    try { rel = api.GetLine(model, rels.get(i)); } catch { continue; }
    const defRef = rel && rel.RelatingPropertyDefinition;
    if (!defRef) continue;
    let def;
    try { def = api.GetLine(model, defRef.value); } catch { continue; }
    if (!def) continue;

    const targets = (rel.RelatedObjects || []).map(o => o.value);

    if (def.Quantities) {
      const q = {};
      for (const h of def.Quantities) {
        let qq; try { qq = api.GetLine(model, h.value); } catch { continue; }
        const n = valOf(qq?.Name);
        const v = valOf(qq?.AreaValue ?? qq?.LengthValue ?? qq?.VolumeValue ?? qq?.CountValue ?? qq?.WeightValue);
        if (n != null && v != null) q[n] = Number(v);
      }
      for (const t of targets) quantities.set(t, Object.assign(quantities.get(t) || {}, q));
    }

    if (def.HasProperties) {
      const setName = valOf(def.Name) || 'Pset';
      const p = {};
      for (const h of def.HasProperties) {
        let pp; try { pp = api.GetLine(model, h.value); } catch { continue; }
        const n = valOf(pp?.Name);
        const v = valOf(pp?.NominalValue);
        if (n != null) p[n] = v;
      }
      for (const t of targets) {
        const cur = properties.get(t) || {};
        cur[setName] = Object.assign(cur[setName] || {}, p);
        properties.set(t, cur);
      }
    }
  }
  return { quantities, properties };
}

// pick the first quantity whose name matches any of the candidates
const pick = (q, names) => {
  if (!q) return null;
  for (const n of names) {
    const hit = Object.keys(q).find(k => k.toLowerCase() === n.toLowerCase());
    if (hit && Number.isFinite(q[hit])) return q[hit];
  }
  return null;
};

function collect(api, wi, model, type) {
  try {
    const ids = api.GetLineIDsWithType(model, type);
    const out = [];
    for (let i = 0; i < ids.size(); i++) out.push(ids.get(i));
    return out;
  } catch { return []; }
}

async function parseIfc(buffer) {
  const { api, wi } = await getApi();
  const model = api.OpenModel(new Uint8Array(buffer));
  try {
    const schema = api.GetModelSchema(model);
    const { quantities, properties } = indexDefinitions(api, wi, model);

    // ---- rooms come from IfcSpace, which is the whole point of using IFC ----
    const rooms = [];
    for (const id of collect(api, wi, model, wi.IFCSPACE)) {
      let e; try { e = api.GetLine(model, id); } catch { continue; }
      const q = quantities.get(id);
      const area = pick(q, ['NetFloorArea', 'GrossFloorArea', 'NetArea', 'GrossArea']);
      const perimeter = pick(q, ['GrossPerimeter', 'Perimeter']);
      const height = pick(q, ['FinishCeilingHeight', 'Height', 'NetHeight']);
      rooms.push({
        id, label: nameOf(e) || 'Unnamed space',
        area, perimeter, height,
        hasQuantities: area != null,
      });
    }

    // ---- walls, doors, windows ----
    const walls = [];
    for (const t of [wi.IFCWALL, wi.IFCWALLSTANDARDCASE]) {
      for (const id of collect(api, wi, model, t)) {
        let e; try { e = api.GetLine(model, id); } catch { continue; }
        const q = quantities.get(id);
        walls.push({
          id, label: nameOf(e) || 'Wall',
          length: pick(q, ['Length', 'NetLength', 'GrossLength']),
          area: pick(q, ['NetSideArea', 'GrossSideArea', 'NetArea']),
          volume: pick(q, ['NetVolume', 'GrossVolume']),
          width: pick(q, ['Width', 'Thickness'])
            ?? (Number(properties.get(id)?.ADT_Pset_Wall?.BaseThickness) || null),
        });
      }
    }

    const countOf = t => collect(api, wi, model, t).length;
    const doors = countOf(wi.IFCDOOR);
    const windows = countOf(wi.IFCWINDOW);
    const slabs = countOf(wi.IFCSLAB);
    const storeys = countOf(wi.IFCBUILDINGSTOREY);

    const roomsWithArea = rooms.filter(r => r.hasQuantities).length;
    const wallsWithQty = walls.filter(w => w.length != null || w.area != null).length;

    // Honest diagnosis for the UI. An IFC with no spaces and no quantities is
    // usually a DWG conversion or an export with base quantities switched off.
    const notes = [];
    if (!rooms.length) {
      notes.push('This IFC contains no IfcSpace (room) objects, so no room areas could be read. Rooms must be defined in the source model and included in the IFC export.');
    } else if (!roomsWithArea) {
      notes.push('Rooms were found but carry no area quantities. Re-export with "base quantities" enabled to get exact areas.');
    }
    if (walls.length && !wallsWithQty) {
      notes.push('Walls carry no length/area quantities, so wall measurements are unavailable from this file.');
    }
    if (!storeys) notes.push('No building storeys are defined in this file.');

    return {
      schema,
      rooms, walls,
      counts: { spaces: rooms.length, walls: walls.length, doors, windows, slabs, storeys },
      quality: {
        roomsWithArea, wallsWithQty,
        // true when the file actually delivers IFC's advantage over DXF
        usable: roomsWithArea > 0 || wallsWithQty > 0,
      },
      notes,
    };
  } finally {
    try { api.CloseModel(model); } catch {}
  }
}

module.exports = { parseIfc };
