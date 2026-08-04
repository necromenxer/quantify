const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

const fmt = n => Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const ASSETS = path.join(__dirname, 'assets');
const img = f => { const p = path.join(ASSETS, f); return fs.existsSync(p) ? p : null; };

function generatePdf(q, stream) {
  const doc = new PDFDocument({ size: 'A4', margins: { top: 40, bottom: 20, left: 55, right: 55 } });
  doc.pipe(stream);

  const M = 55, W = doc.page.width - M * 2, PH = doc.page.height;

  // ---- Header: FDC logo left, mark right (as in the official format) ----
  const left = img('logo_left.png'), right = img('logo_right.png');
  if (left) { try { doc.image(left, M, 42, { height: 52 }); } catch {} }
  else doc.font('Helvetica-Bold').fontSize(16).text('FAHI DHIRIULHUN CORPORATION', M, 50);
  if (right) { try { doc.image(right, M + W - 52, 42, { height: 52 }); } catch {} }

  // ---- Title line (project info) ----
  doc.font('Helvetica-Bold').fontSize(12).fillColor('#000')
     .text(q.title, M, 128, { width: W, align: 'center', lineBreak: false });
  doc.font('Helvetica').fontSize(8.5).fillColor('#444')
     .text(`Department: ${q.department}    |    Date: ${(q.updated_at || q.created_at).slice(0, 10)}`,
       M, 146, { width: W, align: 'center', lineBreak: false });

  // ---- Item table ----
  let y = 170;
  const cols = [
    { label: '#', w: 30, align: 'center' },
    { label: 'Description', w: W - 30 - 55 - 55 - 75 - 85, align: 'left', wrap: true },
    { label: 'Unit', w: 55, align: 'center' },
    { label: 'QTY', w: 55, align: 'center' },
    { label: 'Rate', w: 75, align: 'right' },
    { label: 'Amount', w: 85, align: 'right' },
  ];
  const rowH = 20;          // minimum / default row height
  const PAD_X = 4, PAD_Y = 6, FS = 9;

  // Work out how tall a row needs to be so nothing gets clipped. Only the
  // Description column wraps; the rest are short values kept on one line.
  function measureRow(vals, opts = {}) {
    doc.font(opts.font || 'Helvetica').fontSize(FS);
    let needed = rowH;
    cols.forEach((c, i) => {
      if (!c.wrap) return;
      const txt = String(vals[i] ?? '');
      if (!txt) return;
      const h = doc.heightOfString(txt, { width: c.w - PAD_X * 2, align: c.align });
      needed = Math.max(needed, h + PAD_Y * 2);
    });
    return needed;
  }

  function row(vals, opts = {}) {
    const h = opts.height || measureRow(vals, opts);
    let x = M;
    if (opts.fill) { doc.rect(M, y, W, h).fill(opts.fill); doc.fillColor('#000'); }
    doc.rect(M, y, W, h).strokeColor('#444').lineWidth(0.6).stroke();
    cols.forEach((c, i) => {
      if (i > 0) doc.moveTo(x, y).lineTo(x, y + h).stroke();
      doc.fillColor('#000').font(opts.font || 'Helvetica').fontSize(FS)
         .text(String(vals[i] ?? ''), x + PAD_X, y + PAD_Y, {
           width: c.w - PAD_X * 2,
           align: c.align,
           // wrapping columns flow onto extra lines; fixed ones stay single-line
           lineBreak: !!c.wrap,
           ...(c.wrap ? {} : { ellipsis: true }),
         });
      x += c.w;
    });
    y += h;
  }

  const headerVals = cols.map(c => c.label);
  const drawHeader = () => row(headerVals, { fill: '#d9d9d9', font: 'Helvetica-Bold', height: rowH });
  drawHeader();

  // Rows can now be taller than one line, so the table may need to break onto
  // a new page. Reserve room for the totals + signature block on the last page.
  const CONTENT_BOTTOM = PH - 72;   // last usable y before the page footer
  const TABLE_BOTTOM = PH - 60;     // real rows may run this low, then break page
  // totals block (14 gap + 85) + signature block (20 gap + 105) measured from
  // the end of the table; blank filler rows must never eat into this.
  const BLOCK_AFTER_TABLE = 224;
  const FILLER_BOTTOM = CONTENT_BOTTOM - BLOCK_AFTER_TABLE;
  function ensureSpace(h) {
    if (y + h <= TABLE_BOTTOM) return;
    doc.addPage();
    y = 50;
    drawHeader();
  }

  let subtotal = 0;
  const lines = q.lines || [];
  const nRows = Math.max(lines.length, 15);
  for (let i = 0; i < nRows; i++) {
    const l = lines[i];
    const vals = l
      ? [i + 1, l.description, l.unit, l.qty, fmt(l.rate), fmt((Number(l.qty) || 0) * (Number(l.rate) || 0))]
      : [i + 1, '', '', '', '', '0'];
    if (l) subtotal += (Number(l.qty) || 0) * (Number(l.rate) || 0);
    const h = measureRow(vals);
    // blank padding rows never push the totals/signature block onto a new page
    if (!l && y + h > FILLER_BOTTOM) break;
    ensureSpace(h);
    row(vals, { height: h });
  }

  const gst = subtotal * (Number(q.gst_rate) || 0) / 100;
  const grand = subtotal + gst;

  // ---- Totals block (right aligned, like the official format) ----
  y += 14;
  // totals (~85pt) + signature block (~125pt) must stay together on one page
  if (y + (BLOCK_AFTER_TABLE - 14) > CONTENT_BOTTOM) { doc.addPage(); y = 50; }
  const tx = M + W - 260;
  doc.font('Helvetica-Bold').fontSize(10).fillColor('#000').text('Matericals Cost', tx, y, { lineBreak: false }); y += 17;
  const trow = (label, val, bold) => {
    doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(10)
       .text(label, tx, y, { lineBreak: false })
       .text(fmt(val), tx + 110, y, { width: 150, align: 'right', lineBreak: false });
    doc.moveTo(tx + 110, y + 14).lineTo(tx + 260, y + 14).strokeColor('#000').lineWidth(0.7).stroke();
    y += 21;
  };
  trow('Total', subtotal);
  trow('GST ' + Number(q.gst_rate) + '%', gst);
  y += 5;
  trow('Grand Total', grand, true);

  // ---- Signature block ----
  y += 20;
  const half = W / 2, sigH = 105;
  // page breaks are handled above, so no clamping needed here
  doc.rect(M, y, W, 18).fill('#d9d9d9');
  doc.rect(M, y, W, sigH).strokeColor('#444').lineWidth(0.7).stroke();
  doc.moveTo(M, y + 18).lineTo(M + W, y + 18).stroke();
  doc.moveTo(M + half, y).lineTo(M + half, y + sigH).stroke();
  doc.fillColor('#000').font('Helvetica-Bold').fontSize(9)
     .text('Prepared By', M + 6, y + 5, { lineBreak: false }).text('Approved by', M + half + 6, y + 5, { lineBreak: false });
  doc.font('Helvetica').fontSize(9);
  const sig = (x0, name, desig, date) => {
    doc.text('Name: ' + (name || ''), x0, y + 25, { width: half - 12, lineBreak: false })
       .text('Designation: ' + (desig || ''), x0, y + 41, { width: half - 12, lineBreak: false })
       .text('Signature:', x0, y + 60, { lineBreak: false })
       .text('Date: ' + (date || ''), x0, y + 88, { lineBreak: false });
  };
  // Prepared By date = date of PDF generation (download)
  const today = new Date().toISOString().slice(0, 10).split('-').reverse().join('.');
  sig(M + 6, q.checked_by, q.checked_designation, today);
  sig(M + half + 6, q.approved_by, q.approved_designation);
  // digital signature of the preparing user, if uploaded in Settings
  if (q.creator_signature && String(q.creator_signature).startsWith('data:image/png;base64,')) {
    try {
      const buf = Buffer.from(String(q.creator_signature).split(',')[1], 'base64');
      doc.image(buf, M + 58, y + 50, { fit: [180, 38] });
    } catch {}
  }

  // ---- Footer: contact line + FDC mark (no credits) ----
  doc.font('Helvetica').fontSize(8).fillColor('#666')
     .text('+960 331 3244   |   info@fdc.mv   |   www.fdc.mv', M, PH - 62, { width: W, align: 'center', lineBreak: false })
     .text("2nd Floor, H. Fathangumaage, 20037, Sosun Magu, Male', Republic of Maldives.", M, PH - 51, { width: W, align: 'center', lineBreak: false });
  const mark = img('logo_mark.png');
  if (mark) { try { doc.image(mark, doc.page.width / 2 - 8, PH - 38, { height: 16 }); } catch {} }

  doc.end();
}

module.exports = { generatePdf };
