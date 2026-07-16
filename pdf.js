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
     .text(`Department: ${q.department}    |    Prepared by: ${q.creator_name}    |    Date: ${(q.updated_at || q.created_at).slice(0, 10)}`,
       M, 146, { width: W, align: 'center', lineBreak: false });

  // ---- Item table ----
  let y = 170;
  const cols = [
    { label: '#', w: 30, align: 'center' },
    { label: 'Description', w: W - 30 - 55 - 55 - 75 - 85, align: 'left' },
    { label: 'Unit', w: 55, align: 'center' },
    { label: 'QTY', w: 55, align: 'center' },
    { label: 'Rate', w: 75, align: 'right' },
    { label: 'Amount', w: 85, align: 'right' },
  ];
  const rowH = 20;

  function row(vals, opts = {}) {
    let x = M;
    if (opts.fill) { doc.rect(M, y, W, rowH).fill(opts.fill); doc.fillColor('#000'); }
    doc.rect(M, y, W, rowH).strokeColor('#444').lineWidth(0.6).stroke();
    cols.forEach((c, i) => {
      if (i > 0) doc.moveTo(x, y).lineTo(x, y + rowH).stroke();
      doc.fillColor('#000').font(opts.font || 'Helvetica').fontSize(9)
         .text(String(vals[i] ?? ''), x + 4, y + 6, { width: c.w - 8, align: c.align, lineBreak: false });
      x += c.w;
    });
    y += rowH;
  }

  row(cols.map(c => c.label), { fill: '#d9d9d9', font: 'Helvetica-Bold' });

  let subtotal = 0;
  const lines = q.lines || [];
  const nRows = Math.max(lines.length, 15);
  for (let i = 0; i < nRows; i++) {
    const l = lines[i];
    if (l) {
      const amt = (Number(l.qty) || 0) * (Number(l.rate) || 0);
      subtotal += amt;
      row([i + 1, l.description, l.unit, l.qty, fmt(l.rate), fmt(amt)]);
    } else {
      row([i + 1, '', '', '', '', '0']);
    }
  }

  const gst = subtotal * (Number(q.gst_rate) || 0) / 100;
  const grand = subtotal + gst;

  // ---- Totals block (right aligned, like the official format) ----
  y += 14;
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
  if (y + sigH > PH - 90) y = PH - 90 - sigH; // keep on one page
  doc.rect(M, y, W, 18).fill('#d9d9d9');
  doc.rect(M, y, W, sigH).strokeColor('#444').lineWidth(0.7).stroke();
  doc.moveTo(M, y + 18).lineTo(M + W, y + 18).stroke();
  doc.moveTo(M + half, y).lineTo(M + half, y + sigH).stroke();
  doc.fillColor('#000').font('Helvetica-Bold').fontSize(9)
     .text('Checked By', M + 6, y + 5, { lineBreak: false }).text('Approved by', M + half + 6, y + 5, { lineBreak: false });
  doc.font('Helvetica').fontSize(9);
  const sig = (x0, name, desig) => {
    doc.text('Name: ' + (name || ''), x0, y + 25, { width: half - 12, lineBreak: false })
       .text('Designation: ' + (desig || ''), x0, y + 41, { width: half - 12, lineBreak: false })
       .text('Signature:', x0, y + 60, { lineBreak: false })
       .text('Date:', x0, y + 88, { lineBreak: false });
  };
  sig(M + 6, q.checked_by, q.checked_designation);
  sig(M + half + 6, q.approved_by, q.approved_designation);

  // ---- Footer: contact line + FDC mark (no credits) ----
  doc.font('Helvetica').fontSize(8).fillColor('#666')
     .text('+960 331 3244   |   info@fdc.mv   |   www.fdc.mv', M, PH - 62, { width: W, align: 'center', lineBreak: false })
     .text("2nd Floor, H. Fathangumaage, 20037, Sosun Magu, Male', Republic of Maldives.", M, PH - 51, { width: W, align: 'center', lineBreak: false });
  const mark = img('logo_mark.png');
  if (mark) { try { doc.image(mark, doc.page.width / 2 - 8, PH - 38, { height: 16 }); } catch {} }

  doc.end();
}

module.exports = { generatePdf };
