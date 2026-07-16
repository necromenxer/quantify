const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

const fmt = n => Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

function generatePdf(q, stream) {
  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  doc.pipe(stream);

  const M = 50, W = doc.page.width - M * 2;

  // Header / branding
  const logo = path.join(__dirname, 'public', 'logo.png');
  if (fs.existsSync(logo)) { try { doc.image(logo, M, 40, { height: 45 }); } catch {} }
  else {
    doc.font('Helvetica-Bold').fontSize(18).fillColor('#1a1a1a').text('FAHI DHIRIULHUN CORPORATION', M, 45);
  }
  doc.font('Helvetica').fontSize(9).fillColor('#555')
     .text('Development Services Division', M, doc.y + 2);

  doc.font('Helvetica-Bold').fontSize(13).fillColor('#000')
     .text(q.title, M, 110, { width: W, align: 'center' });
  doc.font('Helvetica').fontSize(9).fillColor('#444')
     .text(`Department: ${q.department}    |    Prepared by: ${q.creator_name}    |    Date: ${(q.updated_at || q.created_at).slice(0, 10)}`,
       M, doc.y + 4, { width: W, align: 'center' });

  // Table
  let y = doc.y + 18;
  const cols = [
    { label: '#', w: 28, align: 'center' },
    { label: 'Description', w: W - 28 - 50 - 55 - 65 - 80, align: 'left' },
    { label: 'Unit', w: 50, align: 'center' },
    { label: 'QTY', w: 55, align: 'right' },
    { label: 'Rate', w: 65, align: 'right' },
    { label: 'Amount', w: 80, align: 'right' },
  ];

  function row(vals, opts = {}) {
    const h = opts.h || 18;
    if (y + h > doc.page.height - 180 && !opts.noBreak) { doc.addPage(); y = 60; }
    let x = M;
    if (opts.fill) doc.rect(M, y, W, h).fill(opts.fill);
    doc.rect(M, y, W, h).strokeColor('#333').lineWidth(0.5).stroke();
    cols.forEach((c, i) => {
      if (i > 0) doc.moveTo(x, y).lineTo(x, y + h).stroke();
      doc.fillColor(opts.color || '#000').font(opts.font || 'Helvetica').fontSize(9)
         .text(String(vals[i] ?? ''), x + 4, y + 5, { width: c.w - 8, align: c.align, lineBreak: false });
      x += c.w;
    });
    y += h;
  }

  row(cols.map(c => c.label), { fill: '#d9d9d9', font: 'Helvetica-Bold', noBreak: true });

  let subtotal = 0;
  const lines = q.lines || [];
  const minRows = Math.max(lines.length, 15);
  for (let i = 0; i < minRows; i++) {
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

  // Totals block
  y += 15;
  const tx = M + W - 250;
  doc.font('Helvetica-Bold').fontSize(10).fillColor('#000').text('Matericals Cost', tx, y); y += 16;
  const trow = (label, val, bold) => {
    doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(10)
       .text(label, tx, y).text(fmt(val), tx + 120, y, { width: 130, align: 'right' });
    doc.moveTo(tx + 120, y + 13).lineTo(tx + 250, y + 13).strokeColor('#000').lineWidth(0.7).stroke();
    y += 20;
  };
  trow('Total', subtotal);
  trow(`GST ${Number(q.gst_rate)}%`, gst);
  y += 4;
  trow('Grand Total', grand, true);

  // Signature block
  y += 25;
  if (y > doc.page.height - 170) { doc.addPage(); y = 60; }
  const half = W / 2;
  const sigH = 110;
  doc.rect(M, y, W, sigH).strokeColor('#333').lineWidth(0.7).stroke();
  doc.moveTo(M + half, y).lineTo(M + half, y + sigH).stroke();
  doc.rect(M, y, W, 18).fill('#d9d9d9');
  doc.rect(M, y, W, 18).stroke();
  doc.moveTo(M + half, y).lineTo(M + half, y + sigH).stroke();
  doc.fillColor('#000').font('Helvetica-Bold').fontSize(9)
     .text('Checked By', M + 5, y + 5).text('Approved by', M + half + 5, y + 5);
  doc.font('Helvetica').fontSize(9)
     .text(`Name: ${q.checked_by || ''}`, M + 5, y + 26)
     .text(`Designation: ${q.checked_designation || ''}`, M + 5, y + 42)
     .text('Signature:', M + 5, y + 62)
     .text('Date:', M + 5, y + 92)
     .text(`Name: ${q.approved_by || ''}`, M + half + 5, y + 26)
     .text(`Designation: ${q.approved_designation || ''}`, M + half + 5, y + 42)
     .text('Signature:', M + half + 5, y + 62)
     .text('Date:', M + half + 5, y + 92);

  // Footer
  doc.font('Helvetica').fontSize(8).fillColor('#666')
     .text('+960 331 3244   |   info@fdc.mv   |   www.fdc.mv', M, doc.page.height - 70, { width: W, align: 'center' })
     .text("2nd Floor, H. Fathangumaage, 20037, Sosun Magu, Male', Republic of Maldives.", { width: W, align: 'center' })
     .text('QuantiFy — designed and created by necromenxer', { width: W, align: 'center' });

  doc.end();
}

module.exports = { generatePdf };
