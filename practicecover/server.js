const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, AlignmentType, BorderStyle, WidthType, ShadingType, Header, Footer, TabStopType, TabStopPosition, PageNumber, HeadingLevel } = require('docx');
// Node 18+ has fetch built-in — no need for node-fetch

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// ─── Database connection ──────────────────────────────────────────────────────
const dbUrl = (process.env.DATABASE_URL || '').replace(/^postgres:\/\//, 'postgresql://');
if (!dbUrl) { console.error('ERROR: DATABASE_URL not set!'); process.exit(1); }

const pool = new Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });

pool.connect((err, client, release) => {
  if (err) console.error('ERROR: DB connection failed:', err.message);
  else { console.log('SUCCESS: Database connected!'); release(); }
});

const query = async (text, params) => {
  try { return await pool.query(text, params); }
  catch (err) { console.error('DB Error:', err.message, '| Query:', text); throw err; }
};

// ─── Sessions ─────────────────────────────────────────────────────────────────
app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'mdesk-secret-2024-xkq9',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, secure: false }
}));

// ─── Auth middleware ───────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorised' });
};
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.role === 'admin') return next();
  res.status(403).json({ error: 'Admin access required' });
};

// ─── Static files (login page served before auth) ────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));


// ─── Audit log helpers ────────────────────────────────────────────────────────
async function auditLog(userId, userName, action, entityType, entityId, description) {
  try {
    await query(
      'INSERT INTO audit_log (id, user_id, user_name, action, entity_type, entity_id, description) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [uuidv4(), userId, userName, action, entityType, entityId, description]
    );
  } catch (e) {
    console.error('Audit log error:', e.message);
  }
}

// Build a human-readable diff summary between old and new field values
function diffFields(oldObj, newObj, fieldMap) {
  const changes = [];
  for (const [key, label] of Object.entries(fieldMap)) {
    const oldVal = oldObj[key] == null ? '' : String(oldObj[key]);
    const newVal = newObj[key] == null ? '' : String(newObj[key]);
    if (oldVal !== newVal) {
      const fmtOld = oldVal || '—';
      const fmtNew = newVal || '—';
      changes.push(`${label}: ${fmtOld} → ${fmtNew}`);
    }
  }
  return changes.length ? changes.join(' · ') : null;
}

// Format a date value from DB row (may be Date object or string)
function fmtAuditDate(v) {
  if (!v) return null;
  if (v instanceof Date) return v.toISOString().split('T')[0];
  return String(v).split('T')[0];
}
// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const result = await query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid email or password' });
    const user = result.rows[0];
    if (!user.active) return res.status(401).json({ error: 'Account disabled. Contact your administrator.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.name = user.name;
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  res.json({ id: req.session.userId, name: req.session.name, role: req.session.role });
});

// ─── User management (admin only) ────────────────────────────────────────────
app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT id, name, email, role, active, created_at FROM users ORDER BY name ASC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });
    const existing = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existing.rows.length) return res.status(400).json({ error: 'A user with that email already exists' });
    const hash = await bcrypt.hash(password, 12);
    const id = uuidv4();
    const result = await query(
      'INSERT INTO users (id, name, email, password_hash, role, active) VALUES ($1,$2,$3,$4,$5,true) RETURNING id, name, email, role, active, created_at',
      [id, name, email.toLowerCase().trim(), hash, role || 'readonly']
    );
    res.status(201).json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { name, email, role, active, password } = req.body;
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      await query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
    }
    const result = await query(
      'UPDATE users SET name=$1, email=$2, role=$3, active=$4 WHERE id=$5 RETURNING id, name, email, role, active, created_at',
      [name, email.toLowerCase().trim(), role, active, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (req.params.id === req.session.userId) return res.status(400).json({ error: 'You cannot delete your own account' });
    await query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Protected API routes ─────────────────────────────────────────────────────

// Customers
app.get('/api/customers', requireAuth, async (req, res) => {
  try { res.json((await query('SELECT * FROM customers ORDER BY name ASC')).rows.map(normaliseCustomer)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/customers', requireAuth, async (req, res) => {
  try {
    const { type, name, email, phone, contactName, contactMobile } = req.body;
    const result = await query('INSERT INTO customers (id,type,name,email,phone,contact_name,contact_mobile) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [uuidv4(),type,name,email,phone,contactName||null,contactMobile||null]);
    const c = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'created', 'Customer', c.id, `Created customer "${c.name}"`);
    res.status(201).json(normaliseCustomer(c));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/customers/:id', requireAuth, async (req, res) => {
  try {
    const { type, name, email, phone, contactName, contactMobile } = req.body;
    const before = (await query('SELECT * FROM customers WHERE id=$1', [req.params.id])).rows[0];
    const result = await query('UPDATE customers SET type=$1,name=$2,email=$3,phone=$4,contact_name=$5,contact_mobile=$6 WHERE id=$7 RETURNING *', [type,name,email,phone,contactName||null,contactMobile||null,req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const c = result.rows[0];
    const changes = before ? diffFields(
      { type: before.type, name: before.name, email: before.email, phone: before.phone, contact: before.contact_name, mobile: before.contact_mobile },
      { type: c.type, name: c.name, email: c.email, phone: c.phone, contact: c.contact_name, mobile: c.contact_mobile },
      { type: 'Type', name: 'Name', email: 'Email', phone: 'Phone', contact: 'Contact Name', mobile: 'Contact Mobile' }
    ) : null;
    const desc = `Updated customer "${c.name}"${changes ? ' — ' + changes : ''}`;
    await auditLog(req.session.userId, req.session.name, 'updated', 'Customer', c.id, desc);
    res.json(normaliseCustomer(c));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/customers/:id', requireAuth, async (req, res) => {
  try {
    const existing = await query('SELECT name FROM customers WHERE id=$1', [req.params.id]);
    const name = existing.rows[0]?.name || req.params.id;
    await query('DELETE FROM customers WHERE id=$1', [req.params.id]);
    await auditLog(req.session.userId, req.session.name, 'deleted', 'Customer', req.params.id, `Deleted customer "${name}"`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Addresses
app.get('/api/addresses', requireAuth, async (req, res) => {
  try {
    const { customerId } = req.query;
    const result = customerId
      ? await query('SELECT * FROM addresses WHERE customer_id=$1 ORDER BY label ASC', [customerId])
      : await query('SELECT * FROM addresses ORDER BY label ASC');
    res.json(result.rows.map(normaliseAddress));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/addresses', requireAuth, async (req, res) => {
  try {
    const { customerId, label, line1, line2, city, postcode } = req.body;
    const result = await query('INSERT INTO addresses (id,customer_id,label,line1,line2,city,postcode) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [uuidv4(),customerId,label,line1,line2,city,postcode]);
    const a = result.rows[0];
    const desc = `Created address "${[a.label, a.line1, a.postcode].filter(Boolean).join(', ')}"`;
    await auditLog(req.session.userId, req.session.name, 'created', 'Address', a.id, desc);
    res.status(201).json(normaliseAddress(a));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/addresses/:id', requireAuth, async (req, res) => {
  try {
    const { customerId, label, line1, line2, city, postcode } = req.body;
    const before = (await query('SELECT * FROM addresses WHERE id=$1', [req.params.id])).rows[0];
    const result = await query('UPDATE addresses SET customer_id=$1,label=$2,line1=$3,line2=$4,city=$5,postcode=$6 WHERE id=$7 RETURNING *', [customerId,label,line1,line2,city,postcode,req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const a = result.rows[0];
    const changes = before ? diffFields(
      { label: before.label, line1: before.line1, line2: before.line2, city: before.city, postcode: before.postcode },
      { label: a.label, line1: a.line1, line2: a.line2, city: a.city, postcode: a.postcode },
      { label: 'Label', line1: 'Line 1', line2: 'Line 2', city: 'City', postcode: 'Postcode' }
    ) : null;
    const addrStr = [a.label, a.line1, a.postcode].filter(Boolean).join(', ');
    const desc = `Updated address "${addrStr}"${changes ? ' — ' + changes : ''}`;
    await auditLog(req.session.userId, req.session.name, 'updated', 'Address', a.id, desc);
    res.json(normaliseAddress(a));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/addresses/:id', requireAuth, async (req, res) => {
  try {
    const existing = await query('SELECT label, line1, postcode FROM addresses WHERE id=$1', [req.params.id]);
    const a = existing.rows[0];
    const desc = a ? `Deleted address "${[a.label, a.line1, a.postcode].filter(Boolean).join(', ')}"` : `Deleted address ${req.params.id}`;
    await query('DELETE FROM addresses WHERE id=$1', [req.params.id]);
    await auditLog(req.session.userId, req.session.name, 'deleted', 'Address', req.params.id, desc);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Trades
app.get('/api/trades', requireAuth, async (req, res) => {
  try { res.json((await query('SELECT * FROM trades ORDER BY company_name ASC')).rows.map(normaliseTrade)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/trades', requireAuth, async (req, res) => {
  try {
    const { status, companyName, companyAddress, contactName, contactNumber, contactEmail, services } = req.body;
    const result = await query('INSERT INTO trades (id,status,company_name,company_address,contact_name,contact_number,contact_email,services) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [uuidv4(),status,companyName,companyAddress,contactName,contactNumber,contactEmail,services]);
    const t = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'created', 'Trade', t.id, `Created subcontractor "${t.company_name}"`);
    res.status(201).json(normaliseTrade(t));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/trades/:id', requireAuth, async (req, res) => {
  try {
    const { status, companyName, companyAddress, contactName, contactNumber, contactEmail, services } = req.body;
    const before = (await query('SELECT * FROM trades WHERE id=$1', [req.params.id])).rows[0];
    const result = await query('UPDATE trades SET status=$1,company_name=$2,company_address=$3,contact_name=$4,contact_number=$5,contact_email=$6,services=$7 WHERE id=$8 RETURNING *', [status,companyName,companyAddress,contactName,contactNumber,contactEmail,services,req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const t = result.rows[0];
    const changes = before ? diffFields(
      { status: before.status, name: before.company_name, address: before.company_address, contact: before.contact_name, phone: before.contact_number, email: before.contact_email, services: (before.services||[]).join(', ') },
      { status: t.status, name: t.company_name, address: t.company_address, contact: t.contact_name, phone: t.contact_number, email: t.contact_email, services: (t.services||[]).join(', ') },
      { status: 'Status', name: 'Company', address: 'Address', contact: 'Contact', phone: 'Phone', email: 'Email', services: 'Services' }
    ) : null;
    const desc = `Updated subcontractor "${t.company_name}"${changes ? ' — ' + changes : ''}`;
    await auditLog(req.session.userId, req.session.name, 'updated', 'Trade', t.id, desc);
    res.json(normaliseTrade(t));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/trades/:id', requireAuth, async (req, res) => {
  try {
    const existing = await query('SELECT company_name FROM trades WHERE id=$1', [req.params.id]);
    const name = existing.rows[0]?.company_name || req.params.id;
    await query('DELETE FROM trades WHERE id=$1', [req.params.id]);
    await auditLog(req.session.userId, req.session.name, 'deleted', 'Trade', req.params.id, `Deleted subcontractor "${name}"`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Jobs
app.get('/api/jobs', requireAuth, async (req, res) => {
  try {
    const jobsResult = await query('SELECT * FROM jobs ORDER BY created_at DESC');
    const [tradesResult, commsResult] = await Promise.all([
      query('SELECT * FROM job_trades'),
      query('SELECT * FROM communications ORDER BY date ASC')
    ]);
    const jobTradesMap = {};
    tradesResult.rows.forEach(r => { if (!jobTradesMap[r.job_id]) jobTradesMap[r.job_id] = []; jobTradesMap[r.job_id].push(r.trade_id); });
    const commsMap = {};
    commsResult.rows.forEach(r => { if (!commsMap[r.job_id]) commsMap[r.job_id] = []; commsMap[r.job_id].push(normaliseComm(r)); });
    res.json(jobsResult.rows.map(j => normaliseJob(j, jobTradesMap[j.id] || [], commsMap[j.id] || [])));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/jobs', requireAuth, async (req, res) => {
  try {
    const { workOrderId, customerId, addressId, title, status, actionRequired,
      dateReceived, deadlineForCompletion, dateWorkCompleted, dateInvoiced,
      invoiceNumber, priceQuotedExclVat, priceQuotedInclVat, complianceStandard,
      poSentSubcontractor, chasedSubcontractor, proposedDateTenant, bookedAdc,
      bookedSubcontractor, tenantNotResponding, onHold, rejectedCancelled, poChasedDate,
      dateBooked, datePaid, tradeIds } = req.body;
    const id = uuidv4();
    const result = await query(
      `INSERT INTO jobs (id,work_order_id,customer_id,address_id,title,status,action_required,
        date_received,deadline_for_completion,date_work_completed,date_invoiced,
        invoice_number,price_quoted_excl_vat,price_quoted_incl_vat,compliance_standard,
        po_sent_subcontractor,chased_subcontractor,proposed_date_tenant,booked_adc,
        booked_subcontractor,tenant_not_responding,on_hold,rejected_cancelled,po_chased_date,
        date_booked,date_paid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26) RETURNING *`,
      [id,workOrderId,customerId,addressId,title,status||'needs_to_be_booked_adc',actionRequired,
        orNull(dateReceived),orNull(deadlineForCompletion),orNull(dateWorkCompleted),orNull(dateInvoiced),
        invoiceNumber||null,priceQuotedExclVat||null,priceQuotedInclVat||null,complianceStandard||null,
        orNull(poSentSubcontractor),orNull(chasedSubcontractor),orNull(proposedDateTenant),orNull(bookedAdc),
        orNull(bookedSubcontractor),orNull(tenantNotResponding),orNull(onHold),orNull(rejectedCancelled),orNull(poChasedDate),
        orNull(dateBooked),orNull(datePaid)]
    );
    if (tradeIds && tradeIds.length) await Promise.all(tradeIds.map(tid => query('INSERT INTO job_trades (job_id,trade_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id,tid])));
    const j = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'created', 'Job', j.id, `Created job "${j.title}" (${j.work_order_id})`);
    res.status(201).json(normaliseJob(j, tradeIds || [], []));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/jobs/:id', requireAuth, async (req, res) => {
  try {
    const beforeJob = (await query('SELECT * FROM jobs WHERE id=$1', [req.params.id])).rows[0] || null;
    const { workOrderId, customerId, addressId, title, status, actionRequired,
      dateReceived, deadlineForCompletion, dateWorkCompleted, dateInvoiced,
      invoiceNumber, priceQuotedExclVat, priceQuotedInclVat, complianceStandard,
      poSentSubcontractor, chasedSubcontractor, proposedDateTenant, bookedAdc,
      bookedSubcontractor, tenantNotResponding, onHold, rejectedCancelled, poChasedDate,
      dateBooked, datePaid, tradeIds } = req.body;
    const result = await query(
      `UPDATE jobs SET work_order_id=$1,customer_id=$2,address_id=$3,title=$4,status=$5,action_required=$6,
        date_received=$7,deadline_for_completion=$8,date_work_completed=$9,date_invoiced=$10,
        invoice_number=$11,price_quoted_excl_vat=$12,price_quoted_incl_vat=$13,compliance_standard=$14,
        po_sent_subcontractor=$15,chased_subcontractor=$16,proposed_date_tenant=$17,booked_adc=$18,
        booked_subcontractor=$19,tenant_not_responding=$20,on_hold=$21,rejected_cancelled=$22,po_chased_date=$23,
        date_booked=$24,date_paid=$25
       WHERE id=$26 RETURNING *`,
      [workOrderId,customerId,addressId,title,status,actionRequired,
        orNull(dateReceived),orNull(deadlineForCompletion),orNull(dateWorkCompleted),orNull(dateInvoiced),
        invoiceNumber||null,priceQuotedExclVat||null,priceQuotedInclVat||null,complianceStandard||null,
        orNull(poSentSubcontractor),orNull(chasedSubcontractor),orNull(proposedDateTenant),orNull(bookedAdc),
        orNull(bookedSubcontractor),orNull(tenantNotResponding),orNull(onHold),orNull(rejectedCancelled),orNull(poChasedDate),
        orNull(dateBooked),orNull(datePaid),req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    await query('DELETE FROM job_trades WHERE job_id=$1', [req.params.id]);
    if (tradeIds && tradeIds.length) await Promise.all(tradeIds.map(tid => query('INSERT INTO job_trades (job_id,trade_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.id,tid])));
    const j = result.rows[0];
    const jobChanges = beforeJob ? diffFields(
      {
        status: beforeJob.status,
        title: beforeJob.title,
        workOrder: beforeJob.work_order_id,
        action: beforeJob.action_required,
        received: fmtAuditDate(beforeJob.date_received),
        deadline: fmtAuditDate(beforeJob.deadline_for_completion),
        completed: fmtAuditDate(beforeJob.date_work_completed),
        invoiced: fmtAuditDate(beforeJob.date_invoiced),
        invoiceNo: beforeJob.invoice_number,
        priceExcl: beforeJob.price_quoted_excl_vat != null ? '£'+parseFloat(beforeJob.price_quoted_excl_vat).toFixed(2) : null,
        priceIncl: beforeJob.price_quoted_incl_vat != null ? '£'+parseFloat(beforeJob.price_quoted_incl_vat).toFixed(2) : null,
        compliance: beforeJob.compliance_standard,
        bookedAdc: fmtAuditDate(beforeJob.booked_adc),
        bookedSub: fmtAuditDate(beforeJob.booked_subcontractor),
        onHold: fmtAuditDate(beforeJob.on_hold),
        rejected: fmtAuditDate(beforeJob.rejected_cancelled),
      },
      {
        status: j.status,
        title: j.title,
        workOrder: j.work_order_id,
        action: j.action_required,
        received: fmtAuditDate(j.date_received),
        deadline: fmtAuditDate(j.deadline_for_completion),
        completed: fmtAuditDate(j.date_work_completed),
        invoiced: fmtAuditDate(j.date_invoiced),
        invoiceNo: j.invoice_number,
        priceExcl: j.price_quoted_excl_vat != null ? '£'+parseFloat(j.price_quoted_excl_vat).toFixed(2) : null,
        priceIncl: j.price_quoted_incl_vat != null ? '£'+parseFloat(j.price_quoted_incl_vat).toFixed(2) : null,
        compliance: j.compliance_standard,
        bookedAdc: fmtAuditDate(j.booked_adc),
        bookedSub: fmtAuditDate(j.booked_subcontractor),
        onHold: fmtAuditDate(j.on_hold),
        rejected: fmtAuditDate(j.rejected_cancelled),
      },
      {
        status: 'Status', title: 'Title', workOrder: 'Work Order', action: 'Action Required',
        received: 'Date Received', deadline: 'Deadline', completed: 'Work Completed',
        invoiced: 'Date Invoiced', invoiceNo: 'Invoice No.', priceExcl: 'Price Excl. VAT',
        priceIncl: 'Price Incl. VAT', compliance: 'Compliance', bookedAdc: 'Booked ADC',
        bookedSub: 'Booked Sub.', onHold: 'On Hold', rejected: 'Rejected/Cancelled',
      }
    ) : null;
    const jobDesc = `Updated job "${j.title}" (${j.work_order_id})${jobChanges ? ' — ' + jobChanges : ''}`;
    await auditLog(req.session.userId, req.session.name, 'updated', 'Job', j.id, jobDesc);
    res.json(normaliseJob(j, tradeIds || [], []));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/jobs/:id', requireAuth, async (req, res) => {
  try {
    const existing = await query('SELECT title, work_order_id FROM jobs WHERE id=$1', [req.params.id]);
    const j = existing.rows[0];
    const desc = j ? `Deleted job "${j.title}" (${j.work_order_id})` : `Deleted job ${req.params.id}`;
    await query('DELETE FROM jobs WHERE id=$1', [req.params.id]);
    await auditLog(req.session.userId, req.session.name, 'deleted', 'Job', req.params.id, desc);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/jobs/:id/communications', requireAuth, async (req, res) => {
  try {
    const { note, author } = req.body;
    const result = await query('INSERT INTO communications (id,job_id,note,author) VALUES ($1,$2,$3,$4) RETURNING *', [uuidv4(),req.params.id,note,author]);
    res.status(201).json(normaliseComm(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Stats
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [jobs, customers, trades, addresses] = await Promise.all([
      query('SELECT status FROM jobs'),
      query('SELECT COUNT(*) FROM customers'),
      query('SELECT COUNT(*) FROM trades'),
      query('SELECT COUNT(*) FROM addresses')
    ]);
    const byStatus = {};
    jobs.rows.forEach(j => { byStatus[j.status] = (byStatus[j.status] || 0) + 1; });
    res.json({ totalJobs: jobs.rows.length, totalCustomers: parseInt(customers.rows[0].count), totalTrades: parseInt(trades.rows[0].count), totalAddresses: parseInt(addresses.rows[0].count), byStatus });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// Audit log
app.get('/api/audit-log', requireAuth, async (req, res) => {
  try {
    const { entity, search, limit } = req.query;
    let q = 'SELECT * FROM audit_log';
    const params = [];
    const conditions = [];
    if (entity && entity !== 'all') { conditions.push(`entity_type = $${params.length+1}`); params.push(entity); }
    if (search) { conditions.push(`(description ILIKE $${params.length+1} OR user_name ILIKE $${params.length+1})`); params.push('%'+search+'%'); }
    if (conditions.length) q += ' WHERE ' + conditions.join(' AND ');
    q += ' ORDER BY created_at DESC';
    q += ` LIMIT ${parseInt(limit) || 200}`;
    const result = await query(q, params);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Tasks ────────────────────────────────────────────────────────────────────
app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { assignedTo, status } = req.query;
    const baseQ = `
      SELECT t.*,
        u.name   AS assigned_to_name,
        ab.name  AS assigned_by_name,
        c.name   AS customer_name,
        j.title  AS job_title, j.work_order_id,
        tr.company_name AS trade_name
      FROM tasks t
      LEFT JOIN users u   ON t.assigned_to  = u.id
      LEFT JOIN users ab  ON t.assigned_by   = ab.id
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN jobs j    ON t.job_id        = j.id
      LEFT JOIN trades tr ON t.trade_id      = tr.id`;
    const conditions = [];
    const params = [];
    if (assignedTo) { conditions.push(`t.assigned_to = $${params.length+1}`); params.push(assignedTo); }
    if (status)     { conditions.push(`t.status = $${params.length+1}`);      params.push(status); }
    const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : '';
    const result = await query(baseQ + where + ' ORDER BY t.target_date ASC, t.created_at ASC', params);
    res.json(result.rows.map(normaliseTask));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { description, targetDate, assignedTo, assignedBy, customerId, jobId, tradeId, status } = req.body;
    if (!description || !targetDate || !assignedTo) return res.status(400).json({ error: 'Description, target date and assigned user required' });
    const id = uuidv4();
    await query(
      'INSERT INTO tasks (id,description,target_date,assigned_to,assigned_by,customer_id,job_id,trade_id,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [id, description, targetDate, assignedTo, assignedBy || req.session.userId, customerId || null, jobId || null, tradeId || null, status || 'open']
    );
    const full = await query(`
      SELECT t.*, u.name AS assigned_to_name, ab.name AS assigned_by_name,
        c.name AS customer_name, j.title AS job_title, j.work_order_id,
        tr.company_name AS trade_name
      FROM tasks t
      LEFT JOIN users u   ON t.assigned_to  = u.id
      LEFT JOIN users ab  ON t.assigned_by   = ab.id
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN jobs j    ON t.job_id        = j.id
      LEFT JOIN trades tr ON t.trade_id      = tr.id
      WHERE t.id = $1`, [id]);
    res.status(201).json(normaliseTask(full.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const { description, targetDate, assignedTo, assignedBy, customerId, jobId, tradeId, status } = req.body;
    await query(
      'UPDATE tasks SET description=$1,target_date=$2,assigned_to=$3,assigned_by=$4,customer_id=$5,job_id=$6,trade_id=$7,status=$8 WHERE id=$9',
      [description, targetDate, assignedTo, assignedBy || req.session.userId, customerId || null, jobId || null, tradeId || null, status, req.params.id]
    );
    const full = await query(`
      SELECT t.*, u.name AS assigned_to_name, ab.name AS assigned_by_name,
        c.name AS customer_name, j.title AS job_title, j.work_order_id,
        tr.company_name AS trade_name
      FROM tasks t
      LEFT JOIN users u   ON t.assigned_to  = u.id
      LEFT JOIN users ab  ON t.assigned_by   = ab.id
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN jobs j    ON t.job_id        = j.id
      LEFT JOIN trades tr ON t.trade_id      = tr.id
      WHERE t.id = $1`, [req.params.id]);
    if (!full.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(normaliseTask(full.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try { await query('DELETE FROM tasks WHERE id=$1', [req.params.id]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});


// ─── Attachments ──────────────────────────────────────────────────────────────
const SUPABASE_URL    = process.env.SUPABASE_URL || '';
const SUPABASE_KEY    = process.env.SUPABASE_SERVICE_KEY || '';
const STORAGE_BUCKET  = process.env.SUPABASE_STORAGE_BUCKET || 'attachments';

// List attachments for an entity
app.get('/api/attachments', requireAuth, async (req, res) => {
  try {
    const { entityType, entityId } = req.query;
    if (!entityType || !entityId) return res.status(400).json({ error: 'entityType and entityId required' });
    const result = await query(
      'SELECT a.*, u.name as uploader_name FROM attachments a LEFT JOIN users u ON a.uploaded_by=u.id WHERE a.entity_type=$1 AND a.entity_id=$2 ORDER BY a.created_at DESC',
      [entityType, entityId]
    );
    res.json(result.rows.map(normaliseAttachment));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Upload one or more attachments
app.post('/api/attachments', requireAuth, upload.array('files', 20), async (req, res) => {
  try {
    const { entityType, entityId } = req.body;
    if (!entityType || !entityId) return res.status(400).json({ error: 'entityType and entityId required' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files provided' });
    if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(500).json({ error: 'Supabase storage not configured. Set SUPABASE_URL, SUPABASE_SERVICE_KEY and SUPABASE_STORAGE_BUCKET env vars.' });

    const saved = [];
    for (const file of req.files) {
      const ext = path.extname(file.originalname);
      const fileId = uuidv4();
      const storagePath = entityType + '/' + entityId + '/' + fileId + ext;

      // Upload to Supabase Storage
      const uploadRes = await fetch(
        SUPABASE_URL + '/storage/v1/object/' + STORAGE_BUCKET + '/' + storagePath,
        {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + SUPABASE_KEY,
            'Content-Type': file.mimetype,
            'x-upsert': 'false'
          },
          body: file.buffer
        }
      );
      if (!uploadRes.ok) {
        const err = await uploadRes.text();
        console.error('Supabase upload error:', err);
        return res.status(500).json({ error: 'Upload failed for ' + file.originalname + ': ' + err });
      }

      const publicUrl = SUPABASE_URL + '/storage/v1/object/public/' + STORAGE_BUCKET + '/' + storagePath;

      const isCompliance = req.body.isCompliance === 'true' || req.body.isCompliance === true;
      const expiryDate   = req.body.expiryDate || null;

      const id = uuidv4();
      await query(
        'INSERT INTO attachments (id, entity_type, entity_id, file_name, file_size, mime_type, storage_path, public_url, uploaded_by, is_compliance, expiry_date) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [id, entityType, entityId, file.originalname, file.size, file.mimetype, storagePath, publicUrl, req.session.userId, isCompliance, expiryDate || null]
      );
      const row = await query(
        'SELECT a.*, u.name as uploader_name FROM attachments a LEFT JOIN users u ON a.uploaded_by=u.id WHERE a.id=$1',
        [id]
      );
      const att = normaliseAttachment(row.rows[0]);

      // Auto-create renewal task if compliance doc with expiry date on a subcontractor
      if (isCompliance && expiryDate && entityType === 'trade') {
        try {
          const taskId = uuidv4();
          const taskDesc = 'Review compliance/accreditation document: "' + file.originalname + '" for subcontractor — expiry date ' + expiryDate;
          await query(
            'INSERT INTO tasks (id,description,target_date,assigned_to,assigned_by,trade_id,status) VALUES ($1,$2,$3,$4,$5,$6,$7)',
            [taskId, taskDesc, expiryDate, req.session.userId, req.session.userId, entityId, 'open']
          );
          att.renewalTaskCreated = true;
        } catch (taskErr) {
          console.error('Failed to create renewal task:', taskErr.message);
        }
      }

      saved.push(att);
    }
    res.status(201).json(saved);
  } catch (e) { console.error('Attachment upload error:', e); res.status(500).json({ error: e.message }); }
});

// Delete an attachment
app.delete('/api/attachments/:id', requireAuth, async (req, res) => {
  try {
    const row = await query('SELECT * FROM attachments WHERE id=$1', [req.params.id]);
    if (!row.rows.length) return res.status(404).json({ error: 'Not found' });
    const att = row.rows[0];

    if (SUPABASE_URL && SUPABASE_KEY) {
      await fetch(
        SUPABASE_URL + '/storage/v1/object/' + STORAGE_BUCKET + '/' + att.storage_path,
        { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + SUPABASE_KEY } }
      );
    }
    await query('DELETE FROM attachments WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// ─── Purchase Orders ──────────────────────────────────────────────────────────

// Generate next PO number
async function nextPoNumber() {
  const r = await query("SELECT po_number FROM purchase_orders ORDER BY created_at DESC LIMIT 1");
  if (!r.rows.length) return 'PO-0001';
  const last = r.rows[0].po_number;
  const m = last.match(/(\d+)$/);
  const n = m ? parseInt(m[1]) + 1 : 1;
  return 'PO-' + String(n).padStart(4, '0');
}

// Normalise PO (with items joined)
function normalisePO(r, items) {
  return {
    id: r.id, poNumber: r.po_number, jobId: r.job_id, tradeId: r.trade_id,
    tradeName: r.trade_name || null, tradeEmail: r.trade_email || null,
    tradeAddress: r.trade_address || null, tradeContact: r.trade_contact || null,
    jobTitle: r.job_title || null, workOrderId: r.work_order_id || null,
    customerName: r.customer_name || null, addressLabel: r.address_label || null,
    status: r.status, issueDate: r.issue_date ? r.issue_date.toISOString().split('T')[0] : '',
    instructions: r.instructions || '', notes: r.notes || '',
    createdBy: r.created_by, createdByName: r.created_by_name || null,
    createdAt: r.created_at, updatedAt: r.updated_at,
    items: (items || []).map(i => ({
      id: i.id, description: i.description,
      quantity: parseFloat(i.quantity), unitCost: parseFloat(i.unit_cost),
      vatRate: parseFloat(i.vat_rate), sortOrder: i.sort_order
    }))
  };
}

const PO_JOIN = `
  SELECT p.*,
    t.company_name AS trade_name, t.contact_email AS trade_email,
    t.company_address AS trade_address, t.contact_name AS trade_contact,
    j.title AS job_title, j.work_order_id,
    c.name AS customer_name,
    COALESCE(a.label || ' – ' || a.line1, a.line1) || ', ' || a.postcode AS address_label,
    u.name AS created_by_name
  FROM purchase_orders p
  LEFT JOIN trades t   ON p.trade_id   = t.id
  LEFT JOIN jobs j     ON p.job_id     = j.id
  LEFT JOIN customers c ON j.customer_id = c.id
  LEFT JOIN addresses a ON j.address_id  = a.id
  LEFT JOIN users u    ON p.created_by  = u.id`;

// List POs for a job OR a trade
app.get('/api/purchase-orders', requireAuth, async (req, res) => {
  try {
    const { jobId, tradeId } = req.query;
    let where = '';
    const params = [];
    if (jobId)   { where = ' WHERE p.job_id = $1';   params.push(jobId); }
    else if (tradeId) { where = ' WHERE p.trade_id = $1'; params.push(tradeId); }
    const pos = await query(PO_JOIN + where + ' ORDER BY p.created_at DESC', params);
    const ids = pos.rows.map(r => r.id);
    let itemsMap = {};
    if (ids.length) {
      const items = await query(
        'SELECT * FROM po_items WHERE po_id = ANY($1) ORDER BY sort_order ASC',
        [ids]
      );
      items.rows.forEach(i => { if (!itemsMap[i.po_id]) itemsMap[i.po_id] = []; itemsMap[i.po_id].push(i); });
    }
    res.json(pos.rows.map(r => normalisePO(r, itemsMap[r.id] || [])));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PO Stats (for dashboard page) ────────────────────────────────────────────
app.get('/api/purchase-orders/stats', requireAuth, async (req, res) => {
  try {
    const [byStatus, byTrade, byMonth] = await Promise.all([
      query(`SELECT status, COUNT(*) as count,
               SUM((SELECT COALESCE(SUM(quantity*unit_cost*(1+vat_rate/100.0)),0) FROM po_items WHERE po_id=purchase_orders.id)) as total
             FROM purchase_orders GROUP BY status`),
      query(`SELECT t.company_name, COUNT(p.id) as count,
               SUM((SELECT COALESCE(SUM(quantity*unit_cost*(1+vat_rate/100.0)),0) FROM po_items WHERE po_id=p.id)) as total
             FROM purchase_orders p JOIN trades t ON p.trade_id=t.id
             GROUP BY t.company_name ORDER BY total DESC LIMIT 10`),
      query(`SELECT TO_CHAR(issue_date,'YYYY-MM') as month, COUNT(*) as count,
               SUM((SELECT COALESCE(SUM(quantity*unit_cost*(1+vat_rate/100.0)),0) FROM po_items WHERE po_id=purchase_orders.id)) as total
             FROM purchase_orders WHERE issue_date >= NOW()-INTERVAL '12 months'
             GROUP BY month ORDER BY month ASC`)
    ]);
    res.json({
      byStatus: byStatus.rows.map(r => ({ status: r.status, count: parseInt(r.count), total: parseFloat(r.total)||0 })),
      byTrade:  byTrade.rows.map(r  => ({ name: r.company_name, count: parseInt(r.count), total: parseFloat(r.total)||0 })),
      byMonth:  byMonth.rows.map(r  => ({ month: r.month, count: parseInt(r.count), total: parseFloat(r.total)||0 }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PO Download as DOCX ──────────────────────────────────────────────────────
app.get('/api/purchase-orders/:id/docx', requireAuth, async (req, res) => {
  try {
    const po = await query(PO_JOIN + ' WHERE p.id = $1', [req.params.id]);
    if (!po.rows.length) return res.status(404).json({ error: 'Not found' });
    const r = po.rows[0];
    const items = (await query('SELECT * FROM po_items WHERE po_id=$1 ORDER BY sort_order ASC', [req.params.id])).rows;

    const subtotal = items.reduce((s,i) => s + parseFloat(i.quantity)*parseFloat(i.unit_cost), 0);
    const vatTotal = items.reduce((s,i) => s + parseFloat(i.quantity)*parseFloat(i.unit_cost)*(parseFloat(i.vat_rate)/100), 0);
    const grandTotal = subtotal + vatTotal;

    const fmt = (n) => '£' + parseFloat(n||0).toLocaleString('en-GB', {minimumFractionDigits:2, maximumFractionDigits:2});
    const fmtD = (d) => d ? new Date(d).toLocaleDateString('en-GB') : '—';

    const noBorder = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
    const nb = { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder };
    const tb = { style: BorderStyle.SINGLE, size: 1, color: 'DDE3E8' };
    const tbs = { top: tb, bottom: tb, left: tb, right: tb };
    const mc = { top: 80, bottom: 80, left: 120, right: 120 };

    function dc(text, width, opts={}) {
      return new TableCell({
        children: [new Paragraph({ alignment: opts.center ? AlignmentType.CENTER : opts.right ? AlignmentType.RIGHT : AlignmentType.LEFT,
          children: [new TextRun({ text: String(text||''), size: opts.size||18, bold: opts.bold, color: opts.color||'1A2535', font: 'Arial' })] })],
        borders: opts.nb ? nb : tbs,
        shading: { fill: opts.fill||'FFFFFF', type: ShadingType.CLEAR },
        width: width ? { size: width, type: WidthType.DXA } : undefined,
        margins: mc
      });
    }

    function hc(text, width, fill='1C2B3A') {
      return new TableCell({
        children: [new Paragraph({ children: [new TextRun({ text, bold: true, size: 18, color: 'FFFFFF', font: 'Arial' })] })],
        borders: tbs, shading: { fill, type: ShadingType.CLEAR },
        width: { size: width, type: WidthType.DXA }, margins: mc
      });
    }

    const doc = new Document({
      styles: { default: { document: { run: { font: 'Arial', size: 20 } } } },
      sections: [{
        properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 } } },
        headers: { default: new Header({ children: [
          new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: '3DB54A', space: 4 } },
            spacing: { after: 120 },
            children: [
              new TextRun({ text: 'ADC Property Desk  ', bold: true, size: 20, color: '1A2535', font: 'Arial' }),
              new TextRun({ text: 'PURCHASE ORDER', size: 20, color: '6B3FA0', font: 'Arial' })
            ]})
        ]})},
        footers: { default: new Footer({ children: [
          new Paragraph({ border: { top: { style: BorderStyle.SINGLE, size: 2, color: 'DDE3E8', space: 4 } },
            spacing: { before: 80 },
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            children: [
              new TextRun({ text: 'ADC Property Desk  ·  Confidential', size: 16, color: '8898A8', font: 'Arial' }),
              new TextRun({ text: '\tPage ', size: 16, color: '8898A8', font: 'Arial' }),
              new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '8898A8', font: 'Arial' })
            ]})
        ]})},
        children: [
          // PO number + date header table
          new Table({ width: { size: 9760, type: WidthType.DXA }, columnWidths: [5800, 3960],
            rows: [new TableRow({ children: [
              new TableCell({ children: [
                new Paragraph({ children: [new TextRun({ text: r.po_number, bold: true, size: 40, color: '1A2535', font: 'Arial' })] }),
                new Paragraph({ spacing: { before: 40 }, children: [new TextRun({ text: 'PURCHASE ORDER', size: 20, color: '6B3FA0', font: 'Arial' })] })
              ], borders: nb, margins: mc }),
              new TableCell({ children: [
                new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: 'Issued: ' + fmtD(r.issue_date), size: 18, color: '4A5A6A', font: 'Arial' })] }),
                new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: 'Status: ' + (r.status||'').toUpperCase(), bold: true, size: 18, color: '3DB54A', font: 'Arial' })] })
              ], borders: nb, margins: mc })
            ]})]
          }),
          new Paragraph({ spacing: { before: 240, after: 0 }, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: '3DB54A' } }, children: [] }),
          new Paragraph({ spacing: { before: 240, after: 80 }, children: [] }),
          // To / For table
          new Table({ width: { size: 9760, type: WidthType.DXA }, columnWidths: [4880, 4880],
            rows: [new TableRow({ children: [
              new TableCell({ children: [
                new Paragraph({ children: [new TextRun({ text: 'TO (SUBCONTRACTOR)', size: 16, color: '8898A8', bold: true, font: 'Arial' })] }),
                new Paragraph({ spacing: { before: 60 }, children: [new TextRun({ text: r.trade_name||'', bold: true, size: 22, color: '1A2535', font: 'Arial' })] }),
                ...(r.trade_address ? [new Paragraph({ children: [new TextRun({ text: r.trade_address, size: 18, color: '4A5A6A', font: 'Arial' })] })] : []),
                ...(r.trade_contact ? [new Paragraph({ children: [new TextRun({ text: 'Contact: ' + r.trade_contact, size: 18, color: '4A5A6A', font: 'Arial' })] })] : []),
                ...(r.trade_email   ? [new Paragraph({ children: [new TextRun({ text: r.trade_email, size: 18, color: '3DB54A', font: 'Arial' })] })] : [])
              ], borders: nb, margins: mc }),
              new TableCell({ children: [
                new Paragraph({ children: [new TextRun({ text: 'FOR JOB', size: 16, color: '8898A8', bold: true, font: 'Arial' })] }),
                new Paragraph({ spacing: { before: 60 }, children: [new TextRun({ text: (r.work_order_id||'') + (r.job_title ? ' – ' + r.job_title : ''), bold: true, size: 20, color: '1A2535', font: 'Arial' })] }),
                ...(r.customer_name ? [new Paragraph({ children: [new TextRun({ text: 'Customer: ' + r.customer_name, size: 18, color: '4A5A6A', font: 'Arial' })] })] : []),
                ...(r.address_label ? [new Paragraph({ children: [new TextRun({ text: r.address_label, size: 18, color: '4A5A6A', font: 'Arial' })] })] : [])
              ], borders: nb, margins: mc })
            ]})]
          }),
          new Paragraph({ spacing: { before: 280, after: 80 }, children: [] }),
          // Items table
          new Table({ width: { size: 9760, type: WidthType.DXA }, columnWidths: [5000, 900, 1320, 820, 1720],
            rows: [
              new TableRow({ children: [hc('Description',5000,'1C2B3A'), hc('Qty',900,'1C2B3A'), hc('Unit Cost',1320,'1C2B3A'), hc('VAT',820,'1C2B3A'), hc('Line Total',1720,'1C2B3A')] }),
              ...items.map(i => {
                const net = parseFloat(i.quantity)*parseFloat(i.unit_cost);
                const vatAmt = net*(parseFloat(i.vat_rate)/100);
                return new TableRow({ children: [
                  dc(i.description, 5000),
                  dc(String(parseFloat(i.quantity)), 900, { center: true }),
                  dc(fmt(i.unit_cost), 1320, { right: true }),
                  dc(parseFloat(i.vat_rate)+'%', 820, { center: true }),
                  dc(fmt(net+vatAmt), 1720, { right: true })
                ]});
              }),
              // Subtotal
              new TableRow({ children: [
                new TableCell({ children: [new Paragraph({ children: [] })], columnSpan: 3, borders: tbs }),
                dc('Subtotal', 820, { right: true, fill: 'F4F6F8', bold: true }),
                dc(fmt(subtotal), 1720, { right: true, fill: 'F4F6F8' })
              ]}),
              new TableRow({ children: [
                new TableCell({ children: [new Paragraph({ children: [] })], columnSpan: 3, borders: tbs }),
                dc('VAT', 820, { right: true, fill: 'F4F6F8', bold: true }),
                dc(fmt(vatTotal), 1720, { right: true, fill: 'F4F6F8' })
              ]}),
              new TableRow({ children: [
                new TableCell({ children: [new Paragraph({ children: [] })], columnSpan: 3, borders: tbs }),
                dc('TOTAL', 820, { right: true, fill: '1C2B3A', bold: true, color: 'FFFFFF' }),
                dc(fmt(grandTotal), 1720, { right: true, fill: '3DB54A', bold: true, color: 'FFFFFF' })
              ]})
            ]
          }),
          // Instructions
          ...(r.instructions ? [
            new Paragraph({ spacing: { before: 320, after: 120 }, children: [new TextRun({ text: 'Instructions / Additional Details', bold: true, size: 22, color: '1A2535', font: 'Arial' })] }),
            new Paragraph({ children: [new TextRun({ text: r.instructions, size: 19, color: '4A5A6A', font: 'Arial' })] })
          ] : []),
          new Paragraph({ spacing: { before: 400 }, alignment: AlignmentType.CENTER, children: [
            new TextRun({ text: 'ADC Property Desk  ·  Generated ' + new Date().toLocaleDateString('en-GB'), size: 16, color: '8898A8', font: 'Arial' })
          ]})
        ]
      }]
    });

    const buffer = await Packer.toBuffer(doc);
    const filename = (r.po_number || 'PO') + '.docx';
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send(buffer);
  } catch (e) { console.error('DOCX error:', e); res.status(500).json({ error: e.message }); }
});

// Get single PO
app.get('/api/purchase-orders/:id', requireAuth, async (req, res) => {
  try {
    const po = await query(PO_JOIN + ' WHERE p.id = $1', [req.params.id]);
    if (!po.rows.length) return res.status(404).json({ error: 'Not found' });
    const items = await query('SELECT * FROM po_items WHERE po_id=$1 ORDER BY sort_order ASC', [req.params.id]);
    res.json(normalisePO(po.rows[0], items.rows));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Create PO
app.post('/api/purchase-orders', requireAuth, async (req, res) => {
  try {
    const { jobId, tradeId, issueDate, instructions, notes, items } = req.body;
    if (!jobId || !tradeId) return res.status(400).json({ error: 'jobId and tradeId required' });
    const poNumber = await nextPoNumber();
    const id = uuidv4();
    await query(
      'INSERT INTO purchase_orders (id,po_number,job_id,trade_id,status,issue_date,instructions,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [id, poNumber, jobId, tradeId, 'draft', issueDate || new Date().toISOString().split('T')[0], instructions||'', notes||'', req.session.userId]
    );
    if (items && items.length) {
      await Promise.all(items.map((item, idx) =>
        query('INSERT INTO po_items (id,po_id,description,quantity,unit_cost,vat_rate,sort_order) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [uuidv4(), id, item.description, item.quantity||1, item.unitCost||0, item.vatRate??20, idx])
      ));
    }
    const po = await query(PO_JOIN + ' WHERE p.id = $1', [id]);
    const poItems = await query('SELECT * FROM po_items WHERE po_id=$1 ORDER BY sort_order ASC', [id]);
    res.status(201).json(normalisePO(po.rows[0], poItems.rows));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update PO
app.put('/api/purchase-orders/:id', requireAuth, async (req, res) => {
  try {
    const { status, issueDate, instructions, notes, items } = req.body;
    await query(
      'UPDATE purchase_orders SET status=$1,issue_date=$2,instructions=$3,notes=$4,updated_at=NOW() WHERE id=$5',
      [status, issueDate, instructions||'', notes||'', req.params.id]
    );
    // Replace all items
    await query('DELETE FROM po_items WHERE po_id=$1', [req.params.id]);
    if (items && items.length) {
      await Promise.all(items.map((item, idx) =>
        query('INSERT INTO po_items (id,po_id,description,quantity,unit_cost,vat_rate,sort_order) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [uuidv4(), req.params.id, item.description, item.quantity||1, item.unitCost||0, item.vatRate??20, idx])
      ));
    }
    const po = await query(PO_JOIN + ' WHERE p.id = $1', [req.params.id]);
    if (!po.rows.length) return res.status(404).json({ error: 'Not found' });
    const poItems = await query('SELECT * FROM po_items WHERE po_id=$1 ORDER BY sort_order ASC', [req.params.id]);
    res.json(normalisePO(po.rows[0], poItems.rows));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete PO
app.delete('/api/purchase-orders/:id', requireAuth, async (req, res) => {
  try {
    await query('DELETE FROM po_items WHERE po_id=$1', [req.params.id]);
    await query('DELETE FROM purchase_orders WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});



// ─── Invoices ─────────────────────────────────────────────────────────────────

async function nextInvoiceNumber() {
  const r = await query("SELECT invoice_number FROM invoices ORDER BY created_at DESC LIMIT 1");
  if (!r.rows.length) return 'INV-0001';
  const last = r.rows[0].invoice_number;
  const m = last.match(/(\d+)$/);
  const n = m ? parseInt(m[1]) + 1 : 1;
  return 'INV-' + String(n).padStart(4, '0');
}

function normaliseInvoice(r, items) {
  return {
    id: r.id, invoiceNumber: r.invoice_number,
    jobId: r.job_id, customerId: r.customer_id,
    customerName: r.customer_name || null,
    customerEmail: r.customer_email || null,
    customerPhone: r.customer_phone || null,
    jobTitle: r.job_title || null, workOrderId: r.work_order_id || null,
    addressLabel: r.address_label || null,
    dateWorkCompleted: r.date_work_completed ? r.date_work_completed.toISOString().split('T')[0] : null,
    status: r.status,
    invoiceDate: r.invoice_date ? r.invoice_date.toISOString().split('T')[0] : '',
    paymentDue:  r.payment_due  ? r.payment_due.toISOString().split('T')[0]  : '',
    datePaid:    r.date_paid    ? r.date_paid.toISOString().split('T')[0]    : null,
    notes: r.notes || '',
    createdBy: r.created_by, createdByName: r.created_by_name || null,
    createdAt: r.created_at, updatedAt: r.updated_at,
    items: (items || []).map(i => ({
      id: i.id, description: i.description,
      quantity: parseFloat(i.quantity), unitCost: parseFloat(i.unit_cost),
      vatRate: parseFloat(i.vat_rate), sortOrder: i.sort_order
    }))
  };
}

const INV_JOIN = `
  SELECT i.*,
    c.name  AS customer_name, c.email AS customer_email, c.phone AS customer_phone,
    j.title AS job_title, j.work_order_id, j.date_work_completed,
    COALESCE(a.label || ' – ' || a.line1, a.line1) || ', ' || a.postcode AS address_label,
    u.name  AS created_by_name
  FROM invoices i
  LEFT JOIN customers c ON i.customer_id = c.id
  LEFT JOIN jobs j      ON i.job_id      = j.id
  LEFT JOIN addresses a ON j.address_id  = a.id
  LEFT JOIN users u     ON i.created_by  = u.id`;

// ── GET stats (MUST be before /:id) ──────────────────────────────────────────
app.get('/api/invoices/stats', requireAuth, async (req, res) => {
  try {
    const [byStatus, byCustomer, byMonth] = await Promise.all([
      query(`SELECT status, COUNT(*) as count,
               SUM((SELECT COALESCE(SUM(quantity*unit_cost*(1+vat_rate/100.0)),0)
                    FROM invoice_items WHERE invoice_id=invoices.id)) as total
             FROM invoices GROUP BY status`),
      query(`SELECT c.name, COUNT(i.id) as count,
               SUM((SELECT COALESCE(SUM(quantity*unit_cost*(1+vat_rate/100.0)),0)
                    FROM invoice_items WHERE invoice_id=i.id)) as total
             FROM invoices i JOIN customers c ON i.customer_id=c.id
             GROUP BY c.name ORDER BY total DESC LIMIT 10`),
      query(`SELECT TO_CHAR(invoice_date,'YYYY-MM') as month, COUNT(*) as count,
               SUM((SELECT COALESCE(SUM(quantity*unit_cost*(1+vat_rate/100.0)),0)
                    FROM invoice_items WHERE invoice_id=invoices.id)) as total
             FROM invoices WHERE invoice_date >= NOW()-INTERVAL '12 months'
             GROUP BY month ORDER BY month ASC`)
    ]);
    res.json({
      byStatus:   byStatus.rows.map(r   => ({ status: r.status,  count: parseInt(r.count), total: parseFloat(r.total)||0 })),
      byCustomer: byCustomer.rows.map(r => ({ name: r.name,      count: parseInt(r.count), total: parseFloat(r.total)||0 })),
      byMonth:    byMonth.rows.map(r    => ({ month: r.month,    count: parseInt(r.count), total: parseFloat(r.total)||0 }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET docx (MUST be before /:id) ───────────────────────────────────────────
app.get('/api/invoices/:id/docx', requireAuth, async (req, res) => {
  try {
    const inv = await query(INV_JOIN + ' WHERE i.id = $1', [req.params.id]);
    if (!inv.rows.length) return res.status(404).json({ error: 'Not found' });
    const r = inv.rows[0];
    const items = (await query('SELECT * FROM invoice_items WHERE invoice_id=$1 ORDER BY sort_order ASC', [req.params.id])).rows;

    const subtotal   = items.reduce((s,i) => s + parseFloat(i.quantity)*parseFloat(i.unit_cost), 0);
    const vatTotal   = items.reduce((s,i) => s + parseFloat(i.quantity)*parseFloat(i.unit_cost)*(parseFloat(i.vat_rate)/100), 0);
    const grandTotal = subtotal + vatTotal;
    const fmt  = n => '£' + parseFloat(n||0).toLocaleString('en-GB', {minimumFractionDigits:2, maximumFractionDigits:2});
    const fmtD = d => d ? new Date(d).toLocaleDateString('en-GB') : '—';

    const noBorder = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
    const nb  = { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder };
    const tb  = { style: BorderStyle.SINGLE, size: 1, color: 'DDE3E8' };
    const tbs = { top: tb, bottom: tb, left: tb, right: tb };
    const mc  = { top: 80, bottom: 80, left: 120, right: 120 };

    const dc = (text, width, opts={}) => new TableCell({
      children: [new Paragraph({ alignment: opts.center ? AlignmentType.CENTER : opts.right ? AlignmentType.RIGHT : AlignmentType.LEFT,
        children: [new TextRun({ text: String(text||''), size: opts.size||18, bold: opts.bold, color: opts.color||'1A2535', font: 'Arial' })] })],
      borders: opts.nb ? nb : tbs,
      shading: { fill: opts.fill||'FFFFFF', type: ShadingType.CLEAR },
      width: width ? { size: width, type: WidthType.DXA } : undefined,
      margins: mc
    });

    const hc = (text, width, fill='1C2B3A') => new TableCell({
      children: [new Paragraph({ children: [new TextRun({ text, bold: true, size: 18, color: 'FFFFFF', font: 'Arial' })] })],
      borders: tbs, shading: { fill, type: ShadingType.CLEAR },
      width: { size: width, type: WidthType.DXA }, margins: mc
    });

    const statusColor = { draft:'8898A8', sent:'2563EB', paid:'1A9467', overdue:'DC2626', cancelled:'9CA3AF' };

    const doc = new Document({
      styles: { default: { document: { run: { font: 'Arial', size: 20 } } } },
      sections: [{
        properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 } } },
        headers: { default: new Header({ children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: '3DB54A', space: 4 } },
          spacing: { after: 120 },
          children: [
            new TextRun({ text: 'ADC Property Desk  ', bold: true, size: 20, color: '1A2535', font: 'Arial' }),
            new TextRun({ text: 'INVOICE', size: 20, color: '6B3FA0', font: 'Arial' })
          ]
        })]}) },
        footers: { default: new Footer({ children: [new Paragraph({
          border: { top: { style: BorderStyle.SINGLE, size: 2, color: 'DDE3E8', space: 4 } },
          spacing: { before: 80 },
          tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
          children: [
            new TextRun({ text: 'ADC Property Desk  ·  Confidential', size: 16, color: '8898A8', font: 'Arial' }),
            new TextRun({ text: '\tPage ', size: 16, color: '8898A8', font: 'Arial' }),
            new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '8898A8', font: 'Arial' })
          ]
        })]}) },
        children: [
          new Table({ width: { size: 9760, type: WidthType.DXA }, columnWidths: [5800, 3960],
            rows: [new TableRow({ children: [
              new TableCell({ children: [
                new Paragraph({ children: [new TextRun({ text: r.invoice_number, bold: true, size: 40, color: '1A2535', font: 'Arial' })] }),
                new Paragraph({ spacing: { before: 40 }, children: [new TextRun({ text: 'INVOICE', size: 20, color: '6B3FA0', font: 'Arial' })] })
              ], borders: nb, margins: mc }),
              new TableCell({ children: [
                new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: 'Invoice Date: ' + fmtD(r.invoice_date), size: 18, color: '4A5A6A', font: 'Arial' })] }),
                new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: 'Payment Due: '  + fmtD(r.payment_due),  bold: true, size: 18, color: '1A2535', font: 'Arial' })] }),
                new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: (r.status||'').toUpperCase(), bold: true, size: 18, color: statusColor[r.status]||'8898A8', font: 'Arial' })] })
              ], borders: nb, margins: mc })
            ]})]
          }),
          new Paragraph({ spacing: { before: 240, after: 0 }, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: '3DB54A' } }, children: [] }),
          new Paragraph({ spacing: { before: 240, after: 80 }, children: [] }),
          new Table({ width: { size: 9760, type: WidthType.DXA }, columnWidths: [4880, 4880],
            rows: [new TableRow({ children: [
              new TableCell({ children: [
                new Paragraph({ children: [new TextRun({ text: 'TO (CUSTOMER)', size: 16, color: '8898A8', bold: true, font: 'Arial' })] }),
                new Paragraph({ spacing: { before: 60 }, children: [new TextRun({ text: r.customer_name||'', bold: true, size: 22, color: '1A2535', font: 'Arial' })] }),
                ...(r.customer_email ? [new Paragraph({ children: [new TextRun({ text: r.customer_email, size: 18, color: '3DB54A', font: 'Arial' })] })] : []),
                ...(r.customer_phone ? [new Paragraph({ children: [new TextRun({ text: r.customer_phone, size: 18, color: '4A5A6A', font: 'Arial' })] })] : [])
              ], borders: nb, margins: mc }),
              new TableCell({ children: [
                new Paragraph({ children: [new TextRun({ text: 'FOR JOB', size: 16, color: '8898A8', bold: true, font: 'Arial' })] }),
                new Paragraph({ spacing: { before: 60 }, children: [new TextRun({ text: (r.work_order_id||'') + (r.job_title ? ' – ' + r.job_title : ''), bold: true, size: 20, color: '1A2535', font: 'Arial' })] }),
                ...(r.address_label ? [new Paragraph({ children: [new TextRun({ text: r.address_label, size: 18, color: '4A5A6A', font: 'Arial' })] })] : []),
                ...(r.date_work_completed ? [new Paragraph({ children: [new TextRun({ text: 'Work Completed: ' + fmtD(r.date_work_completed), size: 18, color: '4A5A6A', font: 'Arial' })] })] : [])
              ], borders: nb, margins: mc })
            ]})]
          }),
          new Paragraph({ spacing: { before: 280, after: 80 }, children: [] }),
          new Table({ width: { size: 9760, type: WidthType.DXA }, columnWidths: [5000, 900, 1320, 820, 1720],
            rows: [
              new TableRow({ children: [hc('Description',5000), hc('Qty',900), hc('Unit Cost',1320), hc('VAT',820), hc('Line Total',1720)] }),
              ...items.map(i => {
                const net = parseFloat(i.quantity)*parseFloat(i.unit_cost);
                const vatAmt = net*(parseFloat(i.vat_rate)/100);
                return new TableRow({ children: [
                  dc(i.description,5000), dc(String(parseFloat(i.quantity)),900,{center:true}),
                  dc(fmt(i.unit_cost),1320,{right:true}), dc(parseFloat(i.vat_rate)+'%',820,{center:true}),
                  dc(fmt(net+vatAmt),1720,{right:true})
                ]});
              }),
              new TableRow({ children: [new TableCell({children:[new Paragraph({children:[]})],columnSpan:3,borders:tbs}), dc('Subtotal',820,{right:true,fill:'F4F6F8',bold:true}), dc(fmt(subtotal),1720,{right:true,fill:'F4F6F8'})] }),
              new TableRow({ children: [new TableCell({children:[new Paragraph({children:[]})],columnSpan:3,borders:tbs}), dc('VAT',820,{right:true,fill:'F4F6F8',bold:true}), dc(fmt(vatTotal),1720,{right:true,fill:'F4F6F8'})] }),
              new TableRow({ children: [new TableCell({children:[new Paragraph({children:[]})],columnSpan:3,borders:tbs}), dc('TOTAL DUE',820,{right:true,fill:'1C2B3A',bold:true,color:'FFFFFF'}), dc(fmt(grandTotal),1720,{right:true,fill:'3DB54A',bold:true,color:'FFFFFF'})] })
            ]
          }),
          ...(r.notes ? [
            new Paragraph({ spacing:{before:320,after:120}, children:[new TextRun({text:'Notes',bold:true,size:22,color:'1A2535',font:'Arial'})] }),
            new Paragraph({ children:[new TextRun({text:r.notes,size:19,color:'4A5A6A',font:'Arial'})] })
          ] : []),
          new Paragraph({ spacing:{before:400}, alignment:AlignmentType.CENTER, children:[
            new TextRun({text:'ADC Property Desk  ·  Generated ' + new Date().toLocaleDateString('en-GB'), size:16, color:'8898A8', font:'Arial'})
          ]})
        ]
      }]
    });

    const buffer = await Packer.toBuffer(doc);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', 'attachment; filename="' + r.invoice_number + '.docx"');
    res.send(buffer);
  } catch (e) { console.error('Invoice DOCX error:', e); res.status(500).json({ error: e.message }); }
});

// ── List invoices ─────────────────────────────────────────────────────────────
app.get('/api/invoices', requireAuth, async (req, res) => {
  try {
    const { jobId, customerId } = req.query;
    let where = ''; const params = [];
    if (jobId)      { where = ' WHERE i.job_id = $1';      params.push(jobId); }
    else if (customerId) { where = ' WHERE i.customer_id = $1'; params.push(customerId); }
    const invs = await query(INV_JOIN + where + ' ORDER BY i.created_at DESC', params);
    const ids = invs.rows.map(r => r.id);
    const itemsMap = {};
    if (ids.length) {
      const items = await query('SELECT * FROM invoice_items WHERE invoice_id = ANY($1) ORDER BY sort_order ASC', [ids]);
      items.rows.forEach(i => { if (!itemsMap[i.invoice_id]) itemsMap[i.invoice_id] = []; itemsMap[i.invoice_id].push(i); });
    }
    res.json(invs.rows.map(r => normaliseInvoice(r, itemsMap[r.id] || [])));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Get single invoice ────────────────────────────────────────────────────────
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  try {
    const inv = await query(INV_JOIN + ' WHERE i.id = $1', [req.params.id]);
    if (!inv.rows.length) return res.status(404).json({ error: 'Not found' });
    const items = await query('SELECT * FROM invoice_items WHERE invoice_id=$1 ORDER BY sort_order ASC', [req.params.id]);
    res.json(normaliseInvoice(inv.rows[0], items.rows));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Create invoice ────────────────────────────────────────────────────────────
app.post('/api/invoices', requireAuth, async (req, res) => {
  try {
    const { jobId, customerId, invoiceDate, paymentDue, status, notes, items } = req.body;
    if (!jobId || !customerId) return res.status(400).json({ error: 'jobId and customerId required' });
    const invoiceNumber = await nextInvoiceNumber();
    const id = uuidv4();
    const today = new Date().toISOString().split('T')[0];
    await query(
      'INSERT INTO invoices (id,invoice_number,job_id,customer_id,status,invoice_date,payment_due,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [id, invoiceNumber, jobId, customerId, status||'draft', invoiceDate||today, paymentDue||today, notes||'', req.session.userId]
    );
    if (items && items.length) {
      await Promise.all(items.map((item, idx) =>
        query('INSERT INTO invoice_items (id,invoice_id,description,quantity,unit_cost,vat_rate,sort_order) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [uuidv4(), id, item.description, item.quantity||1, item.unitCost||0, item.vatRate??20, idx])
      ));
    }
    const inv = await query(INV_JOIN + ' WHERE i.id = $1', [id]);
    const invItems = await query('SELECT * FROM invoice_items WHERE invoice_id=$1 ORDER BY sort_order ASC', [id]);
    res.status(201).json(normaliseInvoice(inv.rows[0], invItems.rows));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Update invoice ────────────────────────────────────────────────────────────
app.put('/api/invoices/:id', requireAuth, async (req, res) => {
  try {
    const { status, invoiceDate, paymentDue, datePaid, notes, items } = req.body;
    await query(
      'UPDATE invoices SET status=$1,invoice_date=$2,payment_due=$3,date_paid=$4,notes=$5,updated_at=NOW() WHERE id=$6',
      [status, invoiceDate, paymentDue, datePaid||null, notes||'', req.params.id]
    );
    await query('DELETE FROM invoice_items WHERE invoice_id=$1', [req.params.id]);
    if (items && items.length) {
      await Promise.all(items.map((item, idx) =>
        query('INSERT INTO invoice_items (id,invoice_id,description,quantity,unit_cost,vat_rate,sort_order) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [uuidv4(), req.params.id, item.description, item.quantity||1, item.unitCost||0, item.vatRate??20, idx])
      ));
    }
    const inv = await query(INV_JOIN + ' WHERE i.id = $1', [req.params.id]);
    if (!inv.rows.length) return res.status(404).json({ error: 'Not found' });
    const invItems = await query('SELECT * FROM invoice_items WHERE invoice_id=$1 ORDER BY sort_order ASC', [req.params.id]);
    res.json(normaliseInvoice(inv.rows[0], invItems.rows));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Delete invoice ────────────────────────────────────────────────────────────
app.delete('/api/invoices/:id', requireAuth, async (req, res) => {
  try {
    await query('DELETE FROM invoice_items WHERE invoice_id=$1', [req.params.id]);
    await query('DELETE FROM invoices WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// ─── AI Subcontractor Finder ──────────────────────────────────────────────────
app.post('/api/ai/find-subcontractors', requireAuth, async (req, res) => {
  try {
    const { postcode, address, jobTitle, actionRequired, tradeType } = req.body;
    if (!postcode && !address) return res.status(400).json({ error: 'Address or postcode required' });

    const location = postcode || address;
    const jobContext = tradeType
      ? tradeType
      : [jobTitle, actionRequired].filter(Boolean).join(' — ');

    const prompt = `You are a property management assistant helping find local subcontractors in the UK.

Search the web for real, currently trading subcontractor companies that offer "${jobContext}" services near ${location}, UK.

Find up to 6 real local businesses. For each one provide:
- Company name
- Full address
- Phone number
- Email address (if available)
- Website (if available)
- A brief description of their services relevant to "${jobContext}"
- The most relevant service category from this list that fits them best (pick the single best match):
  Gas – Domestic, Gas – Commercial, Plumbing, Electrics – Domestic, Electrics – Commercial, Joinery/Carpentry, Painting and Decorating, Roofing – Pitched, Roofing - Flat, General Maintenance and Repair, Drainage, Damp and Timber Works, Insulation, Fire Alarm, Security Systems, Flooring – Carpets and Lino, Tiling – Wall and Floor, Plastering, Rendering, General Builders, Landscaping, Pest Control, Locksmith, Other

Return ONLY valid JSON in this exact format, no other text:
{
  "results": [
    {
      "companyName": "string",
      "companyAddress": "string",
      "contactNumber": "string",
      "contactEmail": "string",
      "website": "string",
      "description": "string",
      "serviceCategory": "string"
    }
  ],
  "searchSummary": "brief one-line description of what was searched for and where"
}

If you cannot find real businesses with sufficient detail, return fewer results rather than fabricating details. Only include companies you found via web search with real contact information.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY || '',
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-opus-4-5',
        max_tokens: 2000,
        tools: [{ type: 'web_search_20250305', name: 'web_search' }],
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!response.ok) {
      const err = await response.text();
      return res.status(500).json({ error: 'AI search failed: ' + err });
    }

    const data = await response.json();

    // Extract text from response — may be after tool use blocks
    const textBlock = data.content && data.content.find(b => b.type === 'text');
    if (!textBlock) return res.status(500).json({ error: 'No response from AI' });

    // Parse JSON from response
    let parsed;
    try {
      const raw = textBlock.text.replace(/```json|```/g, '').trim();
      // Find the JSON object in the response
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON found');
      parsed = JSON.parse(jsonMatch[0]);
    } catch (e) {
      return res.status(500).json({ error: 'Could not parse AI response', raw: textBlock.text.substring(0, 500) });
    }

    res.json(parsed);
  } catch (e) {
    console.error('AI finder error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Catch-all & start ────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ─── Normalisers ──────────────────────────────────────────────────────────────
function normaliseCustomer(r) { return { id: r.id, type: r.type, name: r.name, email: r.email, phone: r.phone, contactName: r.contact_name || '', contactMobile: r.contact_mobile || '', createdAt: r.created_at }; }
function normaliseAddress(r) { return { id: r.id, customerId: r.customer_id, label: r.label, line1: r.line1, line2: r.line2, city: r.city, postcode: r.postcode }; }
function normaliseTrade(r) { return { id: r.id, status: r.status, companyName: r.company_name, companyAddress: r.company_address, contactName: r.contact_name, contactNumber: r.contact_number, contactEmail: r.contact_email, services: r.services || [] }; }
function normaliseJob(r, tradeIds, communications) {
  return {
    id: r.id, workOrderId: r.work_order_id, customerId: r.customer_id, addressId: r.address_id,
    title: r.title, status: r.status, actionRequired: r.action_required,
    dateReceived: fmtDate(r.date_received),
    deadlineForCompletion: fmtDate(r.deadline_for_completion),
    dateWorkCompleted: fmtDate(r.date_work_completed),
    dateInvoiced: fmtDate(r.date_invoiced),
    invoiceNumber: r.invoice_number,
    priceQuotedExclVat: r.price_quoted_excl_vat,
    priceQuotedInclVat: r.price_quoted_incl_vat,
    complianceStandard: r.compliance_standard,
    poSentSubcontractor: fmtDate(r.po_sent_subcontractor),
    chasedSubcontractor: fmtDate(r.chased_subcontractor),
    proposedDateTenant: fmtDate(r.proposed_date_tenant),
    bookedAdc: fmtDate(r.booked_adc),
    bookedSubcontractor: fmtDate(r.booked_subcontractor),
    tenantNotResponding: fmtDate(r.tenant_not_responding),
    onHold: fmtDate(r.on_hold),
    rejectedCancelled: fmtDate(r.rejected_cancelled),
    poChasedDate: fmtDate(r.po_chased_date),
    dateBooked: fmtDate(r.date_booked), datePaid: fmtDate(r.date_paid),
    createdAt: r.created_at, tradeIds, communications
  };
}
function normaliseComm(r) { return { id: r.id, jobId: r.job_id, note: r.note, author: r.author, date: r.date }; }
function normaliseTask(r) {
  return {
    id: r.id, description: r.description,
    targetDate: r.target_date ? r.target_date.toISOString().split('T')[0] : '',
    assignedTo: r.assigned_to, assignedToName: r.assigned_to_name,
    assignedBy: r.assigned_by, assignedByName: r.assigned_by_name,
    customerId: r.customer_id, customerName: r.customer_name,
    jobId: r.job_id, jobTitle: r.job_title, workOrderId: r.work_order_id,
    tradeId: r.trade_id, tradeName: r.trade_name || null,
    status: r.status, createdAt: r.created_at
  };
}
function fmtDate(d) { return d ? d.toISOString().split('T')[0] : ''; }
function normaliseAttachment(r) {
  return {
    id: r.id, entityType: r.entity_type, entityId: r.entity_id,
    fileName: r.file_name, fileSize: r.file_size, mimeType: r.mime_type,
    publicUrl: r.public_url, uploadedBy: r.uploaded_by,
    uploaderName: r.uploader_name || null,
    isCompliance: r.is_compliance || false,
    expiryDate: r.expiry_date ? r.expiry_date.toISOString().split('T')[0] : null,
    createdAt: r.created_at
  };
}
function orNull(v) { return v && v.trim() !== '' ? v : null; }
