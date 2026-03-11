const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const fetch = require('node-fetch');

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


// ─── Audit log helper ─────────────────────────────────────────────────────────
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
    const { type, name, email, phone } = req.body;
    const result = await query('INSERT INTO customers (id,type,name,email,phone) VALUES ($1,$2,$3,$4,$5) RETURNING *', [uuidv4(),type,name,email,phone]);
    const c = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'created', 'Customer', c.id, `Created customer "${c.name}"`);
    res.status(201).json(normaliseCustomer(c));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/customers/:id', requireAuth, async (req, res) => {
  try {
    const { type, name, email, phone } = req.body;
    const result = await query('UPDATE customers SET type=$1,name=$2,email=$3,phone=$4 WHERE id=$5 RETURNING *', [type,name,email,phone,req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const c = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'updated', 'Customer', c.id, `Updated customer "${c.name}"`);
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
    const result = await query('UPDATE addresses SET customer_id=$1,label=$2,line1=$3,line2=$4,city=$5,postcode=$6 WHERE id=$7 RETURNING *', [customerId,label,line1,line2,city,postcode,req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const a = result.rows[0];
    const desc = `Updated address "${[a.label, a.line1, a.postcode].filter(Boolean).join(', ')}"`;
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
    await auditLog(req.session.userId, req.session.name, 'created', 'Trade', t.id, `Created trade "${t.company_name}"`);
    res.status(201).json(normaliseTrade(t));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/trades/:id', requireAuth, async (req, res) => {
  try {
    const { status, companyName, companyAddress, contactName, contactNumber, contactEmail, services } = req.body;
    const result = await query('UPDATE trades SET status=$1,company_name=$2,company_address=$3,contact_name=$4,contact_number=$5,contact_email=$6,services=$7 WHERE id=$8 RETURNING *', [status,companyName,companyAddress,contactName,contactNumber,contactEmail,services,req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const t = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'updated', 'Trade', t.id, `Updated trade "${t.company_name}"`);
    res.json(normaliseTrade(t));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/trades/:id', requireAuth, async (req, res) => {
  try {
    const existing = await query('SELECT company_name FROM trades WHERE id=$1', [req.params.id]);
    const name = existing.rows[0]?.company_name || req.params.id;
    await query('DELETE FROM trades WHERE id=$1', [req.params.id]);
    await auditLog(req.session.userId, req.session.name, 'deleted', 'Trade', req.params.id, `Deleted trade "${name}"`);
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
    await auditLog(req.session.userId, req.session.name, 'updated', 'Job', j.id, `Updated job "${j.title}" (${j.work_order_id}) — status: ${j.status}`);
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
        u.name  AS assigned_to_name,
        ab.name AS assigned_by_name,
        c.name  AS customer_name,
        j.title AS job_title, j.work_order_id
      FROM tasks t
      LEFT JOIN users u  ON t.assigned_to = u.id
      LEFT JOIN users ab ON t.assigned_by  = ab.id
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN jobs j ON t.job_id = j.id`;
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
    const { description, targetDate, assignedTo, assignedBy, customerId, jobId, status } = req.body;
    if (!description || !targetDate || !assignedTo) return res.status(400).json({ error: 'Description, target date and assigned user required' });
    const id = uuidv4();
    await query(
      'INSERT INTO tasks (id,description,target_date,assigned_to,assigned_by,customer_id,job_id,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, description, targetDate, assignedTo, assignedBy || req.session.userId, customerId || null, jobId || null, status || 'open']
    );
    const full = await query(`
      SELECT t.*, u.name AS assigned_to_name, ab.name AS assigned_by_name,
        c.name AS customer_name, j.title AS job_title, j.work_order_id
      FROM tasks t
      LEFT JOIN users u  ON t.assigned_to = u.id
      LEFT JOIN users ab ON t.assigned_by = ab.id
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN jobs j ON t.job_id = j.id
      WHERE t.id = $1`, [id]);
    res.status(201).json(normaliseTask(full.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const { description, targetDate, assignedTo, assignedBy, customerId, jobId, status } = req.body;
    await query(
      'UPDATE tasks SET description=$1,target_date=$2,assigned_to=$3,assigned_by=$4,customer_id=$5,job_id=$6,status=$7 WHERE id=$8',
      [description, targetDate, assignedTo, assignedBy || req.session.userId, customerId || null, jobId || null, status, req.params.id]
    );
    const full = await query(`
      SELECT t.*, u.name AS assigned_to_name, ab.name AS assigned_by_name,
        c.name AS customer_name, j.title AS job_title, j.work_order_id
      FROM tasks t
      LEFT JOIN users u  ON t.assigned_to = u.id
      LEFT JOIN users ab ON t.assigned_by = ab.id
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN jobs j ON t.job_id = j.id
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

      const id = uuidv4();
      await query(
        'INSERT INTO attachments (id, entity_type, entity_id, file_name, file_size, mime_type, storage_path, public_url, uploaded_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [id, entityType, entityId, file.originalname, file.size, file.mimetype, storagePath, publicUrl, req.session.userId]
      );
      const row = await query(
        'SELECT a.*, u.name as uploader_name FROM attachments a LEFT JOIN users u ON a.uploaded_by=u.id WHERE a.id=$1',
        [id]
      );
      saved.push(normaliseAttachment(row.rows[0]));
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

// ─── Catch-all & start ────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ─── Normalisers ──────────────────────────────────────────────────────────────
function normaliseCustomer(r) { return { id: r.id, type: r.type, name: r.name, email: r.email, phone: r.phone, createdAt: r.created_at }; }
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
    createdAt: r.created_at
  };
}
function orNull(v) { return v && v.trim() !== '' ? v : null; }
