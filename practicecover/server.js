const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
// Node 18+ has fetch built-in — no need for node-fetch

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

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
    const {
      type, name, email, phone, contactName, contactMobile,
      practiceName, status, ernNumber, ernExempt, yearEstablished, numSubsidiaries,
      corrAddressLine1, corrAddressLine2, corrCity, corrCounty, corrCountry, corrPostcode,
      businessDescription, entityType
    } = req.body;
    const result = await query(
      `INSERT INTO customers
        (id,type,name,email,phone,contact_name,contact_mobile,
         practice_name,status,ern_number,ern_exempt,year_established,num_subsidiaries,
         corr_address_line1,corr_address_line2,corr_city,corr_county,corr_country,corr_postcode,
         business_description,entity_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
       RETURNING *`,
      [uuidv4(),type,name,email,phone,contactName||null,contactMobile||null,
       practiceName||null,status||'active',ernNumber||null,ernExempt||'no',
       yearEstablished||null,numSubsidiaries!=null?numSubsidiaries:0,
       corrAddressLine1||null,corrAddressLine2||null,corrCity||null,corrCounty||null,
       corrCountry||'United Kingdom',corrPostcode||null,
       businessDescription||null,entityType||null]
    );
    const c = result.rows[0];
    await auditLog(req.session.userId, req.session.name, 'created', 'Customer', c.id, `Created customer "${c.name}"`);
    res.status(201).json(normaliseCustomer(c));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/customers/:id', requireAuth, async (req, res) => {
  try {
    const {
      type, name, email, phone, contactName, contactMobile,
      practiceName, status, ernNumber, ernExempt, yearEstablished, numSubsidiaries,
      corrAddressLine1, corrAddressLine2, corrCity, corrCounty, corrCountry, corrPostcode,
      businessDescription, entityType
    } = req.body;
    const before = (await query('SELECT * FROM customers WHERE id=$1', [req.params.id])).rows[0];
    const result = await query(
      `UPDATE customers SET
        type=$1,name=$2,email=$3,phone=$4,contact_name=$5,contact_mobile=$6,
        practice_name=$7,status=$8,ern_number=$9,ern_exempt=$10,year_established=$11,num_subsidiaries=$12,
        corr_address_line1=$13,corr_address_line2=$14,corr_city=$15,corr_county=$16,
        corr_country=$17,corr_postcode=$18,business_description=$19,entity_type=$20
       WHERE id=$21 RETURNING *`,
      [type,name,email,phone,contactName||null,contactMobile||null,
       practiceName||null,status||'active',ernNumber||null,ernExempt||'no',
       yearEstablished||null,numSubsidiaries!=null?numSubsidiaries:0,
       corrAddressLine1||null,corrAddressLine2||null,corrCity||null,corrCounty||null,
       corrCountry||'United Kingdom',corrPostcode||null,
       businessDescription||null,entityType||null,
       req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const c = result.rows[0];
    const changes = before ? diffFields(
      { name: before.name, email: before.email, phone: before.phone, practice: before.practice_name, status: before.status },
      { name: c.name, email: c.email, phone: c.phone, practice: c.practice_name, status: c.status },
      { name: 'Name', email: 'Email', phone: 'Phone', practice: 'Practice Name', status: 'Status' }
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
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [customers, users] = await Promise.all([
      query('SELECT status FROM customers'),
      query('SELECT COUNT(*) FROM users WHERE active = true'),
    ]);
    const totalCustomers = customers.rows.length;
    const activeCustomers = customers.rows.filter(c => c.status === 'active').length;
    const prospectCustomers = customers.rows.filter(c => c.status === 'prospect').length;
    const totalUsers = parseInt(users.rows[0].count);
    res.json({ totalCustomers, activeCustomers, prospectCustomers, totalUsers });
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
// ─── Attachments ──────────────────────────────────────────────────────────────


// List attachments for an entity
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
// ─── PO Stats (for dashboard page) ────────────────────────────────────────────
// ─── PO Download as DOCX ──────────────────────────────────────────────────────
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
// ── GET docx (MUST be before /:id) ───────────────────────────────────────────
// ── List invoices ─────────────────────────────────────────────────────────────
// ── Get single invoice ────────────────────────────────────────────────────────
// ── Create invoice ────────────────────────────────────────────────────────────
// ── Update invoice ────────────────────────────────────────────────────────────
// ── Delete invoice ────────────────────────────────────────────────────────────
// ─── AI Subcontractor Finder ──────────────────────────────────────────────────
// ─── Quotes ───────────────────────────────────────────────────────────────────
async function nextQuoteRef() {
  const r = await query("SELECT quote_ref FROM quotes ORDER BY created_at DESC LIMIT 1");
  if (!r.rows.length) return 'QT-0001';
  const last = r.rows[0].quote_ref || 'QT-0000';
  const m = last.match(/(\d+)$/);
  const n = m ? parseInt(m[1]) + 1 : 1;
  return 'QT-' + String(n).padStart(4, '0');
}

function normaliseQuote(r) {
  return {
    id: r.id, quoteRef: r.quote_ref, status: r.status,
    // Step 1
    renewalDate: r.renewal_date ? r.renewal_date.toISOString().split('T')[0] : null,
    quoteType: r.quote_type, previousInsurer: r.previous_insurer,
    fullName: r.full_name, contactName: r.contact_name,
    telephone: r.telephone, mobile: r.mobile, email: r.email,
    addrName: r.addr_name, addrLine1: r.addr_line1, addrLine2: r.addr_line2,
    addrTown: r.addr_town, addrCounty: r.addr_county,
    addrCountry: r.addr_country, addrPostcode: r.addr_postcode,
    // Step 2
    noneOfBelow: r.none_of_below,
    decl1: r.decl1, decl2: r.decl2, decl3: r.decl3,
    decl4: r.decl4, decl5: r.decl5, decl6: r.decl6,
    yearsSinceLastClaim: r.years_since_last_claim,
    claims: r.claims || [],
    // Step 3
    dayOneCover: r.day_one_cover, excess: r.excess, fidelity: r.fidelity,
    // Step 4
    dirUnits: r.dir_units, dirFulltime: r.dir_fulltime, dirParttime: r.dir_parttime,
    empUnits: r.emp_units, empFulltime: r.emp_fulltime, empParttime: r.emp_parttime,
    // Step 5
    biCoverType: r.bi_cover_type, biAnnualSumInsured: r.bi_annual_sum_insured,
    biCoverPeriod: r.bi_cover_period, biBookDebtCover: r.bi_book_debt_cover,
    // Step 6
    indemnityLimit: r.indemnity_limit, offsiteClinics: r.offsite_clinics,
    terrorismCover: r.terrorism_cover, materialDamage: r.material_damage,
    nonSelectionRule: r.non_selection_rule, terrorismPostcode: r.terrorism_postcode,
    anticipatedTurnover: r.anticipated_turnover,
    // Step 7
    numPremises: r.num_premises, country: r.country,
    // Premises
    premises: r.premises || [],
    // Meta
    premium: r.premium, validUntil: r.valid_until ? r.valid_until.toISOString().split('T')[0] : null,
    createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

app.get('/api/quotes', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM quotes ORDER BY created_at DESC');
    res.json(result.rows.map(normaliseQuote));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/quotes/:id', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM quotes WHERE id=$1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(normaliseQuote(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/quotes', requireAuth, async (req, res) => {
  try {
    const d = req.body;
    const quoteRef = await nextQuoteRef();
    const result = await query(`
      INSERT INTO quotes (
        id, quote_ref, status,
        renewal_date, quote_type, previous_insurer,
        full_name, contact_name, telephone, mobile, email,
        addr_name, addr_line1, addr_line2, addr_town, addr_county, addr_country, addr_postcode,
        none_of_below, decl1, decl2, decl3, decl4, decl5, decl6,
        years_since_last_claim, claims,
        day_one_cover, excess, fidelity,
        dir_units, dir_fulltime, dir_parttime, emp_units, emp_fulltime, emp_parttime,
        bi_cover_type, bi_annual_sum_insured, bi_cover_period, bi_book_debt_cover,
        indemnity_limit, offsite_clinics, terrorism_cover, material_damage,
        non_selection_rule, terrorism_postcode, anticipated_turnover,
        num_premises, country, premises, premium, valid_until, created_by
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
        $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,
        $37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52,$53
      ) RETURNING *`,
      [
        uuidv4(), quoteRef, d.status || 'draft',
        d.renewalDate || null, d.quoteType || null, d.previousInsurer || null,
        d.fullName || null, d.contactName || null, d.telephone || null, d.mobile || null, d.email || null,
        d.addrName || null, d.addrLine1 || null, d.addrLine2 || null, d.addrTown || null,
        d.addrCounty || null, d.addrCountry || null, d.addrPostcode || null,
        d.noneOfBelow || 'Yes', d.decl1 || 'No', d.decl2 || 'No', d.decl3 || 'No',
        d.decl4 || 'No', d.decl5 || 'No', d.decl6 || 'No',
        d.yearsSinceLastClaim || '0', JSON.stringify(d.claims || []),
        d.dayOneCover || '0', d.excess || '£200', d.fidelity || '£0',
        d.dirUnits || 0, d.dirFulltime || 0, d.dirParttime || 0,
        d.empUnits || 0, d.empFulltime || 0, d.empParttime || 0,
        d.biCoverType || null, d.biAnnualSumInsured || 0, d.biCoverPeriod || '24', d.biBookDebtCover || 10000,
        d.indemnityLimit || '£5,000,000', d.offsiteClinics || 0,
        d.terrorismCover || 'No', d.materialDamage || null,
        d.nonSelectionRule || null, d.terrorismPostcode || null, d.anticipatedTurnover || 0,
        d.numPremises || 1, d.country || 'UK', JSON.stringify(d.premises || []),
        d.premium || null, d.validUntil || null, req.session.userId
      ]
    );
    await auditLog(req.session.userId, req.session.name, 'created', 'Quote', result.rows[0].id, `Created quote ${quoteRef}`);
    res.status(201).json(normaliseQuote(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/quotes/:id', requireAuth, async (req, res) => {
  try {
    const d = req.body;
    const result = await query(`
      UPDATE quotes SET
        status=$1, renewal_date=$2, quote_type=$3, previous_insurer=$4,
        full_name=$5, contact_name=$6, telephone=$7, mobile=$8, email=$9,
        addr_name=$10, addr_line1=$11, addr_line2=$12, addr_town=$13, addr_county=$14,
        addr_country=$15, addr_postcode=$16,
        none_of_below=$17, decl1=$18, decl2=$19, decl3=$20, decl4=$21, decl5=$22, decl6=$23,
        years_since_last_claim=$24, claims=$25,
        day_one_cover=$26, excess=$27, fidelity=$28,
        dir_units=$29, dir_fulltime=$30, dir_parttime=$31,
        emp_units=$32, emp_fulltime=$33, emp_parttime=$34,
        bi_cover_type=$35, bi_annual_sum_insured=$36, bi_cover_period=$37, bi_book_debt_cover=$38,
        indemnity_limit=$39, offsite_clinics=$40, terrorism_cover=$41, material_damage=$42,
        non_selection_rule=$43, terrorism_postcode=$44, anticipated_turnover=$45,
        num_premises=$46, country=$47, premises=$48, premium=$49, valid_until=$50,
        updated_at=NOW()
      WHERE id=$51 RETURNING *`,
      [
        d.status || 'draft', d.renewalDate || null, d.quoteType || null, d.previousInsurer || null,
        d.fullName || null, d.contactName || null, d.telephone || null, d.mobile || null, d.email || null,
        d.addrName || null, d.addrLine1 || null, d.addrLine2 || null, d.addrTown || null,
        d.addrCounty || null, d.addrCountry || null, d.addrPostcode || null,
        d.noneOfBelow || 'Yes', d.decl1 || 'No', d.decl2 || 'No', d.decl3 || 'No',
        d.decl4 || 'No', d.decl5 || 'No', d.decl6 || 'No',
        d.yearsSinceLastClaim || '0', JSON.stringify(d.claims || []),
        d.dayOneCover || '0', d.excess || '£200', d.fidelity || '£0',
        d.dirUnits || 0, d.dirFulltime || 0, d.dirParttime || 0,
        d.empUnits || 0, d.empFulltime || 0, d.empParttime || 0,
        d.biCoverType || null, d.biAnnualSumInsured || 0, d.biCoverPeriod || '24', d.biBookDebtCover || 10000,
        d.indemnityLimit || '£5,000,000', d.offsiteClinics || 0,
        d.terrorismCover || 'No', d.materialDamage || null,
        d.nonSelectionRule || null, d.terrorismPostcode || null, d.anticipatedTurnover || 0,
        d.numPremises || 1, d.country || 'UK', JSON.stringify(d.premises || []),
        d.premium || null, d.validUntil || null,
        req.params.id
      ]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    await auditLog(req.session.userId, req.session.name, 'updated', 'Quote', req.params.id, `Updated quote ${result.rows[0].quote_ref}`);
    res.json(normaliseQuote(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/quotes/:id', requireAuth, async (req, res) => {
  try {
    const existing = await query('SELECT quote_ref FROM quotes WHERE id=$1', [req.params.id]);
    const ref = existing.rows[0]?.quote_ref || req.params.id;
    await query('DELETE FROM quotes WHERE id=$1', [req.params.id]);
    await auditLog(req.session.userId, req.session.name, 'deleted', 'Quote', req.params.id, `Deleted quote ${ref}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Catch-all & start ────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ─── Normalisers ──────────────────────────────────────────────────────────────
function normaliseCustomer(r) {
  return {
    id: r.id,
    type: r.type,
    name: r.name,
    email: r.email,
    phone: r.phone,
    contactName: r.contact_name || '',
    contactMobile: r.contact_mobile || '',
    createdAt: r.created_at,
    // PracticeCover fields
    practiceName:        r.practice_name        || '',
    status:              r.status               || 'active',
    ernNumber:           r.ern_number           || '',
    ernExempt:           r.ern_exempt           || 'no',
    yearEstablished:     r.year_established     || null,
    numSubsidiaries:     r.num_subsidiaries     != null ? r.num_subsidiaries : 0,
    corrAddressLine1:    r.corr_address_line1   || '',
    corrAddressLine2:    r.corr_address_line2   || '',
    corrCity:            r.corr_city            || '',
    corrCounty:          r.corr_county          || '',
    corrCountry:         r.corr_country         || 'United Kingdom',
    corrPostcode:        r.corr_postcode        || '',
    businessDescription: r.business_description || '',
    entityType:          r.entity_type          || '',
  };
}
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
