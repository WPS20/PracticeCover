const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Database connection ──────────────────────────────────────────────────────
const dbUrl = (process.env.DATABASE_URL || '').replace(/^postgres:\/\//, 'postgresql://');

if (!dbUrl) {
  console.error('ERROR: DATABASE_URL environment variable is not set!');
  process.exit(1);
}

console.log('Connecting to database...');

const pool = new Pool({
  connectionString: dbUrl,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('ERROR: Failed to connect to database:', err.message);
  } else {
    console.log('SUCCESS: Database connected!');
    release();
  }
});

const query = async (text, params) => {
  try {
    return await pool.query(text, params);
  } catch (err) {
    console.error('DB Query Error:', err.message, '| Query:', text);
    throw err;
  }
};

// ─── API Routes ───────────────────────────────────────────────────────────────

// ── Customers ──────────────────────────────────────────────────────────────────
app.get('/api/customers', async (req, res) => {
  try {
    const result = await query('SELECT * FROM customers ORDER BY name ASC');
    res.json(result.rows.map(normaliseCustomer));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/customers', async (req, res) => {
  try {
    const { type, name, email, phone } = req.body;
    const id = uuidv4();
    const result = await query(
      'INSERT INTO customers (id, type, name, email, phone) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [id, type, name, email, phone]
    );
    res.status(201).json(normaliseCustomer(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/customers/:id', async (req, res) => {
  try {
    const { type, name, email, phone } = req.body;
    const result = await query(
      'UPDATE customers SET type=$1, name=$2, email=$3, phone=$4 WHERE id=$5 RETURNING *',
      [type, name, email, phone, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(normaliseCustomer(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    await query('DELETE FROM customers WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Addresses ──────────────────────────────────────────────────────────────────
app.get('/api/addresses', async (req, res) => {
  try {
    const { customerId } = req.query;
    const result = customerId
      ? await query('SELECT * FROM addresses WHERE customer_id=$1 ORDER BY label ASC', [customerId])
      : await query('SELECT * FROM addresses ORDER BY label ASC');
    res.json(result.rows.map(normaliseAddress));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/addresses', async (req, res) => {
  try {
    const { customerId, label, line1, line2, city, postcode } = req.body;
    const id = uuidv4();
    const result = await query(
      'INSERT INTO addresses (id, customer_id, label, line1, line2, city, postcode) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [id, customerId, label, line1, line2, city, postcode]
    );
    res.status(201).json(normaliseAddress(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/addresses/:id', async (req, res) => {
  try {
    const { customerId, label, line1, line2, city, postcode } = req.body;
    const result = await query(
      'UPDATE addresses SET customer_id=$1, label=$2, line1=$3, line2=$4, city=$5, postcode=$6 WHERE id=$7 RETURNING *',
      [customerId, label, line1, line2, city, postcode, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(normaliseAddress(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/addresses/:id', async (req, res) => {
  try {
    await query('DELETE FROM addresses WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Trades ─────────────────────────────────────────────────────────────────────
app.get('/api/trades', async (req, res) => {
  try {
    const result = await query('SELECT * FROM trades ORDER BY company_name ASC');
    res.json(result.rows.map(normaliseTrade));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/trades', async (req, res) => {
  try {
    const { status, companyName, companyAddress, contactName, contactNumber, contactEmail, services } = req.body;
    const id = uuidv4();
    const result = await query(
      'INSERT INTO trades (id, status, company_name, company_address, contact_name, contact_number, contact_email, services) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [id, status, companyName, companyAddress, contactName, contactNumber, contactEmail, services]
    );
    res.status(201).json(normaliseTrade(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/trades/:id', async (req, res) => {
  try {
    const { status, companyName, companyAddress, contactName, contactNumber, contactEmail, services } = req.body;
    const result = await query(
      'UPDATE trades SET status=$1, company_name=$2, company_address=$3, contact_name=$4, contact_number=$5, contact_email=$6, services=$7 WHERE id=$8 RETURNING *',
      [status, companyName, companyAddress, contactName, contactNumber, contactEmail, services, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(normaliseTrade(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/trades/:id', async (req, res) => {
  try {
    await query('DELETE FROM trades WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Jobs ───────────────────────────────────────────────────────────────────────
app.get('/api/jobs', async (req, res) => {
  try {
    const jobsResult = await query('SELECT * FROM jobs ORDER BY created_at DESC');
    const jobs = jobsResult.rows;

    const [tradesResult, commsResult] = await Promise.all([
      query('SELECT * FROM job_trades'),
      query('SELECT * FROM communications ORDER BY date ASC')
    ]);

    const jobTradesMap = {};
    tradesResult.rows.forEach(r => {
      if (!jobTradesMap[r.job_id]) jobTradesMap[r.job_id] = [];
      jobTradesMap[r.job_id].push(r.trade_id);
    });

    const commsMap = {};
    commsResult.rows.forEach(r => {
      if (!commsMap[r.job_id]) commsMap[r.job_id] = [];
      commsMap[r.job_id].push(normaliseComm(r));
    });

    res.json(jobs.map(j => normaliseJob(j, jobTradesMap[j.id] || [], commsMap[j.id] || [])));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/jobs', async (req, res) => {
  try {
    const { workOrderId, customerId, addressId, title, status, actionRequired,
            dateReceived, dateBooked, dateCompleted, dateInvoiced, datePaid, tradeIds } = req.body;
    const id = uuidv4();

    const result = await query(
      `INSERT INTO jobs (id, work_order_id, customer_id, address_id, title, status, action_required,
        date_received, date_booked, date_completed, date_invoiced, date_paid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [id, workOrderId, customerId, addressId, title, status || 'new', actionRequired,
       orNull(dateReceived), orNull(dateBooked), orNull(dateCompleted), orNull(dateInvoiced), orNull(datePaid)]
    );

    if (tradeIds && tradeIds.length) {
      await Promise.all(tradeIds.map(tid =>
        query('INSERT INTO job_trades (job_id, trade_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, tid])
      ));
    }

    res.status(201).json(normaliseJob(result.rows[0], tradeIds || [], []));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/jobs/:id', async (req, res) => {
  try {
    const { workOrderId, customerId, addressId, title, status, actionRequired,
            dateReceived, dateBooked, dateCompleted, dateInvoiced, datePaid, tradeIds } = req.body;

    const result = await query(
      `UPDATE jobs SET work_order_id=$1, customer_id=$2, address_id=$3, title=$4, status=$5,
        action_required=$6, date_received=$7, date_booked=$8, date_completed=$9,
        date_invoiced=$10, date_paid=$11 WHERE id=$12 RETURNING *`,
      [workOrderId, customerId, addressId, title, status, actionRequired,
       orNull(dateReceived), orNull(dateBooked), orNull(dateCompleted), orNull(dateInvoiced), orNull(datePaid),
       req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

    await query('DELETE FROM job_trades WHERE job_id=$1', [req.params.id]);
    if (tradeIds && tradeIds.length) {
      await Promise.all(tradeIds.map(tid =>
        query('INSERT INTO job_trades (job_id, trade_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.id, tid])
      ));
    }

    res.json(normaliseJob(result.rows[0], tradeIds || [], []));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/jobs/:id', async (req, res) => {
  try {
    await query('DELETE FROM jobs WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/jobs/:id/communications', async (req, res) => {
  try {
    const { note, author } = req.body;
    const id = uuidv4();
    const result = await query(
      'INSERT INTO communications (id, job_id, note, author) VALUES ($1,$2,$3,$4) RETURNING *',
      [id, req.params.id, note, author]
    );
    res.status(201).json(normaliseComm(result.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Stats ──────────────────────────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const [jobs, customers, trades, addresses] = await Promise.all([
      query('SELECT status FROM jobs'),
      query('SELECT COUNT(*) FROM customers'),
      query('SELECT COUNT(*) FROM trades'),
      query('SELECT COUNT(*) FROM addresses')
    ]);
    const byStatus = {};
    jobs.rows.forEach(j => { byStatus[j.status] = (byStatus[j.status] || 0) + 1; });
    res.json({
      totalJobs: jobs.rows.length,
      totalCustomers: parseInt(customers.rows[0].count),
      totalTrades: parseInt(trades.rows[0].count),
      totalAddresses: parseInt(addresses.rows[0].count),
      byStatus
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Catch-all ──────────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ─── Normalise DB rows to camelCase for the frontend ─────────────────────────
function normaliseCustomer(r) {
  return { id: r.id, type: r.type, name: r.name, email: r.email, phone: r.phone, createdAt: r.created_at };
}
function normaliseAddress(r) {
  return { id: r.id, customerId: r.customer_id, label: r.label, line1: r.line1, line2: r.line2, city: r.city, postcode: r.postcode };
}
function normaliseTrade(r) {
  return { id: r.id, status: r.status, companyName: r.company_name, companyAddress: r.company_address, contactName: r.contact_name, contactNumber: r.contact_number, contactEmail: r.contact_email, services: r.services || [] };
}
function normaliseJob(r, tradeIds, communications) {
  return {
    id: r.id, workOrderId: r.work_order_id, customerId: r.customer_id, addressId: r.address_id,
    title: r.title, status: r.status, actionRequired: r.action_required,
    dateReceived: fmtDate(r.date_received), dateBooked: fmtDate(r.date_booked),
    dateCompleted: fmtDate(r.date_completed), dateInvoiced: fmtDate(r.date_invoiced),
    datePaid: fmtDate(r.date_paid), createdAt: r.created_at,
    tradeIds, communications
  };
}
function normaliseComm(r) {
  return { id: r.id, jobId: r.job_id, note: r.note, author: r.author, date: r.date };
}
function fmtDate(d) { return d ? d.toISOString().split('T')[0] : ''; }
function orNull(v) { return v && v.trim() !== '' ? v : null; }
