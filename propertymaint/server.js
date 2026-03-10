const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-memory data store ────────────────────────────────────────────────────
let db = {
  customers: [],
  addresses: [],
  jobs: [],
  trades: []
};

// Seed some initial data
db.customers.push(
  { id: 'c1', type: 'managing_agent', name: 'Apex Property Management', email: 'admin@apexpm.co.uk', phone: '020 7946 0001', createdAt: new Date().toISOString() },
  { id: 'c2', type: 'individual', name: 'Sarah Mitchell', email: 'sarah.mitchell@email.com', phone: '07700 900123', createdAt: new Date().toISOString() }
);
db.addresses.push(
  { id: 'a1', customerId: 'c1', line1: '14 Harbour View', line2: '', city: 'Bristol', postcode: 'BS1 4RQ', label: 'Flat A' },
  { id: 'a2', customerId: 'c1', line1: '14 Harbour View', line2: '', city: 'Bristol', postcode: 'BS1 4RQ', label: 'Flat B' },
  { id: 'a3', customerId: 'c1', line1: '22 Clifton Down Road', line2: '', city: 'Bristol', postcode: 'BS8 2EH', label: 'Main Property' },
  { id: 'a4', customerId: 'c2', line1: '7 Maple Close', line2: '', city: 'Bath', postcode: 'BA2 6PT', label: 'Home' }
);
db.trades.push(
  { id: 't1', status: 'active', companyName: 'Swift Plumbing Ltd', companyAddress: '10 Trade Park, Bristol BS3 2AB', contactName: 'Mark Swift', contactNumber: '0117 946 0200', contactEmail: 'mark@swiftplumbing.co.uk', services: ['Plumbing', 'Heating'] },
  { id: 't2', status: 'active', companyName: 'PowerSafe Electrical', companyAddress: '5 Wiring Way, Bristol BS5 6TR', contactName: 'Jane Cooper', contactNumber: '0117 946 0300', contactEmail: 'jane@powersafe.co.uk', services: ['Electrical', 'PAT Testing'] }
);
db.jobs.push({
  id: 'j1', workOrderId: 'WO-001', customerId: 'c1', addressId: 'a1',
  title: 'Boiler Repair', status: 'in_progress',
  actionRequired: 'Replace faulty pressure valve on combi boiler',
  communications: [{ id: uuidv4(), date: new Date().toISOString(), note: 'Customer reported no hot water', author: 'System' }],
  tradeIds: ['t1'],
  dateReceived: '2025-01-10', dateBooked: '2025-01-12', dateCompleted: '', dateInvoiced: '', datePaid: '',
  createdAt: new Date().toISOString()
});

// ─── API Routes ───────────────────────────────────────────────────────────────

// Customers
app.get('/api/customers', (req, res) => res.json(db.customers));
app.post('/api/customers', (req, res) => {
  const c = { id: uuidv4(), ...req.body, createdAt: new Date().toISOString() };
  db.customers.push(c);
  res.status(201).json(c);
});
app.put('/api/customers/:id', (req, res) => {
  const idx = db.customers.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.customers[idx] = { ...db.customers[idx], ...req.body };
  res.json(db.customers[idx]);
});
app.delete('/api/customers/:id', (req, res) => {
  db.customers = db.customers.filter(c => c.id !== req.params.id);
  res.json({ success: true });
});

// Addresses
app.get('/api/addresses', (req, res) => {
  const { customerId } = req.query;
  res.json(customerId ? db.addresses.filter(a => a.customerId === customerId) : db.addresses);
});
app.post('/api/addresses', (req, res) => {
  const a = { id: uuidv4(), ...req.body };
  db.addresses.push(a);
  res.status(201).json(a);
});
app.put('/api/addresses/:id', (req, res) => {
  const idx = db.addresses.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.addresses[idx] = { ...db.addresses[idx], ...req.body };
  res.json(db.addresses[idx]);
});
app.delete('/api/addresses/:id', (req, res) => {
  db.addresses = db.addresses.filter(a => a.id !== req.params.id);
  res.json({ success: true });
});

// Trades
app.get('/api/trades', (req, res) => res.json(db.trades));
app.post('/api/trades', (req, res) => {
  const t = { id: uuidv4(), ...req.body };
  db.trades.push(t);
  res.status(201).json(t);
});
app.put('/api/trades/:id', (req, res) => {
  const idx = db.trades.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.trades[idx] = { ...db.trades[idx], ...req.body };
  res.json(db.trades[idx]);
});
app.delete('/api/trades/:id', (req, res) => {
  db.trades = db.trades.filter(t => t.id !== req.params.id);
  res.json({ success: true });
});

// Jobs
app.get('/api/jobs', (req, res) => res.json(db.jobs));
app.post('/api/jobs', (req, res) => {
  const j = { id: uuidv4(), communications: [], tradeIds: [], createdAt: new Date().toISOString(), ...req.body };
  db.jobs.push(j);
  res.status(201).json(j);
});
app.put('/api/jobs/:id', (req, res) => {
  const idx = db.jobs.findIndex(j => j.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.jobs[idx] = { ...db.jobs[idx], ...req.body };
  res.json(db.jobs[idx]);
});
app.delete('/api/jobs/:id', (req, res) => {
  db.jobs = db.jobs.filter(j => j.id !== req.params.id);
  res.json({ success: true });
});
app.post('/api/jobs/:id/communications', (req, res) => {
  const job = db.jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Not found' });
  const comm = { id: uuidv4(), date: new Date().toISOString(), ...req.body };
  job.communications.push(comm);
  res.status(201).json(comm);
});

// Dashboard stats
app.get('/api/stats', (req, res) => {
  const statuses = {};
  db.jobs.forEach(j => { statuses[j.status] = (statuses[j.status] || 0) + 1; });
  res.json({
    totalJobs: db.jobs.length,
    totalCustomers: db.customers.length,
    totalTrades: db.trades.length,
    totalAddresses: db.addresses.length,
    byStatus: statuses
  });
});

// Catch-all → SPA
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
