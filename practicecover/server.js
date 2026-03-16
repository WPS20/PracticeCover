'use strict';
const express   = require('express');
const path      = require('path');
const { v4: uuidv4 } = require('uuid');
const { Pool }  = require('pg');
const bcrypt    = require('bcryptjs');
const session   = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

const dbUrl = (process.env.DATABASE_URL || '').replace(/^postgres:\/\//, 'postgresql://');
if (!dbUrl) { console.error('DATABASE_URL not set'); process.exit(1); }
const pool = new Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
pool.connect((err, c, done) => { if (err) console.error('DB error:', err.message); else { console.log('DB connected'); done(); } });
const query = (t, p) => pool.query(t, p);

app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'pc-secret-2025',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 7*24*60*60*1000, secure: false }
}));

app.use(express.static(path.join(__dirname, 'public')));

const auth  = (q,r,n) => q.session?.userId ? n() : r.status(401).json({ error: 'Unauthorised' });
const admin = (q,r,n) => q.session?.role==='admin' ? n() : r.status(403).json({ error: 'Admin only' });

function normUser(r) { return { id:r.id, name:r.name, email:r.email, role:r.role, active:r.active, createdAt:r.created_at }; }

function normCustomer(r) {
  return {
    id:r.id, type:r.type||'', name:r.name||'', email:r.email||'', phone:r.phone||'',
    contactName:r.contact_name||'', contactMobile:r.contact_mobile||'',
    practiceName:r.practice_name||'', status:r.status||'active',
    ernNumber:r.ern_number||'', ernExempt:r.ern_exempt||'no',
    yearEstablished:r.year_established||null, numSubsidiaries:r.num_subsidiaries??0,
    corrAddressLine1:r.corr_address_line1||'', corrAddressLine2:r.corr_address_line2||'',
    corrCity:r.corr_city||'', corrCounty:r.corr_county||'',
    corrCountry:r.corr_country||'United Kingdom', corrPostcode:r.corr_postcode||'',
    businessDescription:r.business_description||'', entityType:r.entity_type||'', createdAt:r.created_at
  };
}

function normQuote(r) {
  return {
    id:r.id, quoteRef:r.quote_ref, status:r.status, customerId:r.customer_id||null,
    renewalDate:r.renewal_date, quoteType:r.quote_type, previousInsurer:r.previous_insurer,
    fullName:r.full_name||'', contactName:r.contact_name||'',
    telephone:r.telephone||'', mobile:r.mobile||'', email:r.email||'',
    addrName:r.addr_name||'', addrLine1:r.addr_line1||'', addrLine2:r.addr_line2||'',
    addrTown:r.addr_town||'', addrCounty:r.addr_county||'',
    addrCountry:r.addr_country||'', addrPostcode:r.addr_postcode||'',
    noneOfBelow:r.none_of_below||'Yes',
    decl1:r.decl1||'No', decl2:r.decl2||'No', decl3:r.decl3||'No',
    decl4:r.decl4||'No', decl5:r.decl5||'No', decl6:r.decl6||'No',
    yearsSinceLastClaim:r.years_since_last_claim||'0', claims:r.claims||[],
    dayOneCover:r.day_one_cover||'0', excess:r.excess||'£200', fidelity:r.fidelity||'£25000',
    dirUnits:r.dir_units||0, dirFulltime:r.dir_fulltime||0, dirParttime:r.dir_parttime||0,
    empUnits:r.emp_units||0, empFulltime:r.emp_fulltime||0, empParttime:r.emp_parttime||0,
    biCoverType:r.bi_cover_type||'Loss of Income', biAnnualSumInsured:r.bi_annual_sum_insured||0,
    biCoverPeriod:r.bi_cover_period||'24', biBookDebtCover:r.bi_book_debt_cover||10000,
    indemnityLimit:r.indemnity_limit||'£5000000', offsiteClinics:r.offsite_clinics||0,
    terrorismCover:r.terrorism_cover||'No', materialDamage:r.material_damage||null,
    nonSelectionRule:r.non_selection_rule||null, terrorismPostcode:r.terrorism_postcode||null,
    anticipatedTurnover:r.anticipated_turnover||0,
    numPremises:r.num_premises||1, country:r.country||'UK', premises:r.premises||[],
    premium:r.premium||null, validUntil:r.valid_until||null, createdAt:r.created_at
  };
}

// AUTH
app.get('/api/auth/me', (req,res) => {
  if (!req.session?.userId) return res.status(401).json({ error:'Not logged in' });
  res.json({ id:req.session.userId, name:req.session.name, role:req.session.role });
});
app.post('/api/auth/login', async(req,res) => {
  try {
    const { email, password } = req.body;
    const r = await query('SELECT * FROM users WHERE LOWER(email)=$1 AND active=true', [email.toLowerCase().trim()]);
    if (!r.rows.length) return res.status(401).json({ error:'Invalid credentials' });
    const u = r.rows[0];
    if (!await bcrypt.compare(password, u.password_hash)) return res.status(401).json({ error:'Invalid credentials' });
    req.session.userId=u.id; req.session.name=u.name; req.session.role=u.role;
    res.json({ id:u.id, name:u.name, role:u.role });
  } catch(e) { res.status(500).json({ error:e.message }); }
});
app.post('/api/auth/logout', (req,res) => { req.session.destroy(); res.json({ ok:true }); });

// USERS
app.get('/api/users', auth, async(req,res) => {
  try { res.json((await query('SELECT id,name,email,role,active,created_at FROM users ORDER BY name')).rows.map(normUser)); }
  catch(e) { res.status(500).json({ error:e.message }); }
});
app.post('/api/users', auth, admin, async(req,res) => {
  try {
    const { name, email, role, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const r = await query(
      'INSERT INTO users (id,name,email,role,password_hash,active) VALUES ($1,$2,$3,$4,$5,true) RETURNING id,name,email,role,active,created_at',
      [uuidv4(), name, email.toLowerCase(), role||'user', hash]
    );
    res.status(201).json(normUser(r.rows[0]));
  } catch(e) { res.status(500).json({ error:e.message }); }
});
app.put('/api/users/:id', auth, admin, async(req,res) => {
  try {
    const { name, email, role, active, password } = req.body;
    let r;
    if (password) {
      const hash = await bcrypt.hash(password,10);
      r = await query('UPDATE users SET name=$1,email=$2,role=$3,active=$4,password_hash=$5 WHERE id=$6 RETURNING id,name,email,role,active,created_at',[name,email.toLowerCase(),role,active,hash,req.params.id]);
    } else {
      r = await query('UPDATE users SET name=$1,email=$2,role=$3,active=$4 WHERE id=$5 RETURNING id,name,email,role,active,created_at',[name,email.toLowerCase(),role,active,req.params.id]);
    }
    if (!r.rows.length) return res.status(404).json({ error:'Not found' });
    res.json(normUser(r.rows[0]));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// CUSTOMERS
app.get('/api/customers', auth, async(req,res) => {
  try { res.json((await query('SELECT * FROM customers ORDER BY name ASC')).rows.map(normCustomer)); }
  catch(e) { res.status(500).json({ error:e.message }); }
});
app.post('/api/customers', auth, async(req,res) => {
  try {
    const d = req.body;
    const r = await query(
      `INSERT INTO customers (id,type,name,email,phone,contact_name,contact_mobile,practice_name,status,ern_number,ern_exempt,year_established,num_subsidiaries,corr_address_line1,corr_address_line2,corr_city,corr_county,corr_country,corr_postcode,business_description,entity_type) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING *`,
      [uuidv4(),d.type||'gp_practice',d.name,d.email||null,d.phone||null,d.contactName||null,d.contactMobile||null,d.practiceName||null,d.status||'active',d.ernNumber||null,d.ernExempt||'no',d.yearEstablished||null,d.numSubsidiaries??0,d.corrAddressLine1||null,d.corrAddressLine2||null,d.corrCity||null,d.corrCounty||null,d.corrCountry||'United Kingdom',d.corrPostcode||null,d.businessDescription||null,d.entityType||null]
    );
    res.status(201).json(normCustomer(r.rows[0]));
  } catch(e) { res.status(500).json({ error:e.message }); }
});
app.put('/api/customers/:id', auth, async(req,res) => {
  try {
    const d = req.body;
    const r = await query(
      `UPDATE customers SET type=$1,name=$2,email=$3,phone=$4,contact_name=$5,contact_mobile=$6,practice_name=$7,status=$8,ern_number=$9,ern_exempt=$10,year_established=$11,num_subsidiaries=$12,corr_address_line1=$13,corr_address_line2=$14,corr_city=$15,corr_county=$16,corr_country=$17,corr_postcode=$18,business_description=$19,entity_type=$20 WHERE id=$21 RETURNING *`,
      [d.type||'gp_practice',d.name,d.email||null,d.phone||null,d.contactName||null,d.contactMobile||null,d.practiceName||null,d.status||'active',d.ernNumber||null,d.ernExempt||'no',d.yearEstablished||null,d.numSubsidiaries??0,d.corrAddressLine1||null,d.corrAddressLine2||null,d.corrCity||null,d.corrCounty||null,d.corrCountry||'United Kingdom',d.corrPostcode||null,d.businessDescription||null,d.entityType||null,req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ error:'Not found' });
    res.json(normCustomer(r.rows[0]));
  } catch(e) { res.status(500).json({ error:e.message }); }
});
app.delete('/api/customers/:id', auth, async(req,res) => {
  try { await query('DELETE FROM customers WHERE id=$1',[req.params.id]); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ error:e.message }); }
});

// STATS
app.get('/api/stats', auth, async(req,res) => {
  try {
    const [custs, users] = await Promise.all([
      query('SELECT status FROM customers'),
      query('SELECT COUNT(*) AS cnt FROM users WHERE active=true')
    ]);
    const rows = custs.rows;
    res.json({ totalCustomers:rows.length, activeCustomers:rows.filter(r=>r.status==='active').length, prospectCustomers:rows.filter(r=>r.status==='prospect').length, totalUsers:parseInt(users.rows[0].cnt) });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// QUOTES
async function nextRef() {
  const r = await query("SELECT quote_ref FROM quotes ORDER BY created_at DESC LIMIT 1");
  const last = r.rows.length ? parseInt((r.rows[0].quote_ref||'QT-0000').split('-')[1]||0) : 0;
  return 'QT-' + String(last+1).padStart(4,'0');
}

const QCOLS = `id,quote_ref,status,customer_id,renewal_date,quote_type,previous_insurer,full_name,contact_name,telephone,mobile,email,addr_name,addr_line1,addr_line2,addr_town,addr_county,addr_country,addr_postcode,none_of_below,decl1,decl2,decl3,decl4,decl5,decl6,years_since_last_claim,claims,day_one_cover,excess,fidelity,dir_units,dir_fulltime,dir_parttime,emp_units,emp_fulltime,emp_parttime,bi_cover_type,bi_annual_sum_insured,bi_cover_period,bi_book_debt_cover,indemnity_limit,offsite_clinics,terrorism_cover,material_damage,non_selection_rule,terrorism_postcode,anticipated_turnover,num_premises,country,premises,premium,valid_until,created_by`;

function qVals(d, userId) {
  return [
    d.customerId||null, d.renewalDate||null, d.quoteType||null, d.previousInsurer||null,
    d.fullName||null, d.contactName||null, d.telephone||null, d.mobile||null, d.email||null,
    d.addrName||null, d.addrLine1||null, d.addrLine2||null, d.addrTown||null, d.addrCounty||null, d.addrCountry||null, d.addrPostcode||null,
    d.noneOfBelow||'Yes', d.decl1||'No', d.decl2||'No', d.decl3||'No', d.decl4||'No', d.decl5||'No', d.decl6||'No',
    d.yearsSinceLastClaim||'0', JSON.stringify(d.claims||[]),
    d.dayOneCover||'0', d.excess||'£200', d.fidelity||'£25000',
    d.dirUnits||0, d.dirFulltime||0, d.dirParttime||0, d.empUnits||0, d.empFulltime||0, d.empParttime||0,
    d.biCoverType||null, d.biAnnualSumInsured||0, d.biCoverPeriod||'24', d.biBookDebtCover||10000,
    d.indemnityLimit||'£5000000', d.offsiteClinics||0,
    d.terrorismCover||'No', d.materialDamage||null, d.nonSelectionRule||null, d.terrorismPostcode||null, d.anticipatedTurnover||0,
    d.numPremises||1, d.country||'UK', JSON.stringify(d.premises||[]),
    d.premium||null, d.validUntil||null, userId
  ];
}

app.get('/api/quotes', auth, async(req,res) => {
  try { res.json((await query('SELECT * FROM quotes ORDER BY created_at DESC')).rows.map(normQuote)); }
  catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/quotes', auth, async(req,res) => {
  try {
    const d = req.body; const ref = await nextRef();
    const vals = qVals(d, req.session.userId);
    const placeholders = `$1,$2,$3,$4,${vals.map((_,i)=>'$'+(i+5)).join(',')}`;
    const r = await query(
      `INSERT INTO quotes (${QCOLS}) VALUES (${placeholders}) RETURNING *`,
      [uuidv4(), ref, d.status||'draft', ...vals]
    );
    res.status(201).json(normQuote(r.rows[0]));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.put('/api/quotes/:id', auth, async(req,res) => {
  try {
    const d = req.body;
    const cols = QCOLS.split(',').slice(3); // skip id, quote_ref, customer_id... start from status
    const setCols = ['status=$1','customer_id=$2','renewal_date=$3','quote_type=$4','previous_insurer=$5','full_name=$6','contact_name=$7','telephone=$8','mobile=$9','email=$10','addr_name=$11','addr_line1=$12','addr_line2=$13','addr_town=$14','addr_county=$15','addr_country=$16','addr_postcode=$17','none_of_below=$18','decl1=$19','decl2=$20','decl3=$21','decl4=$22','decl5=$23','decl6=$24','years_since_last_claim=$25','claims=$26','day_one_cover=$27','excess=$28','fidelity=$29','dir_units=$30','dir_fulltime=$31','dir_parttime=$32','emp_units=$33','emp_fulltime=$34','emp_parttime=$35','bi_cover_type=$36','bi_annual_sum_insured=$37','bi_cover_period=$38','bi_book_debt_cover=$39','indemnity_limit=$40','offsite_clinics=$41','terrorism_cover=$42','material_damage=$43','non_selection_rule=$44','terrorism_postcode=$45','anticipated_turnover=$46','num_premises=$47','country=$48','premises=$49','premium=$50','valid_until=$51','updated_at=NOW()'];
    const vals = [d.status||'draft',...qVals(d,null).slice(0,-1), req.params.id]; // drop created_by, add id
    const r = await query(`UPDATE quotes SET ${setCols.join(',')} WHERE id=$52 RETURNING *`, vals);
    if (!r.rows.length) return res.status(404).json({ error:'Not found' });
    res.json(normQuote(r.rows[0]));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.delete('/api/quotes/:id', auth, async(req,res) => {
  try { await query('DELETE FROM quotes WHERE id=$1',[req.params.id]); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, () => console.log(`PracticeCover on port ${PORT}`));
