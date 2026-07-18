require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'medresearch-secret-key-change-in-production';
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const CHAT_FILE = path.join(DATA_DIR, 'chat.json');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');
if (!fs.existsSync(CHAT_FILE)) fs.writeFileSync(CHAT_FILE, '{}');

// Reusable email sender
async function sendEmail({ fromName, replyTo, subject, text }) {
  const pass = (process.env.SMTP_PASS || '').replace(/\s+/g, '');
  const useSmtp = process.env.SMTP_HOST && process.env.SMTP_USER && !process.env.SMTP_USER.includes('your.email') && pass.length > 8;
  if (!useSmtp) { console.log('[email skipped]', subject); return; }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false, requireTLS: true,
    auth: { user: process.env.SMTP_USER, pass },
  });
  await transporter.sendMail({
    from: `"${fromName}" <${process.env.SMTP_USER}>`,
    replyTo,
    to: process.env.CONTACT_EMAIL || 'medresearch77@gmail.com',
    subject, text,
  });
}

const upload = multer({ dest: path.join(__dirname, 'uploads'), limits: { fileSize: 50 * 1024 * 1024 } });

// Admin -> client project file uploads (keeps original filename)
const PROJECT_UPLOADS = path.join(__dirname, 'project-uploads');
if (!fs.existsSync(PROJECT_UPLOADS)) fs.mkdirSync(PROJECT_UPLOADS);
const projectUpload = multer({ dest: PROJECT_UPLOADS, limits: { fileSize: 50 * 1024 * 1024 } });

// Backups
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

const pdfkit = require('pdfkit');
const archiver = require('archiver');
const QRCode = require('qrcode');
const crypto = require('crypto');

// ── Self-contained TOTP (RFC 6238, Google Authenticator compatible) ──
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(str) {
  str = str.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = '', bytes = [];
  for (const c of str) {
    const v = B32.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totpGenerate(secret, timeStep = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return (code % (10 ** digits)).toString().padStart(digits, '0');
}
function totpVerify(token, secret, window = 1, timeStep = 30, digits = 6) {
  token = String(token).trim();
  if (!/^\d+$/.test(token) || token.length !== digits) return false;
  for (let w = -window; w <= window; w++) {
    const counter = Math.floor(Date.now() / 1000 / timeStep) + w;
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
    const candidate = (code % (10 ** digits)).toString().padStart(digits, '0');
    if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(candidate))) return true;
  }
  return false;
}
function totpSecret() {
  const bytes = crypto.randomBytes(20);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

// ── Recovery codes (single-use backup for 2FA) ──
const RECOVERY_CODE_COUNT = 5;
function recoveryCodeHash(code) {
  return crypto.createHash('sha256').update('recovery:' + code).digest('hex');
}
function makeRecoveryCodes() {
  const plain = [];
  const hashed = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase(); // 10 hex chars
    const grouped = raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 10);
    plain.push(grouped);
    hashed.push(recoveryCodeHash(grouped));
  }
  return { plain, hashed };
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Guard against serving sensitive server files / data over HTTP.
const STATIC_DENY = [/^\/?\.env($|\/)/i, /^\/?server\.js($|\/)/i, /^\/?package\.json($|\/)/i,
  /^\/?package-lock\.json($|\/)/i, /^\/?data($|\/)/i, /^\/?project-uploads($|\/)/i,
  /^\/?uploads($|\/)/i, /^\/?node_modules($|\/)/i, /^\/?backups?($|\/)/i];
app.use((req, res, next) => {
  const p = (req.path || '/').split('?')[0];
  if (STATIC_DENY.some(rx => rx.test(p))) return res.status(404).end();
  next();
});
app.use(express.static(path.join(__dirname, '.')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ── Admin credentials store (persisted, changeable from portal) ──
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
function loadAdminCreds() {
  if (fs.existsSync(ADMIN_FILE)) {
    try { return JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8')); } catch (e) {}
  }
  const seed = {
    username: process.env.ADMIN_USERNAME || 'shreeadmin',
    password: process.env.ADMIN_PASSWORD || 'medresearch-admin',
  };
  fs.writeFileSync(ADMIN_FILE, JSON.stringify(seed, null, 2));
  return seed;
}
let adminCreds = loadAdminCreds();
function saveAdminCreds(c) { adminCreds = c; fs.writeFileSync(ADMIN_FILE, JSON.stringify(c, null, 2)); }

// ── TOTP (Google Authenticator) 2FA ──
const TOTP_ISSUER = 'medresearch.me';
const TOTP_WINDOW = 1; // allow ±1 time step drift
// Short-lived proof that password step passed, before 2FA code is verified.
const pendingLogins = new Map(); // loginKey -> { username, expires }
function newLoginKey(username) {
  const key = require('crypto').randomBytes(24).toString('hex');
  pendingLogins.set(key, { username, expires: Date.now() + 5 * 60 * 1000 });
  return key;
}

// ── Login rate-limiting + account lockout (in-memory) ──
const RATE_WINDOW = 60 * 1000;   // 1 minute
const RATE_MAX = 5;              // max attempts per window
const LOCK_MS = 15 * 60 * 1000;  // 15 minute lockout
const loginAttempts = new Map(); // key -> { count, first, lockUntil }
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || 'unknown';
}
function checkLoginThrottle(ip, username) {
  const now = Date.now();
  for (const key of [ip, 'u:' + username]) {
    const a = loginAttempts.get(key);
    if (a && a.lockUntil && a.lockUntil > now) {
      return { blocked: true, retryAfter: Math.ceil((a.lockUntil - now) / 1000) };
    }
  }
  return { blocked: false };
}
function registerLoginFailure(ip, username) {
  const now = Date.now();
  for (const key of [ip, 'u:' + username]) {
    let a = loginAttempts.get(key);
    if (!a || !a.first || now - a.first > RATE_WINDOW) {
      a = { count: 0, first: now, lockUntil: 0 };
    }
    a.count += 1;
    if (a.count >= RATE_MAX) a.lockUntil = now + LOCK_MS;
    loginAttempts.set(key, a);
  }
}
function registerLoginSuccess(ip, username) {
  loginAttempts.delete(ip);
  loginAttempts.delete('u:' + username);
}

// ── Helpers ──
const readJSON = f => JSON.parse(fs.readFileSync(f, 'utf8'));
const writeJSON = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));
const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.split(' ')[1], JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Invalid token' }); }
};

// ── Contact API ──
const CONTACT_LABELS = {
  name: 'Name', email: 'Email', service: 'Service', whatsapp: 'WhatsApp Number', country: 'Country',
  congress: 'Target Congress', congress_other: 'Target Congress (Other)',
  plan: 'Plan', topic: 'Topic / Research Question', idea: 'Idea / Concept',
  description: 'Description', question: 'Research Question',
  analysis_type: 'Analysis Type', data_description: 'Data Description',
  journal: 'Target Journal', prisma: 'PRISMA Required',
  visuals: 'Visuals / Figures', references: 'Key References',
  deadline: 'Target Deadline', message: 'Message'
};
const CONTACT_ORDER = ['name','email','whatsapp','country','service','congress','congress_other','plan','topic','idea','question','description','analysis_type','data_description','journal','prisma','visuals','references','deadline','message'];

app.post('/api/contact', async (req, res) => {
  const { honeypot, _gotcha, _formspree_id, ...fields } = req.body;
  if (honeypot || _gotcha) return res.json({ ok: true });

  // Build a readable email from EVERY submitted field (nothing dropped)
  const lines = [];
  for (const k of CONTACT_ORDER) {
    const v = fields[k];
    if (v !== undefined && v !== null && String(v).trim() !== '') {
      lines.push(`${CONTACT_LABELS[k] || k}: ${String(v).trim()}`);
    }
  }
  for (const k of Object.keys(fields)) {
    if (!CONTACT_ORDER.includes(k)) {
      const v = fields[k];
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        lines.push(`${CONTACT_LABELS[k] || k}: ${String(v).trim()}`);
      }
    }
  }

  const name = (fields.name || '').trim();
  const email = (fields.email || '').trim();
  if (!name || !email) return res.status(400).json({ ok: false, error: 'Name and email are required.' });
  if (lines.length < 2) return res.status(400).json({ ok: false, error: 'Please provide some details.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'Invalid email address.' });
  }

  const subjectService = fields.service || fields.congress_other || fields.congress || fields.topic || 'Inquiry';
  const body = lines.join('\n');

  const pass = (process.env.SMTP_PASS || '').replace(/\s+/g, '');
  const useSmtp = process.env.SMTP_HOST
    && process.env.SMTP_USER && !process.env.SMTP_USER.includes('your.email')
    && pass.length > 8;

  if (useSmtp) {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: false,
      requireTLS: true,
      auth: { user: process.env.SMTP_USER, pass },
    });
    try {
      const info = await transporter.sendMail({
        from: `"${name}" <${process.env.SMTP_USER}>`,
        replyTo: email,
        to: process.env.CONTACT_EMAIL || 'medresearch77@gmail.com',
        subject: `[medresearch.me] New Inquiry — ${String(subjectService).slice(0, 60)}`,
        text: body,
      });
      console.log('Email sent:', info.messageId);
      return res.json({ ok: true });
    } catch (err) {
      console.error('SMTP error:', err.message);
    }
  }
  console.log('\n=== NEW CONTACT FORM SUBMISSION (no SMTP) ===');
  console.log(body);
  console.log('==============================================\n');

  res.json({ ok: true });
});

// ── Auth Routes ──
// Client signup is admin-only. Kept for backwards compatibility but disabled in UI.
app.post('/api/auth/signup', async (req, res) => {
  return res.status(403).json({ error: 'Client accounts are created by the administrator only.' });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid email or password' });
  if (user.disabled) return res.status(403).json({ error: 'This account has been disabled. Contact support.' });
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: 'client' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// ── Admin auth middleware (defined early so client-management routes can use it) ──
const adminAuth = (req, res, next) => {
  const h = req.headers.authorization || (req.query.token ? 'Bearer ' + req.query.token : null);
  if (!h) return res.status(401).json({ error: 'No token' });
  try {
    const u = jwt.verify(h.split(' ')[1], JWT_SECRET);
    if (u.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
};

// ── Admin: Client (user) management ──
app.get('/api/admin/clients', adminAuth, (req, res) => {
  const users = readJSON(USERS_FILE).map(u => ({
    id: u.id, name: u.name, email: u.email, createdAt: u.createdAt,
    passwordText: u.passwordText || '',
    disabled: !!u.disabled, projectCount: readJSON(ORDERS_FILE).filter(o => o.userId === u.id && o.adminManaged).length
  }));
  res.json(users);
});

app.post('/api/admin/clients', adminAuth, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, email, and password (6+ chars) required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), name, email, password: hash, passwordText: password, createdAt: new Date().toISOString(), disabled: false };
  users.push(user);
  writeJSON(USERS_FILE, users);
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, passwordText: password } });
});

app.post('/api/admin/clients/:id/password', adminAuth, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const users = readJSON(USERS_FILE);
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Client not found' });
  users[idx].password = await bcrypt.hash(password, 10);
  users[idx].passwordText = password;
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

app.post('/api/admin/clients/:id/toggle', adminAuth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Client not found' });
  users[idx].disabled = !users[idx].disabled;
  writeJSON(USERS_FILE, users);
  res.json({ ok: true, disabled: users[idx].disabled });
});

app.delete('/api/admin/clients/:id', adminAuth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const filtered = users.filter(u => u.id !== req.params.id);
  if (filtered.length === users.length) return res.status(404).json({ error: 'Client not found' });
  writeJSON(USERS_FILE, filtered);
  res.json({ ok: true });
});

// ── Orders / Projects ──
app.get('/api/orders', auth, (req, res) => {
  const orders = readJSON(ORDERS_FILE)
    .filter(o => o.userId === req.user.id && o.adminManaged)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(o => ({
      id: o.id, service: o.service, plan: o.plan, title: o.title, deadline: o.deadline,
      description: o.description, status: o.status, notes: o.notes || '',
      paymentLink: o.paymentLink || '', paymentEnabled: !!o.paymentEnabled,
      agreementAccepted: !!o.agreementAccepted, agreementAcceptedAt: o.agreementAcceptedAt || null,
      paid: !!o.paid, paidAt: o.paidAt || null,
      depositPaid: !!o.depositPaid, depositPaidAt: o.depositPaidAt || null,
      paymentType: o.paymentType || 'full',
      amount: Number(o.amount) || 0,
      filesReleased: !!o.paid,
      createdAt: o.createdAt, files: o.paid ? (o.files || []) : []
    }));
  res.json(orders);
});

app.get('/api/orders/:id', auth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const order = orders.find(o => o.id == req.params.id && o.userId === req.user.id && o.adminManaged);
  if (!order) return res.status(404).json({ error: 'Project not found' });
  res.json({
    id: order.id, service: order.service, plan: order.plan, title: order.title, deadline: order.deadline,
    description: order.description, status: order.status, notes: order.notes || '',
    paymentLink: order.paymentLink || '', paymentEnabled: !!order.paymentEnabled,
    agreementAccepted: !!order.agreementAccepted, agreementAcceptedAt: order.agreementAcceptedAt || null,
    paid: !!order.paid, paidAt: order.paidAt || null,
    depositPaid: !!order.depositPaid, depositPaidAt: order.depositPaidAt || null,
    paymentType: order.paymentType || 'full',
    amount: Number(order.amount) || 0,
    filesReleased: !!order.paid,
    createdAt: order.createdAt, files: order.paid ? (order.files || []) : []
  });
});

// Client accepts agreement -> records acceptance, returns payment link for redirect
app.post('/api/orders/:id/agreement', auth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const idx = orders.findIndex(o => o.id == req.params.id && o.userId === req.user.id && o.adminManaged);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  const o = orders[idx];
  if (!o.paymentEnabled) return res.status(403).json({ error: 'Payment is not enabled for this project yet. Contact support.' });
  if (!o.paymentLink) return res.status(400).json({ error: 'No payment link has been assigned to this project.' });
  o.agreementAccepted = true;
  o.agreementAcceptedAt = new Date().toISOString();
  o.activity = o.activity || [];
  o.activity.push({ at: o.agreementAcceptedAt, by: 'client', action: 'Agreement accepted' });
  orders[idx] = o;
  writeJSON(ORDERS_FILE, orders);
  const total = Number(o.amount) || 0;
  const isSplit = (o.paymentType || 'full') === 'split';
  if (isSplit && !o.depositPaid && !o.paid) {
    // First (deposit) payment step of a split plan — admin marks 50% done after receiving it.
    return res.json({
      ok: true,
      paymentLink: o.paymentLink,
      paymentType: 'split',
      depositStep: true,
      depositAmount: Math.round(total / 2 * 100) / 100,
      finalAmount: Math.round(total / 2 * 100) / 100,
      total,
      message: 'Proceed to pay the 50% deposit. Your administrator will mark it as received, after which the remaining 50% is due on completion.'
    });
  }
  const isSplitFinal = isSplit;
  res.json({
    ok: true,
    paymentLink: o.paymentLink,
    paymentType: o.paymentType || 'full',
    depositStep: false,
    finalStep: isSplitFinal,
    amount: isSplitFinal ? Math.round(total / 2 * 100) / 100 : total,
    total
  });
});

// ── Chat (client ↔ admin) ──
// Storage: { [userId]: [ { id, from:'client'|'admin', text, at } ] }
const readChat = () => { try { return readJSON(CHAT_FILE); } catch(e) { return {}; } };
const writeChat = d => writeJSON(CHAT_FILE, d);

// Client: get conversation
app.get('/api/chat', auth, (req, res) => {
  const chat = readChat();
  res.json(chat[req.user.id] || []);
});

// Client: mark admin messages as read
app.post('/api/chat/read', auth, (req, res) => {
  const chat = readChat();
  const msgs = chat[req.user.id] || [];
  msgs.forEach(m => { if (m.from === 'admin') m.read = true; });
  chat[req.user.id] = msgs;
  writeChat(chat);
  res.json({ ok: true });
});

// Client: send message
app.post('/api/chat', auth, async (req, res) => {
  const text = (req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Message cannot be empty' });
  const users = readJSON(USERS_FILE);
  const u = users.find(x => x.id === req.user.id);
  const chat = readChat();
  const msg = { id: uuidv4(), from: 'client', text, at: new Date().toISOString() };
  chat[req.user.id] = chat[req.user.id] || [];
  chat[req.user.id].push(msg);
  writeChat(chat);
  // Email admin immediately
  try {
    await sendEmail({
      fromName: u ? u.name : req.user.name,
      replyTo: u ? u.email : req.user.email,
      subject: `[medresearch.me] New chat message from ${u ? u.name : req.user.name}`,
      text: `New message from ${u ? u.name : req.user.name} <${u ? u.email : req.user.email}>:\n\n${text}\n\n--\nReply from the admin panel at /admin.html (Chat tab).`
    });
  } catch(e) { console.error('Chat email error:', e.message); }
  res.json({ ok: true, message: msg });
});

// Admin: list all conversations (with last message + unread count)
app.get('/api/admin/chat', adminAuth, (req, res) => {
  const chat = readChat();
  const users = readJSON(USERS_FILE);
  const convos = Object.keys(chat).map(userId => {
    const msgs = chat[userId];
    const u = users.find(x => x.id === userId);
    const unread = msgs.filter(m => m.from === 'client' && !m.read).length;
    return {
      userId,
      name: u ? u.name : 'Unknown',
      email: u ? u.email : '',
      count: msgs.length,
      unread,
      last: msgs[msgs.length - 1] || null
    };
  }).filter(c => c.count > 0).sort((a, b) => new Date((b.last||{}).at) - new Date((a.last||{}).at));
  res.json(convos);
});

// Admin: get one conversation
app.get('/api/admin/chat/:userId', adminAuth, (req, res) => {
  const chat = readChat();
  const msgs = chat[req.params.userId] || [];
  res.json(msgs);
});

// Admin: reply
app.post('/api/admin/chat/:userId', adminAuth, (req, res) => {
  const text = (req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Message cannot be empty' });
  const chat = readChat();
  chat[req.params.userId] = chat[req.params.userId] || [];
  const msg = { id: uuidv4(), from: 'admin', text, at: new Date().toISOString() };
  chat[req.params.userId].push(msg);
  writeChat(chat);
  res.json({ ok: true, message: msg });
});

// Admin: mark conversation read
app.post('/api/admin/chat/:userId/read', adminAuth, (req, res) => {
  const chat = readChat();
  const msgs = chat[req.params.userId] || [];
  msgs.forEach(m => { if (m.from === 'client') m.read = true; });
  chat[req.params.userId] = msgs;
  writeChat(chat);
  res.json({ ok: true });
});

// ── Payment Route (Stripe placeholder) ──
app.post('/api/create-payment', auth, async (req, res) => {
  const { amount, service, orderId } = req.body;
  // In production, integrate Stripe:
  // const paymentIntent = await stripe.paymentIntents.create({ amount: amount * 100, currency: 'usd' });
  // res.json({ clientSecret: paymentIntent.client_secret });
  res.json({
    ok: true,
    message: 'Payment integration ready. To activate Stripe, set STRIPE_SECRET_KEY in .env',
    amount,
    service,
    orderId
  });
});

// ── Admin Routes ──
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIp(req);
  const throttle = checkLoginThrottle(ip, username || '');
  if (throttle.blocked) return res.status(429).json({ error: `Too many attempts. Try again in ${throttle.retryAfter}s.` });
  if (!username || username !== adminCreds.username) { registerLoginFailure(ip, username || ''); return res.status(401).json({ error: 'Invalid username' }); }
  if (!password || password !== adminCreds.password) { registerLoginFailure(ip, username); return res.status(401).json({ error: 'Invalid password' }); }
  registerLoginSuccess(ip, username);
  // If 2FA is enabled, require a TOTP code before issuing the admin token.
  if (adminCreds.totpEnabled && adminCreds.totpSecret) {
    return res.json({ twoFactor: true, loginKey: newLoginKey(username) });
  }
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// Step 2: verify the TOTP code and issue the admin token
app.post('/api/admin/login/verify', (req, res) => {
  const { loginKey, code } = req.body;
  const pending = pendingLogins.get(loginKey);
  if (!pending || pending.expires < Date.now()) return res.status(401).json({ error: 'Login session expired. Please sign in again.' });
  pendingLogins.delete(loginKey);
  const ip = getClientIp(req);
  const throttle = checkLoginThrottle(ip, pending.username);
  if (throttle.blocked) return res.status(429).json({ error: `Too many attempts. Try again in ${throttle.retryAfter}s.` });
  let usedRecovery = false;
  let ok = totpVerify(code, adminCreds.totpSecret, TOTP_WINDOW);
  if (!ok && Array.isArray(adminCreds.recoveryCodes)) {
    const hash = recoveryCodeHash(String(code).trim().toUpperCase());
    const idx = adminCreds.recoveryCodes.indexOf(hash);
    if (idx !== -1) {
      ok = true;
      usedRecovery = true;
      const remaining = adminCreds.recoveryCodes.slice();
      remaining.splice(idx, 1);
      saveAdminCreds({ ...adminCreds, recoveryCodes: remaining });
    }
  }
  if (!ok) { registerLoginFailure(ip, pending.username); return res.status(401).json({ error: 'Invalid authentication code' }); }
  if (usedRecovery) console.log('[2FA] recovery code consumed for', pending.username);
  registerLoginSuccess(ip, pending.username);
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.post('/api/admin/logout', (req, res) => {
  res.json({ ok: true });
});

// ── 2FA enrollment (requires existing admin session) ──
app.get('/api/admin/2fa/setup', adminAuth, async (req, res) => {
  try {
    const secret = totpSecret();
    const label = encodeURIComponent(TOTP_ISSUER + ':' + adminCreds.username);
    const issuer = encodeURIComponent(TOTP_ISSUER);
    const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}`;
    const qr = await QRCode.toDataURL(otpauth);
    res.json({ secret, qr });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/2fa/enable', adminAuth, (req, res) => {
  const { secret, code } = req.body;
  if (!secret || !code) return res.status(400).json({ error: 'Secret and code are required' });
  const ok = totpVerify(code, secret, TOTP_WINDOW);
  if (!ok) return res.status(400).json({ error: 'Invalid code. 2FA not enabled.' });
  const { plain, hashed } = makeRecoveryCodes();
  saveAdminCreds({ ...adminCreds, totpSecret: secret, totpEnabled: true, recoveryCodes: hashed });
  res.json({ ok: true, recoveryCodes: plain });
});

app.post('/api/admin/2fa/disable', adminAuth, (req, res) => {
  const { code } = req.body;
  if (!adminCreds.totpEnabled || !adminCreds.totpSecret) return res.json({ ok: true });
  if (code) {
    const ok = totpVerify(code, adminCreds.totpSecret, TOTP_WINDOW);
    if (!ok) return res.status(400).json({ error: 'Invalid code. 2FA not disabled.' });
  }
  saveAdminCreds({ ...adminCreds, totpEnabled: false, totpSecret: undefined, recoveryCodes: undefined });
  res.json({ ok: true });
});

// Regenerate a fresh set of recovery codes (requires current TOTP code)
app.post('/api/admin/2fa/recovery/regenerate', adminAuth, (req, res) => {
  const { code } = req.body;
  if (!adminCreds.totpEnabled || !adminCreds.totpSecret) return res.status(400).json({ error: '2FA is not enabled' });
  if (!totpVerify(code, adminCreds.totpSecret, TOTP_WINDOW)) return res.status(400).json({ error: 'Invalid code' });
  const { plain, hashed } = makeRecoveryCodes();
  saveAdminCreds({ ...adminCreds, recoveryCodes: hashed });
  res.json({ ok: true, recoveryCodes: plain });
});

// How many recovery codes remain (for the security panel)
app.get('/api/admin/2fa/recovery/count', adminAuth, (req, res) => {
  res.json({ count: Array.isArray(adminCreds.recoveryCodes) ? adminCreds.recoveryCodes.length : 0 });
});

app.get('/api/admin/2fa/status', adminAuth, (req, res) => {
  res.json({
    enabled: !!(adminCreds.totpEnabled && adminCreds.totpSecret),
    recoveryCodesRemaining: Array.isArray(adminCreds.recoveryCodes) ? adminCreds.recoveryCodes.length : 0,
  });
});

// Change admin username/password from within the portal
app.post('/api/admin/credentials', adminAuth, (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body;
  if (!currentPassword || currentPassword !== adminCreds.password) return res.status(401).json({ error: 'Current password is incorrect' });
  const updates = {};
  if (newUsername && newUsername.trim()) {
    if (newUsername.trim().length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    updates.username = newUsername.trim();
  }
  if (newPassword && newPassword.trim()) {
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    updates.password = newPassword;
  }
  if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No changes provided' });
  saveAdminCreds({ ...adminCreds, ...updates });
  res.json({ ok: true, username: adminCreds.username });
});

app.get('/api/admin/orders', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const users = readJSON(USERS_FILE);
  const enriched = orders.map(o => {
    const u = users.find(x => x.id === o.userId);
    return { ...o, userEmail: u ? u.email : 'unknown', userName: u ? u.name : 'unknown' };
  }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(enriched);
});

// Admin: create a project for a client
app.post('/api/admin/projects', adminAuth, (req, res) => {
  const { userId, service, plan, title, deadline, description, paymentLink, amount } = req.body;
  if (!userId || !title) return res.status(400).json({ error: 'Client and title are required' });
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'Client not found' });
  const orders = readJSON(ORDERS_FILE);
  const maxId = orders.reduce((m, o) => Math.max(m, Number(o.id) || 0), 0);
  const newOrder = {
    id: maxId + 1,
    userId,
    client: user.name,
    clientEmail: user.email,
    service: service || 'General',
    plan: plan || '',
    title,
    deadline: deadline || '',
    description: description || '',
    paymentLink: paymentLink || '',
    paymentEnabled: false,
    paid: false,
    depositPaid: false,
    paymentType: 'full',
    amount: Number(amount) || 0,
    status: 'pending',
    notes: '',
    agreementAccepted: false,
    agreementAcceptedAt: null,
    files: [],
    adminManaged: true,
    createdAt: new Date().toISOString(),
    activity: [{ at: new Date().toISOString(), by: 'admin', action: 'Project created' }]
  };
  orders.push(newOrder);
  writeJSON(ORDERS_FILE, orders);
  res.json({ ok: true, order: newOrder });
});

// Admin: update a project (status, notes, paymentLink, payment status, fields)
app.post('/api/admin/projects/:id', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const idx = orders.findIndex(o => o.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  const o = orders[idx];
  const { service, plan, title, deadline, description, status, notes, paymentLink, paymentState, paid, depositPaid, paymentType, amount, paymentEnabled } = req.body;
  const changes = [];
  if (service !== undefined && service !== o.service) { o.service = service; changes.push('service'); }
  if (plan !== undefined && plan !== o.plan) { o.plan = plan; changes.push('plan'); }
  if (title !== undefined && title !== o.title) { o.title = title; changes.push('title'); }
  if (deadline !== undefined && deadline !== o.deadline) { o.deadline = deadline; changes.push('deadline'); }
  if (description !== undefined && description !== o.description) { o.description = description; changes.push('description'); }
  if (status !== undefined && status !== o.status) { o.status = status; changes.push('status → ' + status); }
  if (notes !== undefined && notes !== o.notes) { o.notes = notes; changes.push('notes'); }
  if (paymentLink !== undefined && paymentLink !== o.paymentLink) { o.paymentLink = paymentLink; changes.push('payment link'); }
  if (paymentType !== undefined && paymentType !== o.paymentType) { o.paymentType = paymentType === 'split' ? 'split' : 'full'; changes.push('payment type → ' + o.paymentType); }
  // Single, source-of-truth payment status set by the admin.
  if (paymentState !== undefined) {
    let np = false, nd = false;
    if (paymentState === 'paid' || paymentState === 'full') { np = true; nd = true; }
    else if (paymentState === 'deposit') { np = false; nd = true; }
    else { np = false; nd = false; }
    if (nd !== o.depositPaid) { o.depositPaid = nd; o.depositPaidAt = nd ? (o.depositPaidAt || new Date().toISOString()) : null; changes.push('payment status → ' + (np ? '100% paid' : (nd ? '50% paid' : 'not paid'))); }
    if (np !== o.paid) { o.paid = np; o.paidAt = np ? (o.paidAt || new Date().toISOString()) : null; changes.push('payment ' + (np ? 'received (full)' : 'marked unpaid')); }
  }
  if (paid !== undefined && !!paid !== !!o.paid) { o.paid = !!paid; o.paidAt = o.paid ? (o.paidAt || new Date().toISOString()) : null; changes.push('payment ' + (o.paid ? 'received (full)' : 'marked unpaid')); }
  if (depositPaid !== undefined && !!depositPaid !== !!o.depositPaid) { o.depositPaid = !!depositPaid; o.depositPaidAt = o.depositPaid ? (o.depositPaidAt || new Date().toISOString()) : null; changes.push('deposit ' + (o.depositPaid ? 'paid' : 'reversed')); }
  if (amount !== undefined && Number(amount) !== Number(o.amount)) { o.amount = Number(amount) || 0; changes.push('amount'); }
  // Client access to the agreement & payment page is toggled explicitly by the admin button.
  if (paymentEnabled !== undefined) {
    if (!!paymentEnabled !== !!o.paymentEnabled) { o.paymentEnabled = !!paymentEnabled; changes.push('client access ' + (o.paymentEnabled ? 'enabled' : 'disabled')); }
  }
  o.activity = o.activity || [];
  for (const c of changes) o.activity.push({ at: new Date().toISOString(), by: 'admin', action: 'Updated ' + c });
  orders[idx] = o;
  writeJSON(ORDERS_FILE, orders);
  res.json({ ok: true, order: o });
});

// Admin: agreements log — all admin-managed projects with acceptance status + activity
app.get('/api/admin/agreements', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const result = orders
    .filter(o => o.adminManaged)
    .map(o => ({
      id: o.id,
      client: o.client || '',
      clientEmail: o.clientEmail || o.userEmail || '',
      service: o.service,
      title: o.title,
      status: o.status,
      paymentEnabled: !!o.paymentEnabled,
      paid: !!o.paid,
      paidAt: o.paidAt || null,
      amount: Number(o.amount) || 0,
      agreementAccepted: !!o.agreementAccepted,
      agreementAcceptedAt: o.agreementAcceptedAt || null,
      paymentLink: o.paymentLink || '',
      activity: (o.activity || []).slice().sort((a, b) => new Date(b.at) - new Date(a.at))
    }))
    .sort((a, b) => {
      const ad = a.agreementAcceptedAt ? new Date(a.agreementAcceptedAt) : 0;
      const bd = b.agreementAcceptedAt ? new Date(b.agreementAcceptedAt) : 0;
      return bd - ad;
    });
  res.json(result);
});

app.delete('/api/admin/projects/:id', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const filtered = orders.filter(o => o.id != req.params.id);
  if (filtered.length === orders.length) return res.status(404).json({ error: 'Project not found' });
  writeJSON(ORDERS_FILE, filtered);
  res.json({ ok: true });
});

// ── Admin: upload files to a project (delivered to client) ──
app.post('/api/admin/projects/:id/files', adminAuth, projectUpload.single('file'), (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const idx = orders.findIndex(o => o.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  if (!req.file) return res.status(400).json({ error: 'No file provided' });
  const files = [{ name: req.file.originalname, url: '/project-files/' + req.file.filename, size: req.file.size, at: new Date().toISOString() }];
  orders[idx].files = orders[idx].files || [];
  orders[idx].files.push(...files);
  orders[idx].activity = orders[idx].activity || [];
  orders[idx].activity.push({ at: new Date().toISOString(), by: 'admin', action: 'Uploaded ' + files.length + ' file(s)' });
  writeJSON(ORDERS_FILE, orders);
  res.json({ ok: true, files });
});
app.delete('/api/admin/projects/:id/files', adminAuth, (req, res) => {
  const name = req.query.name;
  const url = req.body && req.body.url;
  const orders = readJSON(ORDERS_FILE);
  const idx = orders.findIndex(o => o.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  const before = (orders[idx].files || []).length;
  orders[idx].files = (orders[idx].files || []).filter(f => (name ? f.name !== name : f.url !== url));
  if (orders[idx].files.length === before) return res.status(404).json({ error: 'File not found' });
  let diskName = url ? url.replace('/project-files/', '') : null;
  if (!diskName && name) {
    const all = readJSON(ORDERS_FILE);
    const o = all.find(x => x.id == req.params.id);
    const f = (o.files || []).find(x => x.name === name);
    if (f) diskName = f.url.replace('/project-files/', '');
  }
  if (diskName) { try { fs.unlinkSync(path.join(PROJECT_UPLOADS, diskName)); } catch(e) {} }
  writeJSON(ORDERS_FILE, orders);
  res.json({ ok: true });
});

// Explicit, name-correct file download (served by hash, original name enforced)
// Gated: must be the owning client or an admin.
app.get('/project-files/:file', (req, res) => {
  const name = req.params.file;
  const token = (req.headers.authorization || '').split(' ')[1] || req.query.token;
  let who = null;
  try { who = jwt.verify(token, JWT_SECRET); } catch(e) {}
  let entry = null, ownerId = null;
  try {
    const orders = readJSON(ORDERS_FILE);
    for (const o of orders) {
      const f = (o.files || []).find(x => x.url === '/project-files/' + name);
      if (f) { entry = f; ownerId = o.userId; break; }
    }
  } catch(e) {}
  if (!entry) return res.status(404).send('File not found');
  if (!who) return res.status(401).send('Sign in to download');
  if (who.role !== 'admin' && who.id !== ownerId) return res.status(403).send('Forbidden');
  const fpath = path.join(PROJECT_UPLOADS, name);
  if (!fs.existsSync(fpath)) return res.status(404).send('File not found');
  res.setHeader('Content-Disposition', `attachment; filename="${entry.name.replace(/"/g, '')}"`);
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(fpath).pipe(res);
});

// ── Invoice / Receipt PDF ──
function buildInvoiceDoc(order, user) {
  const doc = new pdfkit({ margin: 50 });
  const amount = Number(order.amount) || 0;
  const amtStr = '$' + amount.toFixed(2);
  const BRAND = '#0a2540', ACCENT = '#1b7a1b', GRAY = '#888888', LINE = '#dddddd';
  const cn = (user && user.name) || order.client || 'Client';
  const ce = (user && user.email) || order.clientEmail || '';
  const idt = new Date(order.paidAt || order.createdAt);
  const dd = order.deadline ? new Date(order.deadline) : null;
  const W = doc.page.width, RIGHT = W - 50;

  // ── Header band ──
  doc.rect(0, 0, W, 90).fill(BRAND);
  doc.fillColor('#ffffff');
  doc.font('Helvetica-Bold').fontSize(22).text('medresearch.me', 50, 30);
  doc.font('Helvetica').fontSize(10).fillColor('#c9d6e5').text('Research Support & Manuscript Services', 50, 60);

  doc.font('Helvetica-Bold').fontSize(18).fillColor('#ffffff');
  doc.text('INVOICE', RIGHT - doc.widthOfString('INVOICE'), 32);
  doc.font('Helvetica').fontSize(10).fillColor('#c9d6e5');
  const invNo = 'INV-' + order.id;
  doc.text(invNo, RIGHT - doc.widthOfString(invNo), 56);
  const dtStr = idt.toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });
  doc.text(dtStr, RIGHT - doc.widthOfString(dtStr), 70);

  doc.y = 115;
  doc.font('Helvetica').fillColor('#000');

  // ── Billed-to / status / due ──
  const colY = doc.y;
  doc.font('Helvetica-Bold').fontSize(8).fillColor(GRAY).text('BILLED TO', 50, colY);
  doc.font('Helvetica').fontSize(11).fillColor('#000').text(cn, 50, colY + 14);
  doc.fontSize(10).fillColor('#444').text(ce || '', 50, colY + 30);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(GRAY).text('STATUS', 330, colY);
  doc.fontSize(11).fillColor(order.paid ? ACCENT : '#b8860b').text(order.paid ? 'PAID' : 'AWAITING PAYMENT', 330, colY + 14);
  if (dd) {
    doc.font('Helvetica-Bold').fontSize(8).fillColor(GRAY).text('DUE DATE', 430, colY);
    doc.font('Helvetica').fontSize(10).fillColor('#000').text(dd.toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' }), 430, colY + 14);
  }

  let y = colY + 58;
  doc.moveTo(50, y).lineTo(W - 50, y).lineWidth(1).strokeColor(LINE).stroke();

  // ── Line-item header ──
  y += 16;
  doc.font('Helvetica-Bold').fontSize(9).fillColor(GRAY);
  doc.text('DESCRIPTION', 50, y);
  doc.text('QTY', 360, y);
  doc.text('AMOUNT', RIGHT - doc.widthOfString('AMOUNT'), y);
  y += 8;
  doc.moveTo(50, y).lineTo(W - 50, y).lineWidth(1).strokeColor(LINE).stroke();

  // ── Line item ──
  y += 14;
  const svc = (order.service || 'Service') + (order.plan ? ' (' + order.plan + ')' : '');
  doc.font('Helvetica').fontSize(10).fillColor('#000');
  doc.text(svc, 50, y, { width: 300 });
  doc.text('1', 360, y);
  doc.text(amtStr, RIGHT - doc.widthOfString(amtStr), y);
  doc.fontSize(9).fillColor('#666').text('Project #' + order.id + ' — ' + order.title, 50, y + 16, { width: 360 });

  // ── Totals ──
  y += 46;
  doc.moveTo(50, y).lineTo(W - 50, y).lineWidth(1).strokeColor(LINE).stroke();

  y += 14;
  doc.font('Helvetica').fontSize(10).fillColor('#000');
  doc.text('Subtotal', RIGHT - doc.widthOfString('Subtotal'), y);
  doc.text(amtStr, RIGHT - doc.widthOfString(amtStr), y);
  let totalY = y;
  if (order.paid) {
    doc.fillColor('#b8860b').text('Amount Paid', RIGHT - doc.widthOfString('Amount Paid'), y + 18);
    doc.text('-$' + amount.toFixed(2), RIGHT - doc.widthOfString('-$' + amount.toFixed(2)), y + 18);
    totalY = y + 40;
  } else {
    totalY = y + 22;
  }
  doc.font('Helvetica-Bold').fontSize(13).fillColor(BRAND);
  doc.text('TOTAL', RIGHT - doc.widthOfString('TOTAL'), totalY);
  doc.text(amtStr, RIGHT - doc.widthOfString(amtStr), totalY);

  // ── Right Transfer Agreement (only when paid) ──
  let footTop = totalY + 40;
  if (order.paid) {
    doc.moveTo(50, footTop).lineTo(W - 50, footTop).lineWidth(1).strokeColor(LINE).stroke();
    let rtaY = footTop + 14;
    doc.font('Helvetica-Bold').fontSize(10).fillColor(BRAND);
    doc.text('RIGHT TRANSFER AGREEMENT', 50, rtaY);
    rtaY += 16;
    doc.font('Helvetica').fontSize(9).fillColor('#333').text(
      'Upon receipt of full payment for this Project, medresearch.me transfers all rights, title, and interest in the final deliverables to the Client. The deliverables become the Client’s property and may be used, published, submitted, or modified by the Client without further restriction. medresearch.me retains no rights to republish Client-specific content without permission.',
      50, rtaY, { width: W - 100, lineGap: 2 }
    );
    // advance y below the paragraph
    const rtaH = doc.heightOfString(
      'Upon receipt of full payment for this Project, medresearch.me transfers all rights, title, and interest in the final deliverables to the Client. The deliverables become the Client’s property and may be used, published, submitted, or modified by the Client without further restriction. medresearch.me retains no rights to republish Client-specific content without permission.',
      { width: W - 100, lineGap: 2 }
    );
    footTop = rtaY + rtaH + 16;
  }

  // ── Footer ──
  doc.moveTo(50, footTop).lineTo(W - 50, footTop).lineWidth(1).strokeColor(LINE).stroke();
  const footY = footTop + 12;
  doc.font('Helvetica').fontSize(8).fillColor(GRAY);
  doc.text('medresearch.me  •  ' + (process.env.CONTACT_EMAIL || 'medresearch77@gmail.com'), 50, footY);
  const msg = order.paid ? 'Thank you for your payment. This is your official receipt.' : 'Please complete payment using the link provided in your dashboard.';
  doc.text(msg, RIGHT - doc.widthOfString(msg), footY, { width: 260, align: 'right' });
  return doc;
}

// Custom Right Transfer Agreement paper (standalone document)
function buildRTADoc(order, user) {
  const doc = new pdfkit({ margin: 50 });
  const amount = Number(order.amount) || 0;
  const BRAND = '#0a2540', ACCENT = '#1b7a1b', GRAY = '#888888', LINE = '#dddddd';
  const cn = (user && user.name) || order.client || 'Client';
  const ce = (user && user.email) || order.clientEmail || '';
  const W = doc.page.width, RIGHT = W - 50;
  const today = new Date();

  // Header
  doc.rect(0, 0, W, 90).fill(BRAND);
  doc.fillColor('#ffffff');
  doc.font('Helvetica-Bold').fontSize(22).text('medresearch.me', 50, 30);
  doc.font('Helvetica').fontSize(10).fillColor('#c9d6e5').text('Research Support & Manuscript Services', 50, 60);
  doc.font('Helvetica-Bold').fontSize(16).fillColor('#ffffff');
  doc.text('RIGHT TRANSFER AGREEMENT', RIGHT - doc.widthOfString('RIGHT TRANSFER AGREEMENT'), 36);

  doc.y = 118;
  doc.font('Helvetica').fillColor('#000');

  doc.font('Helvetica-Bold').fontSize(11).fillColor(BRAND);
  doc.text('Agreement of Transfer of Rights', 50, doc.y);
  doc.moveDown(0.6);

  // Parties block
  doc.font('Helvetica-Bold').fontSize(8).fillColor(GRAY).text('PROVIDER', 50, doc.y);
  doc.font('Helvetica').fontSize(10).fillColor('#000').text('medresearch.me', 50, doc.y + 14);
  doc.fontSize(9).fillColor('#444').text((process.env.CONTACT_EMAIL || 'medresearch77@gmail.com'), 50, doc.y + 28);

  doc.font('Helvetica-Bold').fontSize(8).fillColor(GRAY).text('CLIENT', 330, doc.y - 28);
  doc.font('Helvetica').fontSize(10).fillColor('#000').text(cn, 330, doc.y - 14);
  doc.fontSize(9).fillColor('#444').text(ce || '', 330, doc.y + 0);

  doc.moveDown(2.2);

  const body = [
    { h: '1. Parties', p: 'This Right Transfer Agreement (the "Agreement") is entered into between medresearch.me ("Provider") and ' + cn + ' ("Client") in respect of the project described below.' },
    { h: '2. Project', p: 'Project #' + order.id + ' — ' + (order.title || '') + (order.service ? ' (' + order.service + (order.plan ? ' · ' + order.plan : '') + ')' : '') + '. Total fee: $' + amount.toFixed(2) + '.' },
    { h: '3. Consideration', p: 'The rights described in this Agreement are transferred in consideration of the full payment received from the Client for the above Project, recorded as paid on ' + today.toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' }) + '.' },
    { h: '4. Transfer of Rights', p: 'Upon receipt of full payment, medresearch.me hereby assigns, transfers, and sets over to the Client all rights, title, and interest of every kind whatsoever, throughout the world and for the full term of copyright, in and to the final deliverables produced for the Project (the "Work"). The Client shall be the sole owner of the Work.' },
    { h: '5. Rights Granted', p: 'The Client is free to use, reproduce, publish, submit, present, modify, adapt, translate, license, and otherwise exploit the Work in any manner and for any purpose, without further permission from or payment to the Provider.' },
    { h: '6. Provider Retained Rights', p: 'The Provider retains no rights to republish, resell, or redistribute Client-specific content or the Work without the Client’s prior written permission. The Provider may retain a non-client-specific, anonymized copy of methodology solely for internal quality assurance.' },
    { h: '7. Warranties', p: 'The Provider warrants that the Work is original (except for properly cited third-party material) and does not infringe the intellectual property rights of any third party to the best of the Provider’s knowledge.' },
    { h: '8. Entire Agreement', p: 'This Agreement constitutes the entire understanding between the parties regarding transfer of rights in the Work and supersedes all prior discussions on this subject.' }
  ];

  body.forEach((s, i) => {
    if (doc.y > doc.page.height - 140) { doc.addPage(); doc.y = 60; }
    doc.font('Helvetica-Bold').fontSize(10).fillColor(BRAND);
    doc.text(s.h, 50, doc.y);
    doc.moveDown(0.3);
    doc.font('Helvetica').fontSize(9.5).fillColor('#222');
    doc.text(s.p, 50, doc.y, { width: W - 100, lineGap: 2, align: 'justify' });
    doc.moveDown(0.9);
  });

  // Signature block
  if (doc.y > doc.page.height - 160) { doc.addPage(); doc.y = 60; }
  const signY = doc.y + 10;
  doc.moveTo(50, signY + 26).lineTo(260, signY + 26).lineWidth(1).strokeColor(LINE).stroke();
  doc.moveTo(330, signY + 26).lineTo(540, signY + 26).lineWidth(1).strokeColor(LINE).stroke();
  doc.font('Helvetica').fontSize(9).fillColor('#444');
  doc.text('medresearch.me (Provider)', 50, signY + 30);
  doc.text(cn + ' (Client)', 330, signY + 30);
  doc.fontSize(8).fillColor(GRAY);
  doc.text('Date: ' + today.toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' }), 50, signY + 46);

  // Footer
  const footY = doc.page.height - 50;
  doc.moveTo(50, footY - 8).lineTo(W - 50, footY - 8).lineWidth(1).strokeColor(LINE).stroke();
  doc.font('Helvetica').fontSize(8).fillColor(GRAY);
  doc.text('medresearch.me  •  ' + (process.env.CONTACT_EMAIL || 'medresearch77@gmail.com'), 50, footY);
  doc.text('Generated ' + today.toLocaleDateString('en-US'), RIGHT - doc.widthOfString('Generated ' + today.toLocaleDateString('en-US')), footY);
  return doc;
}

// Admin: download invoice PDF (preview/verify)
app.get('/api/admin/projects/:id/invoice', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const o = orders.find(x => x.id == req.params.id);
  if (!o) return res.status(404).json({ error: 'Project not found' });
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === o.userId);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="invoice-${o.id}.pdf"`);
  const doc = buildInvoiceDoc(o, user);
  doc.on('error', e => { try { fs.appendFileSync(path.join(DATA_DIR, 'pdf-errors.log'), new Date().toISOString() + ' ' + e.message + '\n'); } catch(_) {} });
  doc.pipe(res);
  doc.end();
});

// Admin: preview Right Transfer Agreement PDF
app.get('/api/admin/projects/:id/rta', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const o = orders.find(x => x.id == req.params.id);
  if (!o) return res.status(404).json({ error: 'Project not found' });
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === o.userId);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="right-transfer-${o.id}.pdf"`);
  const doc = buildRTADoc(o, user);
  doc.on('error', e => { try { fs.appendFileSync(path.join(DATA_DIR, 'pdf-errors.log'), new Date().toISOString() + ' ' + e.message + '\n'); } catch(_) {} });
  doc.pipe(res);
  doc.end();
});

// ── Admin dashboard overview ──
app.get('/api/admin/overview', adminAuth, (req, res) => {
  const orders = readJSON(ORDERS_FILE).filter(o => o.adminManaged);
  const users = readJSON(USERS_FILE);
  const chat = readChat();
  const revenue = orders.filter(o => o.paid).reduce((s, o) => s + (Number(o.amount) || 0), 0);
  const pendingPayments = orders.filter(o => o.paymentEnabled && !o.paid).length;
  const awaitingAccept = orders.filter(o => o.paymentEnabled && !o.agreementAccepted).length;
  let unreadChats = 0; const chatConvos = [];
  for (const uid of Object.keys(chat)) {
    const msgs = chat[uid];
    const unread = msgs.filter(m => m.from === 'client' && !m.read).length;
    unreadChats += unread;
    const u = users.find(x => x.id === uid);
    const last = msgs[msgs.length - 1];
    if (last) chatConvos.push({ userId: uid, name: u ? u.name : 'Unknown', email: u ? u.email : '', unread, last: last.text, at: last.at });
  }
  chatConvos.sort((a, b) => new Date(b.at) - new Date(a.at));
  // Recent activity across projects
  const activity = [];
  for (const o of orders) {
    for (const a of (o.activity || [])) activity.push({ ...a, project: '#' + o.id + ' ' + o.title, client: o.client || '' });
  }
  activity.sort((a, b) => new Date(b.at) - new Date(a.at));
  const byStatus = {};
  orders.forEach(o => { byStatus[o.status] = (byStatus[o.status] || 0) + 1; });
  const outstanding = orders.filter(o => o.paymentEnabled && !o.paid).reduce((s, o) => s + (Number(o.amount) || 0), 0);
  const active = orders.filter(o => ['active','in-progress'].includes(o.status)).length;
  const paidCount = orders.filter(o => o.paid).length;
  const completed = orders.filter(o => o.status === 'completed').length;
  res.json({
    totalProjects: orders.length,
    projects: orders.length,
    active,
    awaitingPayment: pendingPayments,
    paid: paidCount,
    completed,
    outstanding,
    revenue,
    clients: users.length,
    pendingPayments,
    awaitingAccept,
    unreadChats,
    byStatus,
    chatConvos: chatConvos.slice(0, 6),
    recentActivity: activity.slice(0, 10)
  });
});

// ── Data backup ──
function doBackup() {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(BACKUP_DIR, 'backup-' + stamp);
  fs.mkdirSync(dest);
  for (const f of [USERS_FILE, ORDERS_FILE, CHAT_FILE]) {
    try { fs.copyFileSync(f, path.join(dest, path.basename(f))); } catch(e) {}
  }
  // keep only last 20 backups
  const dirs = fs.readdirSync(BACKUP_DIR).filter(d => d.startsWith('backup-')).sort().reverse();
  for (const d of dirs.slice(20)) { try { fs.rmSync(path.join(BACKUP_DIR, d), { recursive: true, force: true }); } catch(e) {} }
  return dest;
}
app.post('/api/admin/backup', adminAuth, (req, res) => {
  try { res.json({ ok: true, path: doBackup() }); } catch(e) { res.status(500).json({ error: e.message }); }
});
// Periodic backup every 6 hours
setInterval(() => { try { doBackup(); } catch(e) { console.error('backup error', e.message); } }, 6 * 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`→ medresearch.me running at http://localhost:${PORT}`);
});
