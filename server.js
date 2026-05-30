const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure data directory exists
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Database
const db = new Database(path.join(DATA_DIR, 'crt.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    assigned_to INTEGER,
    date TEXT,
    status TEXT DEFAULT 'planifiee',
    created_by INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(assigned_to) REFERENCES users(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_name TEXT,
    mimetype TEXT,
    size INTEGER,
    action_id INTEGER,
    uploaded_by INTEGER,
    uploaded_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(action_id) REFERENCES actions(id),
    FOREIGN KEY(uploaded_by) REFERENCES users(id)
  );
`);

// Seed admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, ?)").run('Super Admin', 'admin', hash, 'admin', 'active');
  const presHash = bcrypt.hashSync('crt2024', 10);
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, ?)").run('Ahmed Ben Salah', 'president', presHash, 'president', 'active');
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, ?)").run('Fatma Gharbi', 'vice', presHash, 'vice', 'active');
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, ?)").run('Sana Trabelsi', 'sana', presHash, 'member', 'active');
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, ?)").run('Ali Mansouri', 'ali', presHash, 'member', 'active');
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, ?)").run('Rania Belhaj', 'rania', presHash, 'member', 'active');
  // Seed actions
  db.prepare("INSERT INTO actions (title, description, assigned_to, date, status, created_by) VALUES (?, ?, ?, ?, ?, ?)").run('Campagne don de sang', 'École secondaire Megrine', 4, '2024-03-15', 'terminee', 2);
  db.prepare("INSERT INTO actions (title, description, assigned_to, date, status, created_by) VALUES (?, ?, ?, ?, ?, ?)").run('Distribution de vivres', 'Aide alimentaire familles défavorisées', 5, '2024-03-22', 'en_cours', 2);
  db.prepare("INSERT INTO actions (title, description, assigned_to, date, status, created_by) VALUES (?, ?, ?, ?, ?, ?)").run('Sensibilisation premiers secours', 'Formation gestes d\'urgence', 6, '2024-04-05', 'planifiee', 2);
}

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'crt-megrine-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user || !['admin','president','vice'].includes(user.role)) return res.status(403).json({ error: 'Accès refusé' });
  req.user = user;
  next();
}
function loadUser(req, res, next) {
  if (req.session.userId) {
    req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  }
  next();
}

// ===== AUTH ROUTES =====
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.json({ ok: false, error: 'Identifiants incorrects' });
  if (user.status === 'pending') return res.json({ ok: false, error: 'Compte en attente d\'approbation' });
  if (user.status === 'rejected') return res.json({ ok: false, error: 'Demande refusée par l\'administrateur' });
  req.session.userId = user.id;
  res.json({ ok: true, user: { id: user.id, name: user.name, username: user.username, role: user.role } });
});

app.post('/api/register', (req, res) => {
  const { firstname, lastname, username, password, role } = req.body;
  if (!firstname || !lastname || !username || !password) return res.json({ ok: false, error: 'Champs manquants' });
  if (password.length < 6) return res.json({ ok: false, error: 'Mot de passe trop court' });
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) return res.json({ ok: false, error: 'Nom d\'utilisateur déjà utilisé' });
  const hash = bcrypt.hashSync(password, 10);
  const safeRole = ['member', 'vice'].includes(role) ? role : 'member';
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, 'pending')").run(`${firstname} ${lastname}`, username, hash, safeRole);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, username, role, status FROM users WHERE id = ?').get(req.session.userId);
  res.json(user);
});

// ===== ADMIN ROUTES =====
app.get('/api/admin/requests', requireAdmin, (req, res) => {
  const pending = db.prepare("SELECT id, name, username, role, status, created_at FROM users WHERE status = 'pending' ORDER BY created_at DESC").all();
  const all = db.prepare("SELECT id, name, username, role, status, created_at FROM users WHERE role NOT IN ('admin') ORDER BY created_at DESC").all();
  res.json({ pending, all });
});

app.post('/api/admin/approve/:id', requireAdmin, (req, res) => {
  db.prepare("UPDATE users SET status = 'active' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/reject/:id', requireAdmin, (req, res) => {
  db.prepare("UPDATE users SET status = 'rejected' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/members', requireAdmin, (req, res) => {
  const members = db.prepare("SELECT id, name, username, role, status, created_at FROM users WHERE role NOT IN ('admin') ORDER BY name").all();
  res.json(members);
});

app.post('/api/admin/members', requireAdmin, (req, res) => {
  const { name, username, password, role } = req.body;
  if (!name || !username || !password) return res.json({ ok: false, error: 'Champs manquants' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.json({ ok: false, error: 'Username déjà pris' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO users (name, username, password, role, status) VALUES (?, ?, ?, ?, 'active')").run(name, username, hash, role || 'member');
  res.json({ ok: true });
});

app.delete('/api/admin/members/:id', requireAdmin, (req, res) => {
  db.prepare("DELETE FROM users WHERE id = ? AND role NOT IN ('admin')").run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalMembers = db.prepare("SELECT COUNT(*) as c FROM users WHERE status='active' AND role NOT IN ('admin')").get().c;
  const pendingCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE status='pending'").get().c;
  const totalActions = db.prepare("SELECT COUNT(*) as c FROM actions").get().c;
  const doneActions = db.prepare("SELECT COUNT(*) as c FROM actions WHERE status='terminee'").get().c;
  const ongoingActions = db.prepare("SELECT COUNT(*) as c FROM actions WHERE status='en_cours'").get().c;
  const totalMedia = db.prepare("SELECT COUNT(*) as c FROM media").get().c;
  res.json({ totalMembers, pendingCount, totalActions, doneActions, ongoingActions, totalMedia });
});

// ===== ACTIONS ROUTES =====
app.get('/api/actions', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  let actions;
  if (['admin','president','vice'].includes(user.role)) {
    actions = db.prepare(`SELECT a.*, u.name as member_name, u.username as member_username,
      (SELECT COUNT(*) FROM media m WHERE m.action_id = a.id) as media_count
      FROM actions a LEFT JOIN users u ON a.assigned_to = u.id ORDER BY a.created_at DESC`).all();
  } else {
    actions = db.prepare(`SELECT a.*, u.name as member_name,
      (SELECT COUNT(*) FROM media m WHERE m.action_id = a.id AND m.uploaded_by = ?) as media_count
      FROM actions a LEFT JOIN users u ON a.assigned_to = u.id WHERE a.assigned_to = ? ORDER BY a.created_at DESC`).all(user.id, user.id);
  }
  res.json(actions);
});

app.post('/api/actions', requireAdmin, (req, res) => {
  const { title, description, assigned_to, date, status } = req.body;
  if (!title) return res.json({ ok: false, error: 'Titre requis' });
  const result = db.prepare("INSERT INTO actions (title, description, assigned_to, date, status, created_by) VALUES (?, ?, ?, ?, ?, ?)").run(title, description, assigned_to, date, status || 'planifiee', req.session.userId);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.put('/api/actions/:id', requireAdmin, (req, res) => {
  const { title, description, assigned_to, date, status } = req.body;
  db.prepare("UPDATE actions SET title=?, description=?, assigned_to=?, date=?, status=? WHERE id=?").run(title, description, assigned_to, date, status, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/actions/:id', requireAdmin, (req, res) => {
  db.prepare("DELETE FROM media WHERE action_id = ?").run(req.params.id);
  db.prepare("DELETE FROM actions WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// ===== MEDIA ROUTES =====
app.post('/api/media/upload', requireAuth, upload.array('files', 20), (req, res) => {
  const { action_id } = req.body;
  if (!req.files || req.files.length === 0) return res.json({ ok: false, error: 'Aucun fichier' });
  const saved = [];
  for (const file of req.files) {
    const result = db.prepare("INSERT INTO media (filename, original_name, mimetype, size, action_id, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)").run(file.filename, file.originalname, file.mimetype, file.size, action_id || null, req.session.userId);
    saved.push({ id: result.lastInsertRowid, filename: file.filename, url: '/uploads/' + file.filename });
  }
  res.json({ ok: true, files: saved });
});

app.get('/api/media', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  let media;
  if (['admin','president','vice'].includes(user.role)) {
    media = db.prepare(`SELECT m.*, u.name as uploader_name, a.title as action_title
      FROM media m LEFT JOIN users u ON m.uploaded_by = u.id LEFT JOIN actions a ON m.action_id = a.id
      ORDER BY m.uploaded_at DESC`).all();
  } else {
    media = db.prepare(`SELECT m.*, u.name as uploader_name, a.title as action_title
      FROM media m LEFT JOIN users u ON m.uploaded_by = u.id LEFT JOIN actions a ON m.action_id = a.id
      WHERE m.uploaded_by = ? ORDER BY m.uploaded_at DESC`).all(user.id);
  }
  media = media.map(m => ({ ...m, url: '/uploads/' + m.filename }));
  res.json(media);
});

app.delete('/api/media/:id', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const m = db.prepare('SELECT * FROM media WHERE id = ?').get(req.params.id);
  if (!m) return res.json({ ok: false });
  if (m.uploaded_by !== user.id && !['admin','president','vice'].includes(user.role)) return res.status(403).json({ error: 'Accès refusé' });
  try { fs.unlinkSync(path.join(UPLOADS_DIR, m.filename)); } catch(e) {}
  db.prepare('DELETE FROM media WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Serve index.html for all other routes (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CRT Megrine Media running on port ${PORT}`);
});
