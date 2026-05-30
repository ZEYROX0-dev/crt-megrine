const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, 'crt.db'));

function run(sql, params=[]) {
  return new Promise((res, rej) => db.run(sql, params, function(err) { if(err) rej(err); else res(this); }));
}
function get(sql, params=[]) {
  return new Promise((res, rej) => db.get(sql, params, (err, row) => { if(err) rej(err); else res(row); }));
}
function all(sql, params=[]) {
  return new Promise((res, rej) => db.all(sql, params, (err, rows) => { if(err) rej(err); else res(rows); }));
}

async function initDB() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    assigned_to INTEGER,
    date TEXT,
    status TEXT DEFAULT 'planifiee',
    created_by INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_name TEXT,
    mimetype TEXT,
    size INTEGER,
    action_id INTEGER,
    uploaded_by INTEGER,
    uploaded_at TEXT DEFAULT (datetime('now'))
  )`);

  const admin = await get('SELECT id FROM users WHERE username = ?', ['admin']);
  if (!admin) {
    const h = (p) => bcrypt.hashSync(p, 10);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,?)", ['Super Admin','admin',h('admin123'),'admin','active']);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,?)", ['Ahmed Ben Salah','president',h('crt2024'),'president','active']);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,?)", ['Fatma Gharbi','vice',h('crt2024'),'vice','active']);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,?)", ['Sana Trabelsi','sana',h('crt2024'),'member','active']);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,?)", ['Ali Mansouri','ali',h('crt2024'),'member','active']);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,?)", ['Rania Belhaj','rania',h('crt2024'),'member','active']);
    await run("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES (?,?,?,?,?,?)", ['Campagne don de sang','École secondaire Megrine',4,'2024-03-15','terminee',2]);
    await run("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES (?,?,?,?,?,?)", ['Distribution de vivres','Aide alimentaire familles',5,'2024-03-22','en_cours',2]);
    await run("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES (?,?,?,?,?,?)", ['Premiers secours','Formation gestes urgence',6,'2024-04-05','planifiee',2]);
  }
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + ext);
  }
});
const upload = multer({ storage });

app.use(express.json({ limit: '10gb' }));
app.use(express.urlencoded({ limit: '10gb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'crt-megrine-2024-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function isAdmin(role) { return ['admin','president','vice'].includes(role); }

async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  req.user = await get('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  next();
}
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = await get('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (!user || !isAdmin(user.role)) return res.status(403).json({ error: 'Accès refusé' });
  req.user = user;
  next();
}

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || !bcrypt.compareSync(password, user.password)) return res.json({ ok: false, error: 'Identifiants incorrects' });
    if (user.status === 'pending') return res.json({ ok: false, error: "Compte en attente d'approbation" });
    if (user.status === 'rejected') return res.json({ ok: false, error: 'Demande refusée' });
    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, name: user.name, username: user.username, role: user.role } });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/register', async (req, res) => {
  try {
    const { firstname, lastname, username, password, role } = req.body;
    if (!firstname || !lastname || !username || !password) return res.json({ ok: false, error: 'Champs manquants' });
    if (password.length < 6) return res.json({ ok: false, error: 'Mot de passe trop court' });
    const exists = await get('SELECT id FROM users WHERE username = ?', [username]);
    if (exists) return res.json({ ok: false, error: "Nom d'utilisateur déjà utilisé" });
    const hash = bcrypt.hashSync(password, 10);
    const safeRole = ['member','vice'].includes(role) ? role : 'member';
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,'pending')", [`${firstname} ${lastname}`, username, hash, safeRole]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = await get('SELECT id,name,username,role,status FROM users WHERE id = ?', [req.session.userId]);
  res.json(user);
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const totalMembers = (await get("SELECT COUNT(*) as c FROM users WHERE status='active' AND role NOT IN ('admin')")).c;
  const pendingCount = (await get("SELECT COUNT(*) as c FROM users WHERE status='pending'")).c;
  const totalActions = (await get("SELECT COUNT(*) as c FROM actions")).c;
  const doneActions = (await get("SELECT COUNT(*) as c FROM actions WHERE status='terminee'")).c;
  const ongoingActions = (await get("SELECT COUNT(*) as c FROM actions WHERE status='en_cours'")).c;
  const totalMedia = (await get("SELECT COUNT(*) as c FROM media")).c;
  res.json({ totalMembers, pendingCount, totalActions, doneActions, ongoingActions, totalMedia });
});

app.get('/api/admin/requests', requireAdmin, async (req, res) => {
  const pending = await all("SELECT id,name,username,role,status,created_at FROM users WHERE status='pending' ORDER BY created_at DESC");
  const allUsers = await all("SELECT id,name,username,role,status,created_at FROM users WHERE role NOT IN ('admin') ORDER BY created_at DESC");
  res.json({ pending, all: allUsers });
});

app.post('/api/admin/approve/:id', requireAdmin, async (req, res) => {
  await run("UPDATE users SET status='active' WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/admin/reject/:id', requireAdmin, async (req, res) => {
  await run("UPDATE users SET status='rejected' WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/admin/members', requireAdmin, async (req, res) => {
  const members = await all("SELECT id,name,username,role,status,created_at FROM users WHERE role NOT IN ('admin') ORDER BY name");
  res.json(members);
});

app.post('/api/admin/members', requireAdmin, async (req, res) => {
  try {
    const { name, username, password, role } = req.body;
    if (!name || !username || !password) return res.json({ ok: false, error: 'Champs manquants' });
    if (await get('SELECT id FROM users WHERE username=?', [username])) return res.json({ ok: false, error: 'Username déjà pris' });
    const hash = bcrypt.hashSync(password, 10);
    await run("INSERT INTO users (name,username,password,role,status) VALUES (?,?,?,?,'active')", [name, username, hash, role||'member']);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.get('/api/actions', requireAuth, async (req, res) => {
  const u = req.user;
  let actions;
  if (isAdmin(u.role)) {
    actions = await all(`SELECT a.*,u.name as member_name,
      (SELECT COUNT(*) FROM media m WHERE m.action_id=a.id) as media_count
      FROM actions a LEFT JOIN users u ON a.assigned_to=u.id ORDER BY a.created_at DESC`);
  } else {
    actions = await all(`SELECT a.*,u.name as member_name,
      (SELECT COUNT(*) FROM media m WHERE m.action_id=a.id AND m.uploaded_by=?) as media_count
      FROM actions a LEFT JOIN users u ON a.assigned_to=u.id WHERE a.assigned_to=? ORDER BY a.created_at DESC`, [u.id, u.id]);
  }
  res.json(actions);
});

app.post('/api/actions', requireAdmin, async (req, res) => {
  try {
    const { title, description, assigned_to, date, status } = req.body;
    if (!title) return res.json({ ok: false, error: 'Titre requis' });
    const r = await run("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES (?,?,?,?,?,?)",
      [title, description, assigned_to||null, date, status||'planifiee', req.session.userId]);
    res.json({ ok: true, id: r.lastID });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.put('/api/actions/:id', requireAdmin, async (req, res) => {
  const { title, description, assigned_to, date, status } = req.body;
  await run("UPDATE actions SET title=?,description=?,assigned_to=?,date=?,status=? WHERE id=?",
    [title, description, assigned_to||null, date, status, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/actions/:id', requireAdmin, async (req, res) => {
  await run("DELETE FROM media WHERE action_id=?", [req.params.id]);
  await run("DELETE FROM actions WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/media/upload', requireAuth, upload.array('files', 20), async (req, res) => {
  if (!req.files || !req.files.length) return res.json({ ok: false, error: 'Aucun fichier' });
  const { action_id } = req.body;
  const saved = [];
  for (const file of req.files) {
    const r = await run("INSERT INTO media (filename,original_name,mimetype,size,action_id,uploaded_by) VALUES (?,?,?,?,?,?)",
      [file.filename, file.originalname, file.mimetype, file.size, action_id||null, req.session.userId]);
    saved.push({ id: r.lastID, filename: file.filename, url: '/uploads/' + file.filename });
  }
  res.json({ ok: true, files: saved });
});

app.get('/api/media', requireAuth, async (req, res) => {
  const u = req.user;
  let media;
  if (isAdmin(u.role)) {
    media = await all(`SELECT m.*,u.name as uploader_name,a.title as action_title
      FROM media m LEFT JOIN users u ON m.uploaded_by=u.id LEFT JOIN actions a ON m.action_id=a.id
      ORDER BY m.uploaded_at DESC`);
  } else {
    media = await all(`SELECT m.*,u.name as uploader_name,a.title as action_title
      FROM media m LEFT JOIN users u ON m.uploaded_by=u.id LEFT JOIN actions a ON m.action_id=a.id
      WHERE m.uploaded_by=? ORDER BY m.uploaded_at DESC`, [u.id]);
  }
  media = media.map(m => ({ ...m, url: '/uploads/' + m.filename }));
  res.json(media);
});

app.delete('/api/media/:id', requireAuth, async (req, res) => {
  const u = req.user;
  const m = await get('SELECT * FROM media WHERE id=?', [req.params.id]);
  if (!m) return res.json({ ok: false });
  if (m.uploaded_by !== u.id && !isAdmin(u.role)) return res.status(403).json({ error: 'Accès refusé' });
  try { fs.unlinkSync(path.join(UPLOADS_DIR, m.filename)); } catch(e) {}
  await run('DELETE FROM media WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => console.log(`CRT Megrine running on port ${PORT}`));
}).catch(console.error);
