const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function query(sql, params=[]) {
  const r = await pool.query(sql, params);
  return r.rows;
}
async function queryOne(sql, params=[]) {
  const r = await pool.query(sql, params);
  return r.rows[0] || null;
}

// Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: (req, file) => ({
    folder: 'crt-megrine',
    resource_type: file.mimetype.startsWith('video') ? 'video' : 'image',
    allowed_formats: ['jpg','jpeg','png','gif','webp','mp4','mov','avi','mkv','heic','heif'],
    chunk_size: 6000000,
  }),
});
const upload = multer({ storage });

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS actions (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      assigned_to INTEGER REFERENCES users(id),
      date TEXT,
      status TEXT DEFAULT 'planifiee',
      created_by INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS media (
      id SERIAL PRIMARY KEY,
      filename TEXT NOT NULL,
      original_name TEXT,
      mimetype TEXT,
      size INTEGER,
      url TEXT,
      public_id TEXT,
      action_id INTEGER REFERENCES actions(id),
      uploaded_by INTEGER REFERENCES users(id),
      uploaded_at TIMESTAMP DEFAULT NOW()
    );
  `);

  const admin = await queryOne('SELECT id FROM users WHERE username=$1', ['admin']);
  if (!admin) {
    const h = (p) => bcrypt.hashSync(p, 10);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,$5)", ['Super Admin','admin',h('admin123'),'admin','active']);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,$5)", ['Ahmed Ben Salah','president',h('crt2024'),'president','active']);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,$5)", ['Fatma Gharbi','vice',h('crt2024'),'vice','active']);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,$5)", ['Sana Trabelsi','sana',h('crt2024'),'member','active']);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,$5)", ['Ali Mansouri','ali',h('crt2024'),'member','active']);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,$5)", ['Rania Belhaj','rania',h('crt2024'),'member','active']);
    const u = await query('SELECT id FROM users ORDER BY id');
    await pool.query("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES ($1,$2,$3,$4,$5,$6)", ['Campagne don de sang','École secondaire Megrine',u[3].id,'2024-03-15','terminee',u[1].id]);
    await pool.query("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES ($1,$2,$3,$4,$5,$6)", ['Distribution de vivres','Aide alimentaire familles',u[4].id,'2024-03-22','en_cours',u[1].id]);
    await pool.query("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES ($1,$2,$3,$4,$5,$6)", ['Premiers secours','Formation gestes urgence',u[5].id,'2024-04-05','planifiee',u[1].id]);
    console.log('DB seeded');
  }
}

// Session in-memory (simple)
app.use(session({
  secret: process.env.SESSION_SECRET || 'crt-megrine-2024-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use(express.json({ limit: '10gb' }));
app.use(express.urlencoded({ limit: '10gb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

function isAdmin(role) { return ['admin','president','vice'].includes(role); }

async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  req.user = await queryOne('SELECT * FROM users WHERE id=$1', [req.session.userId]);
  if (!req.user) return res.status(401).json({ error: 'Non authentifié' });
  next();
}
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = await queryOne('SELECT * FROM users WHERE id=$1', [req.session.userId]);
  if (!user || !isAdmin(user.role)) return res.status(403).json({ error: 'Accès refusé' });
  req.user = user;
  next();
}

// AUTH
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await queryOne('SELECT * FROM users WHERE username=$1', [username]);
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
    const exists = await queryOne('SELECT id FROM users WHERE username=$1', [username]);
    if (exists) return res.json({ ok: false, error: "Nom d'utilisateur déjà utilisé" });
    const hash = bcrypt.hashSync(password, 10);
    const safeRole = ['member','vice'].includes(role) ? role : 'member';
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,'pending')", [`${firstname} ${lastname}`, username, hash, safeRole]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = await queryOne('SELECT id,name,username,role,status FROM users WHERE id=$1', [req.session.userId]);
  res.json(user);
});

// ADMIN
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [tm, pc, ta, da, oa, tme] = await Promise.all([
    queryOne("SELECT COUNT(*) as c FROM users WHERE status='active' AND role NOT IN ('admin')"),
    queryOne("SELECT COUNT(*) as c FROM users WHERE status='pending'"),
    queryOne("SELECT COUNT(*) as c FROM actions"),
    queryOne("SELECT COUNT(*) as c FROM actions WHERE status='terminee'"),
    queryOne("SELECT COUNT(*) as c FROM actions WHERE status='en_cours'"),
    queryOne("SELECT COUNT(*) as c FROM media"),
  ]);
  res.json({ totalMembers:+tm.c, pendingCount:+pc.c, totalActions:+ta.c, doneActions:+da.c, ongoingActions:+oa.c, totalMedia:+tme.c });
});

app.get('/api/admin/requests', requireAdmin, async (req, res) => {
  const pending = await query("SELECT id,name,username,role,status,created_at FROM users WHERE status='pending' ORDER BY created_at DESC");
  const all = await query("SELECT id,name,username,role,status,created_at FROM users WHERE role NOT IN ('admin') ORDER BY created_at DESC");
  res.json({ pending, all });
});

app.post('/api/admin/approve/:id', requireAdmin, async (req, res) => {
  await pool.query("UPDATE users SET status='active' WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/admin/reject/:id', requireAdmin, async (req, res) => {
  await pool.query("UPDATE users SET status='rejected' WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/admin/members', requireAdmin, async (req, res) => {
  const members = await query("SELECT id,name,username,role,status,created_at FROM users WHERE role NOT IN ('admin') ORDER BY name");
  res.json(members);
});

app.post('/api/admin/members', requireAdmin, async (req, res) => {
  try {
    const { name, username, password, role } = req.body;
    if (!name || !username || !password) return res.json({ ok: false, error: 'Champs manquants' });
    if (await queryOne('SELECT id FROM users WHERE username=$1', [username])) return res.json({ ok: false, error: 'Username déjà pris' });
    const hash = bcrypt.hashSync(password, 10);
    await pool.query("INSERT INTO users (name,username,password,role,status) VALUES ($1,$2,$3,$4,'active')", [name, username, hash, role||'member']);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/admin/change-role/:id', requireAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['member','vice','president','admin'].includes(role)) return res.json({ ok: false, error: 'Rôle invalide' });
    await pool.query("UPDATE users SET role=$1 WHERE id=$2", [role, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/admin/change-password/:id', requireAdmin, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) return res.json({ ok: false, error: 'Mot de passe trop court' });
    const hash = bcrypt.hashSync(password, 10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ACTIONS
app.get('/api/actions', requireAuth, async (req, res) => {
  const u = req.user;
  let actions;
  if (isAdmin(u.role)) {
    actions = await query(`SELECT a.*,u.name as member_name,
      (SELECT COUNT(*) FROM media m WHERE m.action_id=a.id) as media_count
      FROM actions a LEFT JOIN users u ON a.assigned_to=u.id ORDER BY a.created_at DESC`);
  } else {
    actions = await query(`SELECT a.*,u.name as member_name,
      (SELECT COUNT(*) FROM media m WHERE m.action_id=a.id AND m.uploaded_by=$1) as media_count
      FROM actions a LEFT JOIN users u ON a.assigned_to=u.id WHERE a.assigned_to=$2 ORDER BY a.created_at DESC`, [u.id, u.id]);
  }
  res.json(actions);
});

app.post('/api/actions', requireAdmin, async (req, res) => {
  try {
    const { title, description, assigned_to, date, status } = req.body;
    if (!title) return res.json({ ok: false, error: 'Titre requis' });
    const r = await queryOne("INSERT INTO actions (title,description,assigned_to,date,status,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
      [title, description, assigned_to||null, date, status||'planifiee', req.session.userId]);
    res.json({ ok: true, id: r.id });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.put('/api/actions/:id', requireAdmin, async (req, res) => {
  const { title, description, assigned_to, date, status } = req.body;
  await pool.query("UPDATE actions SET title=$1,description=$2,assigned_to=$3,date=$4,status=$5 WHERE id=$6",
    [title, description, assigned_to||null, date, status, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/actions/:id', requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM media WHERE action_id=$1", [req.params.id]);
  await pool.query("DELETE FROM actions WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// MEDIA
app.post('/api/media/upload', requireAuth, upload.array('files', 50), async (req, res) => {
  if (!req.files || !req.files.length) return res.json({ ok: false, error: 'Aucun fichier' });
  const { action_id } = req.body;
  const saved = [];
  for (const file of req.files) {
    const r = await queryOne("INSERT INTO media (filename,original_name,mimetype,size,url,public_id,action_id,uploaded_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
      [file.filename, file.originalname, file.mimetype, file.size, file.path, file.filename, action_id||null, req.session.userId]);
    saved.push({ id: r.id, url: file.path });
  }
  res.json({ ok: true, files: saved });
});

app.get('/api/media', requireAuth, async (req, res) => {
  const u = req.user;
  let media;
  if (isAdmin(u.role)) {
    media = await query(`SELECT m.*,u.name as uploader_name,a.title as action_title
      FROM media m LEFT JOIN users u ON m.uploaded_by=u.id LEFT JOIN actions a ON m.action_id=a.id
      ORDER BY m.uploaded_at DESC`);
  } else {
    media = await query(`SELECT m.*,u.name as uploader_name,a.title as action_title
      FROM media m LEFT JOIN users u ON m.uploaded_by=u.id LEFT JOIN actions a ON m.action_id=a.id
      WHERE m.uploaded_by=$1 ORDER BY m.uploaded_at DESC`, [u.id]);
  }
  res.json(media);
});

app.delete('/api/media/:id', requireAuth, async (req, res) => {
  const u = req.user;
  const m = await queryOne('SELECT * FROM media WHERE id=$1', [req.params.id]);
  if (!m) return res.json({ ok: false });
  if (m.uploaded_by !== u.id && !isAdmin(u.role)) return res.status(403).json({ error: 'Accès refusé' });
  try { await cloudinary.uploader.destroy(m.public_id, { resource_type: m.mimetype&&m.mimetype.startsWith('video')?'video':'image' }); } catch(e) {}
  await pool.query('DELETE FROM media WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => console.log(`CRT Megrine running on port ${PORT}`));
}).catch(console.error);
