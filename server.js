const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ia-chat-secret-mude-isso';
const CREATOR_EMAIL = process.env.CREATOR_EMAIL || 'jefersonrotello@gmail.com';

const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || '/tmp/iachat.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    personal_api_key TEXT,
    personal_provider TEXT,
    personal_model TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Ensure creator account exists
function ensureCreator() {
  const pwd = process.env.CREATOR_PASSWORD || 'trocar123';
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(CREATOR_EMAIL);
  if (!existing) {
    const hash = bcrypt.hashSync(pwd, 10);
    db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(CREATOR_EMAIL, hash, 'creator');
    console.log(`✅ Conta criador criada: ${CREATOR_EMAIL}`);
  }
}
ensureCreator();

// ── Helpers ───────────────────────────────────────────────────────────────────
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function auth(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Não autenticado.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Sessão expirada.' }); }
}

function role(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Acesso negado.' });
    next();
  };
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios.' });
  if (password.length < 6) return res.status(400).json({ error: 'Senha mínima: 6 caracteres.' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase()))
    return res.status(400).json({ error: 'Email já cadastrado.' });
  const hash = bcrypt.hashSync(password, 10);
  const r = db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(email.toLowerCase(), hash, 'user');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(r.lastInsertRowid);
  res.cookie('token', signToken(user), { httpOnly: true, maxAge: 7*24*60*60*1000 });
  res.json({ ok: true, user: { email: user.email, role: user.role } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email||'').toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Email ou senha incorretos.' });
  res.cookie('token', signToken(user), { httpOnly: true, maxAge: 7*24*60*60*1000 });
  res.json({ ok: true, user: { email: user.email, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, role, personal_provider, personal_model FROM users WHERE id = ?').get(req.user.id);
  const hasPersonalKey = !!db.prepare('SELECT personal_api_key FROM users WHERE id = ?').get(req.user.id)?.personal_api_key;
  res.json({ ...user, hasPersonalKey });
});

// ── Personal key ──────────────────────────────────────────────────────────────
app.post('/api/my-key', auth, (req, res) => {
  const { apiKey, provider, model } = req.body;
  db.prepare('UPDATE users SET personal_api_key=?, personal_provider=?, personal_model=? WHERE id=?')
    .run(apiKey||null, provider||null, model||null, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/my-key', auth, (req, res) => {
  db.prepare('UPDATE users SET personal_api_key=NULL, personal_provider=NULL, personal_model=NULL WHERE id=?').run(req.user.id);
  res.json({ ok: true });
});

// ── Change password ───────────────────────────────────────────────────────────
app.post('/api/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Preencha todos os campos.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Nova senha mínima: 6 caracteres.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(401).json({ error: 'Senha atual incorreta.' });
  db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res.json({ ok: true });
});

// ── Chat ──────────────────────────────────────────────────────────────────────
app.post('/api/chat', auth, async (req, res) => {
  const { messages, systemPrompt } = req.body;
  const userData = db.prepare('SELECT personal_api_key, personal_provider, personal_model FROM users WHERE id=?').get(req.user.id);

  let apiKey, provider, model;

  if (userData?.personal_api_key) {
    apiKey = userData.personal_api_key;
    provider = userData.personal_provider || 'groq';
    model = userData.personal_model || 'llama-3.3-70b-versatile';
  } else {
    const gKey = db.prepare('SELECT value FROM config WHERE key=?').get('global_api_key')?.value;
    if (!gKey) return res.status(503).json({ error: 'Nenhuma API key configurada. Contate o administrador ou adicione sua própria key em Configurações.' });
    apiKey = gKey;
    provider = db.prepare('SELECT value FROM config WHERE key=?').get('global_provider')?.value || 'groq';
    model = db.prepare('SELECT value FROM config WHERE key=?').get('global_model')?.value || '';
  }

  model = model || (provider === 'groq' ? 'llama-3.3-70b-versatile' : 'gemini-2.0-flash');

  try {
    const reply = provider === 'groq'
      ? await callGroq(apiKey, model, messages, systemPrompt)
      : await callGemini(apiKey, model, messages, systemPrompt);
    res.json({ reply, provider, model });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function callGroq(apiKey, model, messages, sys) {
  const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({
      model,
      messages: [{ role: 'system', content: sys || 'Você é um assistente prestativo. Responda em português.' }, ...messages],
      max_tokens: 2048, temperature: 0.7
    })
  });
  if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error?.message || `Groq erro ${r.status}`); }
  const d = await r.json();
  return d.choices?.[0]?.message?.content || 'Sem resposta.';
}

async function callGemini(apiKey, model, messages, sys) {
  const contents = messages.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }));
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      system_instruction: { parts: [{ text: sys || 'Você é um assistente prestativo. Responda em português.' }] },
      contents,
      generationConfig: { maxOutputTokens: 2048, temperature: 0.7 }
    })
  });
  if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error?.message || `Gemini erro ${r.status}`); }
  const d = await r.json();
  const text = d.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error('Resposta vazia do Gemini.');
  return text;
}

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/config', auth, role('creator','admin'), (req, res) => {
  const provider = db.prepare('SELECT value FROM config WHERE key=?').get('global_provider')?.value || 'groq';
  const model = db.prepare('SELECT value FROM config WHERE key=?').get('global_model')?.value || '';
  const raw = db.prepare('SELECT value FROM config WHERE key=?').get('global_api_key')?.value || '';
  res.json({ provider, model, keyMasked: raw ? raw.slice(0,8)+'••••••••••••' : null, hasKey: !!raw });
});

app.post('/api/admin/config', auth, role('creator'), (req, res) => {
  const { apiKey, provider, model } = req.body;
  if (!apiKey || !provider) return res.status(400).json({ error: 'API key e provedor obrigatórios.' });
  const u = db.prepare('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)');
  u.run('global_api_key', apiKey);
  u.run('global_provider', provider);
  u.run('global_model', model||'');
  res.json({ ok: true });
});

app.get('/api/admin/users', auth, role('creator','admin'), (req, res) => {
  const users = db.prepare('SELECT id, email, role, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.post('/api/admin/users', auth, role('creator','admin'), (req, res) => {
  const { email, password, role: newRole } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios.' });
  if (newRole === 'creator') return res.status(403).json({ error: 'Não é possível criar outro criador.' });
  if (newRole === 'admin' && req.user.role !== 'creator') return res.status(403).json({ error: 'Apenas o criador pode criar admins.' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.status(400).json({ error: 'Email já cadastrado.' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (email,password,role) VALUES (?,?,?)').run(email.toLowerCase(), hash, newRole||'user');
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/role', auth, role('creator'), (req, res) => {
  const { role: newRole } = req.body;
  if (newRole === 'creator') return res.status(400).json({ error: 'Não é possível promover para criador.' });
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (target.role === 'creator') return res.status(400).json({ error: 'Não é possível alterar o criador.' });
  db.prepare('UPDATE users SET role=? WHERE id=?').run(newRole, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', auth, role('creator','admin'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (target.role === 'creator') return res.status(400).json({ error: 'Não é possível deletar o criador.' });
  if (target.role === 'admin' && req.user.role !== 'creator') return res.status(403).json({ error: 'Apenas o criador pode remover admins.' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🚀 IA Chat rodando na porta ${PORT}`));
