const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexia-secret-2024';
const CREATOR_EMAIL = process.env.CREATOR_EMAIL || 'jefersonrotello@gmail.com';
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database('/tmp/nexia.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    personal_groq_key TEXT,
    personal_gemini_key TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT 'Nova conversa',
    provider TEXT NOT NULL DEFAULT 'groq',
    model TEXT NOT NULL DEFAULT 'llama-3.3-70b-versatile',
    messages TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER DEFAULT (strftime('%s','now')),
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

function ensureCreator() {
  const pwd = process.env.CREATOR_PASSWORD || 'trocar123';
  if (!db.prepare('SELECT id FROM users WHERE email=?').get(CREATOR_EMAIL)) {
    db.prepare('INSERT INTO users (email,password,role) VALUES (?,?,?)').run(CREATOR_EMAIL, bcrypt.hashSync(pwd,10), 'creator');
    console.log('✅ Criador criado');
  }
}
ensureCreator();

function seedEnvKeys() {
  if (process.env.GROQ_API_KEY) db.prepare('INSERT OR IGNORE INTO config (key,value) VALUES (?,?)').run('global_groq_key', process.env.GROQ_API_KEY);
  if (process.env.GEMINI_API_KEY) db.prepare('INSERT OR IGNORE INTO config (key,value) VALUES (?,?)').run('global_gemini_key', process.env.GEMINI_API_KEY);
}
seedEnvKeys();

function signToken(u) { return jwt.sign({ id:u.id, email:u.email, role:u.role }, JWT_SECRET, { expiresIn:'7d' }); }
function auth(req,res,next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ','');
  if (!token) return res.status(401).json({ error:'Não autenticado.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error:'Sessão expirada.' }); }
}
function role(...roles) {
  return (req,res,next) => { if (!roles.includes(req.user.role)) return res.status(403).json({ error:'Acesso negado.' }); next(); };
}

app.post('/api/register', (req,res) => {
  const {email,password} = req.body;
  if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
  if (password.length<6) return res.status(400).json({ error:'Senha mínima: 6 caracteres.' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.status(400).json({ error:'Email já cadastrado.' });
  const r = db.prepare('INSERT INTO users (email,password,role) VALUES (?,?,?)').run(email.toLowerCase(), bcrypt.hashSync(password,10), 'user');
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
  res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
  res.json({ ok:true, user:{ email:user.email, role:user.role } });
});

app.post('/api/login', (req,res) => {
  const {email,password} = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase());
  if (!user||!bcrypt.compareSync(password,user.password)) return res.status(401).json({ error:'Email ou senha incorretos.' });
  res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
  res.json({ ok:true, user:{ email:user.email, role:user.role } });
});

app.post('/api/logout', (req,res) => { res.clearCookie('token'); res.json({ ok:true }); });

app.get('/api/me', auth, (req,res) => {
  const user = db.prepare('SELECT id,email,role FROM users WHERE id=?').get(req.user.id);
  const keys = db.prepare('SELECT personal_groq_key,personal_gemini_key FROM users WHERE id=?').get(req.user.id);
  res.json({ ...user, hasGroqKey:!!keys.personal_groq_key, hasGeminiKey:!!keys.personal_gemini_key });
});

app.post('/api/my-key', auth, (req,res) => {
  const {groqKey,geminiKey} = req.body;
  if (groqKey!==undefined) db.prepare('UPDATE users SET personal_groq_key=? WHERE id=?').run(groqKey||null, req.user.id);
  if (geminiKey!==undefined) db.prepare('UPDATE users SET personal_gemini_key=? WHERE id=?').run(geminiKey||null, req.user.id);
  res.json({ ok:true });
});

app.post('/api/change-password', auth, (req,res) => {
  const {currentPassword,newPassword} = req.body;
  if (!currentPassword||!newPassword) return res.status(400).json({ error:'Preencha todos os campos.' });
  if (newPassword.length<6) return res.status(400).json({ error:'Nova senha mínima: 6 caracteres.' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword,user.password)) return res.status(401).json({ error:'Senha atual incorreta.' });
  db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(newPassword,10), req.user.id);
  res.json({ ok:true });
});

app.get('/api/conversations', auth, (req,res) => {
  res.json(db.prepare('SELECT id,title,provider,model,updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC LIMIT 50').all(req.user.id));
});

app.get('/api/conversations/:id', auth, (req,res) => {
  const conv = db.prepare('SELECT * FROM conversations WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!conv) return res.status(404).json({ error:'Não encontrada.' });
  res.json({ ...conv, messages: JSON.parse(conv.messages) });
});

app.post('/api/conversations', auth, (req,res) => {
  const {title,provider,model} = req.body;
  const r = db.prepare('INSERT INTO conversations (user_id,title,provider,model,messages) VALUES (?,?,?,?,?)').run(req.user.id, title||'Nova conversa', provider||'groq', model||'llama-3.3-70b-versatile', '[]');
  const conv = db.prepare('SELECT * FROM conversations WHERE id=?').get(r.lastInsertRowid);
  res.json({ ...conv, messages:[] });
});

app.delete('/api/conversations/:id', auth, (req,res) => {
  db.prepare('DELETE FROM conversations WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok:true });
});

app.post('/api/chat', auth, async (req,res) => {
  const {messages, systemPrompt, provider, model, conversationId} = req.body;
  if (!provider) return res.status(400).json({ error:'Provedor não informado.' });
  const userData = db.prepare('SELECT personal_groq_key,personal_gemini_key FROM users WHERE id=?').get(req.user.id);
  let apiKey;
  if (provider==='groq') {
    apiKey = userData?.personal_groq_key || db.prepare('SELECT value FROM config WHERE key=?').get('global_groq_key')?.value || process.env.GROQ_API_KEY;
    if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Groq configurada.' });
  } else {
    apiKey = userData?.personal_gemini_key || db.prepare('SELECT value FROM config WHERE key=?').get('global_gemini_key')?.value || process.env.GEMINI_API_KEY;
    if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Gemini configurada.' });
  }
  const usedModel = model || (provider==='groq' ? 'llama-3.3-70b-versatile' : 'gemini-2.0-flash');
  try {
    const reply = provider==='groq' ? await callGroq(apiKey, usedModel, messages, systemPrompt) : await callGemini(apiKey, usedModel, messages, systemPrompt);
    if (conversationId) {
      const conv = db.prepare('SELECT * FROM conversations WHERE id=? AND user_id=?').get(conversationId, req.user.id);
      if (conv) {
        const updated = [...messages, { role:'assistant', content:reply }];
        let title = conv.title;
        if (title==='Nova conversa' && messages.length===1) title = (messages[0].content||'').slice(0,40);
        db.prepare('UPDATE conversations SET messages=?,title=?,updated_at=? WHERE id=?').run(JSON.stringify(updated), title, Math.floor(Date.now()/1000), conversationId);
      }
    }
    res.json({ reply });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

async function callGroq(apiKey, model, messages, sys) {
  const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`},
    body: JSON.stringify({ model, messages:[{role:'system',content:sys||'Você é um assistente prestativo. Responda em português.'},...messages], max_tokens:2048, temperature:0.7 })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`Groq erro ${r.status}`); }
  return (await r.json()).choices?.[0]?.message?.content||'Sem resposta.';
}

async function callGemini(apiKey, model, messages, sys) {
  const contents = messages.map(m => ({ role:m.role==='assistant'?'model':'user', parts:[{text:m.content}] }));
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ system_instruction:{parts:[{text:sys||'Você é um assistente prestativo. Responda em português.'}]}, contents, generationConfig:{maxOutputTokens:2048,temperature:0.7} })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`Gemini erro ${r.status}`); }
  return (await r.json()).candidates?.[0]?.content?.parts?.[0]?.text||'Sem resposta.';
}

app.get('/api/admin/config', auth, role('creator','admin'), (req,res) => {
  const g = k => db.prepare('SELECT value FROM config WHERE key=?').get(k)?.value||'';
  res.json({
    groqKeyMasked: g('global_groq_key')?g('global_groq_key').slice(0,8)+'••••':null, hasGroqKey:!!g('global_groq_key'), groqModel:g('global_groq_model')||'llama-3.3-70b-versatile',
    geminiKeyMasked: g('global_gemini_key')?g('global_gemini_key').slice(0,8)+'••••':null, hasGeminiKey:!!g('global_gemini_key'), geminiModel:g('global_gemini_model')||'gemini-2.0-flash',
  });
});

app.post('/api/admin/config', auth, role('creator'), (req,res) => {
  const u = db.prepare('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)');
  const {groqKey,geminiKey,groqModel,geminiModel} = req.body;
  if (groqKey) u.run('global_groq_key',groqKey);
  if (geminiKey) u.run('global_gemini_key',geminiKey);
  if (groqModel) u.run('global_groq_model',groqModel);
  if (geminiModel) u.run('global_gemini_model',geminiModel);
  res.json({ ok:true });
});

app.get('/api/admin/users', auth, role('creator','admin'), (req,res) => {
  const users = db.prepare('SELECT id,email,role,created_at,personal_groq_key,personal_gemini_key FROM users ORDER BY created_at DESC').all();
  res.json(users.map(u=>({...u,hasGroqKey:!!u.personal_groq_key,hasGeminiKey:!!u.personal_gemini_key,personal_groq_key:undefined,personal_gemini_key:undefined})));
});

app.post('/api/admin/users', auth, role('creator','admin'), (req,res) => {
  const {email,password,role:newRole} = req.body;
  if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
  if (newRole==='creator') return res.status(403).json({ error:'Não é possível criar outro criador.' });
  if (newRole==='admin'&&req.user.role!=='creator') return res.status(403).json({ error:'Apenas o criador pode criar admins.' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.status(400).json({ error:'Email já cadastrado.' });
  db.prepare('INSERT INTO users (email,password,role) VALUES (?,?,?)').run(email.toLowerCase(), bcrypt.hashSync(password,10), newRole||'user');
  res.json({ ok:true });
});

app.patch('/api/admin/users/:id/role', auth, role('creator'), (req,res) => {
  const {role:newRole} = req.body;
  if (newRole==='creator') return res.status(400).json({ error:'Operação não permitida.' });
  const t = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!t||t.role==='creator') return res.status(400).json({ error:'Operação não permitida.' });
  db.prepare('UPDATE users SET role=? WHERE id=?').run(newRole,req.params.id);
  res.json({ ok:true });
});

app.delete('/api/admin/users/:id', auth, role('creator','admin'), (req,res) => {
  const t = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!t) return res.status(404).json({ error:'Usuário não encontrado.' });
  if (t.role==='creator') return res.status(400).json({ error:'Não é possível deletar o criador.' });
  if (t.role==='admin'&&req.user.role!=='creator') return res.status(403).json({ error:'Apenas o criador pode remover admins.' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok:true });
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, () => console.log(`🚀 Nexia rodando na porta ${PORT}`));
