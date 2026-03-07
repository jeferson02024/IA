const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexia-secret-2024';
const CREATOR_EMAIL = process.env.CREATOR_EMAIL || 'jefersonrotello@gmail.com';
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
});

const q = (sql, p=[]) => pool.query(sql, p);

async function initDB() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', personal_groq_key TEXT, personal_gemini_key TEXT,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )`);
  await q(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`);
  await q(`CREATE TABLE IF NOT EXISTS conversations (
    id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT 'Nova conversa', provider TEXT NOT NULL DEFAULT 'groq',
    model TEXT NOT NULL DEFAULT 'llama-3.3-70b-versatile', messages TEXT NOT NULL DEFAULT '[]',
    updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()), created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )`);

  const ex = await q('SELECT id FROM users WHERE email=$1', [CREATOR_EMAIL]);
  if (!ex.rows.length) {
    const pwd = process.env.CREATOR_PASSWORD || 'trocar123';
    await q('INSERT INTO users (email,password,role) VALUES ($1,$2,$3)', [CREATOR_EMAIL, bcrypt.hashSync(pwd,10), 'creator']);
    console.log('✅ Criador criado');
  }
  if (process.env.GROQ_API_KEY) await q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', ['global_groq_key', process.env.GROQ_API_KEY]);
  if (process.env.GEMINI_API_KEY) await q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', ['global_gemini_key', process.env.GEMINI_API_KEY]);
  console.log('✅ Banco pronto!');
}

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

app.post('/api/register', async (req,res) => {
  try {
    const {email,password} = req.body;
    if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
    if (password.length<6) return res.status(400).json({ error:'Senha mínima: 6 caracteres.' });
    const ex = await q('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (ex.rows.length) return res.status(400).json({ error:'Email já cadastrado.' });
    const r = await q('INSERT INTO users (email,password,role) VALUES ($1,$2,$3) RETURNING *', [email.toLowerCase(), bcrypt.hashSync(password,10), 'user']);
    const user = r.rows[0];
    res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
    res.json({ ok:true, user:{ email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/login', async (req,res) => {
  try {
    const {email,password} = req.body;
    const r = await q('SELECT * FROM users WHERE email=$1', [(email||'').toLowerCase()]);
    const user = r.rows[0];
    if (!user||!bcrypt.compareSync(password,user.password)) return res.status(401).json({ error:'Email ou senha incorretos.' });
    res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
    res.json({ ok:true, user:{ email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/logout', (req,res) => { res.clearCookie('token'); res.json({ ok:true }); });

app.get('/api/me', auth, async (req,res) => {
  try {
    const r = await q('SELECT id,email,role,personal_groq_key,personal_gemini_key FROM users WHERE id=$1', [req.user.id]);
    const user = r.rows[0];
    res.json({ id:user.id, email:user.email, role:user.role, hasGroqKey:!!user.personal_groq_key, hasGeminiKey:!!user.personal_gemini_key });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/my-key', auth, async (req,res) => {
  try {
    const {groqKey,geminiKey} = req.body;
    if (groqKey!==undefined) await q('UPDATE users SET personal_groq_key=$1 WHERE id=$2', [groqKey||null, req.user.id]);
    if (geminiKey!==undefined) await q('UPDATE users SET personal_gemini_key=$1 WHERE id=$2', [geminiKey||null, req.user.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/change-password', auth, async (req,res) => {
  try {
    const {currentPassword,newPassword} = req.body;
    if (!currentPassword||!newPassword) return res.status(400).json({ error:'Preencha todos os campos.' });
    if (newPassword.length<6) return res.status(400).json({ error:'Nova senha mínima: 6 caracteres.' });
    const r = await q('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!bcrypt.compareSync(currentPassword,r.rows[0].password)) return res.status(401).json({ error:'Senha atual incorreta.' });
    await q('UPDATE users SET password=$1 WHERE id=$2', [bcrypt.hashSync(newPassword,10), req.user.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/conversations', auth, async (req,res) => {
  try {
    const r = await q('SELECT id,title,provider,model,updated_at FROM conversations WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50', [req.user.id]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/conversations/:id', auth, async (req,res) => {
  try {
    const r = await q('SELECT * FROM conversations WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error:'Não encontrada.' });
    const conv = r.rows[0];
    res.json({ ...conv, messages: JSON.parse(conv.messages) });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/conversations', auth, async (req,res) => {
  try {
    const {title,provider,model} = req.body;
    const r = await q('INSERT INTO conversations (user_id,title,provider,model,messages) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, title||'Nova conversa', provider||'groq', model||'llama-3.3-70b-versatile', '[]']);
    const conv = r.rows[0];
    res.json({ ...conv, messages:[] });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.delete('/api/conversations/:id', auth, async (req,res) => {
  try {
    await q('DELETE FROM conversations WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/chat', auth, async (req,res) => {
  try {
    const {messages, systemPrompt, provider, model, conversationId} = req.body;
    if (!provider) return res.status(400).json({ error:'Provedor não informado.' });
    const ur = await q('SELECT personal_groq_key,personal_gemini_key FROM users WHERE id=$1', [req.user.id]);
    const userData = ur.rows[0];
    let apiKey;
    if (provider==='groq') {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_groq_key']);
      apiKey = userData?.personal_groq_key || ck.rows[0]?.value || process.env.GROQ_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Groq configurada.' });
    } else {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_gemini_key']);
      apiKey = userData?.personal_gemini_key || ck.rows[0]?.value || process.env.GEMINI_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Gemini configurada.' });
    }
    const usedModel = model || (provider==='groq' ? 'llama-3.3-70b-versatile' : 'gemini-2.0-flash');
    const reply = provider==='groq' ? await callGroq(apiKey, usedModel, messages, systemPrompt) : await callGemini(apiKey, usedModel, messages, systemPrompt);
    if (conversationId) {
      const cr = await q('SELECT * FROM conversations WHERE id=$1 AND user_id=$2', [conversationId, req.user.id]);
      if (cr.rows.length) {
        const conv = cr.rows[0];
        const updated = [...messages, { role:'assistant', content:reply }];
        let title = conv.title;
        if (title==='Nova conversa' && messages.length===1) title = (messages[0].content||'').slice(0,40);
        await q('UPDATE conversations SET messages=$1,title=$2,updated_at=$3 WHERE id=$4',
          [JSON.stringify(updated), title, Math.floor(Date.now()/1000), conversationId]);
      }
    }
    res.json({ reply });
  } catch(e) { res.status(500).json({ error:e.message }); }
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

app.get('/api/admin/config', auth, role('creator','admin'), async (req,res) => {
  try {
    const r = await q("SELECT key,value FROM config WHERE key IN ('global_groq_key','global_gemini_key','global_groq_model','global_gemini_model')");
    const cfg = {};
    r.rows.forEach(row => cfg[row.key]=row.value);
    res.json({
      groqKeyMasked: cfg.global_groq_key?cfg.global_groq_key.slice(0,8)+'••••':null, hasGroqKey:!!cfg.global_groq_key, groqModel:cfg.global_groq_model||'llama-3.3-70b-versatile',
      geminiKeyMasked: cfg.global_gemini_key?cfg.global_gemini_key.slice(0,8)+'••••':null, hasGeminiKey:!!cfg.global_gemini_key, geminiModel:cfg.global_gemini_model||'gemini-2.0-flash',
    });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/admin/config', auth, role('creator'), async (req,res) => {
  try {
    const {groqKey,geminiKey,groqModel,geminiModel} = req.body;
    const upsert = (k,v) => q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [k,v]);
    if (groqKey) await upsert('global_groq_key', groqKey);
    if (geminiKey) await upsert('global_gemini_key', geminiKey);
    if (groqModel) await upsert('global_groq_model', groqModel);
    if (geminiModel) await upsert('global_gemini_model', geminiModel);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/users', auth, role('creator','admin'), async (req,res) => {
  try {
    const r = await q('SELECT id,email,role,created_at,personal_groq_key,personal_gemini_key FROM users ORDER BY created_at DESC');
    res.json(r.rows.map(u=>({...u,hasGroqKey:!!u.personal_groq_key,hasGeminiKey:!!u.personal_gemini_key,personal_groq_key:undefined,personal_gemini_key:undefined})));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/admin/users', auth, role('creator','admin'), async (req,res) => {
  try {
    const {email,password,role:newRole} = req.body;
    if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
    if (newRole==='creator') return res.status(403).json({ error:'Não é possível criar outro criador.' });
    if (newRole==='admin'&&req.user.role!=='creator') return res.status(403).json({ error:'Apenas o criador pode criar admins.' });
    const ex = await q('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (ex.rows.length) return res.status(400).json({ error:'Email já cadastrado.' });
    await q('INSERT INTO users (email,password,role) VALUES ($1,$2,$3)', [email.toLowerCase(), bcrypt.hashSync(password,10), newRole||'user']);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.patch('/api/admin/users/:id/role', auth, role('creator'), async (req,res) => {
  try {
    const {role:newRole} = req.body;
    if (newRole==='creator') return res.status(400).json({ error:'Operação não permitida.' });
    const t = await q('SELECT * FROM users WHERE id=$1', [req.params.id]);
    if (!t.rows.length||t.rows[0].role==='creator') return res.status(400).json({ error:'Operação não permitida.' });
    await q('UPDATE users SET role=$1 WHERE id=$2', [newRole, req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.delete('/api/admin/users/:id', auth, role('creator','admin'), async (req,res) => {
  try {
    const t = await q('SELECT * FROM users WHERE id=$1', [req.params.id]);
    if (!t.rows.length) return res.status(404).json({ error:'Usuário não encontrado.' });
    if (t.rows[0].role==='creator') return res.status(400).json({ error:'Não é possível deletar o criador.' });
    if (t.rows[0].role==='admin'&&req.user.role!=='creator') return res.status(403).json({ error:'Apenas o criador pode remover admins.' });
    await q('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, async () => {
  console.log(`🚀 Nexia rodando na porta ${PORT}`);
  await initDB().catch(console.error);
});
