const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexia-secret-2024';
const CREATOR_EMAIL = process.env.CREATOR_EMAIL || 'jefersonrotello@gmail.com';
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

// Supabase REST API
const SB_URL = 'https://olbzdxculbwkdfkedekz.supabase.co';
const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9sYnpkeGN1bGJ3a2Rma2VkZWt6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI4NDYwNDUsImV4cCI6MjA4ODQyMjA0NX0.CRTaKufSTrcK1tObM8ihXqhIClB-plhjWrwBK-c9-Bs';

const sb = {
  async query(table, method='GET', body=null, filters='') {
    const url = `${SB_URL}/rest/v1/${table}${filters}`;
    const opts = {
      method,
      headers: {
        'apikey': SB_KEY,
        'Authorization': `Bearer ${SB_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': method==='POST' ? 'return=representation' : method==='PATCH' ? 'return=representation' : '',
      }
    };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(url, opts);
    if (method==='DELETE') return [];
    const text = await r.text();
    if (!text) return [];
    return JSON.parse(text);
  },
  async get(table, filters='') { return this.query(table,'GET',null,filters); },
  async insert(table, body) { return this.query(table,'POST',body); },
  async update(table, body, filters) { return this.query(table,'PATCH',body,filters); },
  async delete(table, filters) { return this.query(table,'DELETE',null,filters); },
};

app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Init: criar tabelas via SQL RPC ──────────────────────────────────────────
async function initDB() {
  const sql = async (query) => {
    const r = await fetch(`${SB_URL}/rest/v1/rpc/exec_sql`, {
      method: 'POST',
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    return r;
  };

  // Criar tabelas direto pelo Supabase dashboard já foi feito, então só verificamos o criador
  try {
    const users = await sb.get('users', `?email=eq.${encodeURIComponent(CREATOR_EMAIL)}`);
    if (!users.length) {
      const pwd = process.env.CREATOR_PASSWORD || 'trocar123';
      await sb.insert('users', { email: CREATOR_EMAIL, password: bcrypt.hashSync(pwd,10), role: 'creator' });
      console.log('✅ Criador criado');
    }

    // Seed env keys
    if (process.env.GROQ_API_KEY) {
      const ex = await sb.get('config', `?key=eq.global_groq_key`);
      if (!ex.length) await sb.insert('config', { key:'global_groq_key', value: process.env.GROQ_API_KEY });
    }
    if (process.env.GEMINI_API_KEY) {
      const ex = await sb.get('config', `?key=eq.global_gemini_key`);
      if (!ex.length) await sb.insert('config', { key:'global_gemini_key', value: process.env.GEMINI_API_KEY });
    }
    console.log('✅ Supabase conectado!');
  } catch(e) {
    console.error('Erro init:', e.message);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
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

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req,res) => {
  try {
    const {email,password} = req.body;
    if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
    if (password.length<6) return res.status(400).json({ error:'Senha mínima: 6 caracteres.' });
    const ex = await sb.get('users', `?email=eq.${encodeURIComponent(email.toLowerCase())}`);
    if (ex.length) return res.status(400).json({ error:'Email já cadastrado.' });
    const rows = await sb.insert('users', { email:email.toLowerCase(), password:bcrypt.hashSync(password,10), role:'user' });
    const user = rows[0];
    res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
    res.json({ ok:true, user:{ email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/login', async (req,res) => {
  try {
    const {email,password} = req.body;
    const rows = await sb.get('users', `?email=eq.${encodeURIComponent((email||'').toLowerCase())}`);
    const user = rows[0];
    if (!user||!bcrypt.compareSync(password,user.password)) return res.status(401).json({ error:'Email ou senha incorretos.' });
    res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
    res.json({ ok:true, user:{ email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/logout', (req,res) => { res.clearCookie('token'); res.json({ ok:true }); });

app.get('/api/me', auth, async (req,res) => {
  try {
    const rows = await sb.get('users', `?id=eq.${req.user.id}`);
    const user = rows[0];
    if (!user) return res.status(404).json({ error:'Não encontrado.' });
    res.json({ id:user.id, email:user.email, role:user.role, hasGroqKey:!!user.personal_groq_key, hasGeminiKey:!!user.personal_gemini_key });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/my-key', auth, async (req,res) => {
  try {
    const {groqKey,geminiKey} = req.body;
    const upd = {};
    if (groqKey!==undefined) upd.personal_groq_key = groqKey||null;
    if (geminiKey!==undefined) upd.personal_gemini_key = geminiKey||null;
    await sb.update('users', upd, `?id=eq.${req.user.id}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/change-password', auth, async (req,res) => {
  try {
    const {currentPassword,newPassword} = req.body;
    if (!currentPassword||!newPassword) return res.status(400).json({ error:'Preencha todos os campos.' });
    if (newPassword.length<6) return res.status(400).json({ error:'Nova senha mínima: 6 caracteres.' });
    const rows = await sb.get('users', `?id=eq.${req.user.id}`);
    const user = rows[0];
    if (!bcrypt.compareSync(currentPassword,user.password)) return res.status(401).json({ error:'Senha atual incorreta.' });
    await sb.update('users', { password:bcrypt.hashSync(newPassword,10) }, `?id=eq.${req.user.id}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── Conversations ─────────────────────────────────────────────────────────────
app.get('/api/conversations', auth, async (req,res) => {
  try {
    const rows = await sb.get('conversations', `?user_id=eq.${req.user.id}&order=updated_at.desc&limit=50&select=id,title,provider,model,updated_at`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/conversations/:id', auth, async (req,res) => {
  try {
    const rows = await sb.get('conversations', `?id=eq.${req.params.id}&user_id=eq.${req.user.id}`);
    if (!rows.length) return res.status(404).json({ error:'Não encontrada.' });
    const conv = rows[0];
    res.json({ ...conv, messages: JSON.parse(conv.messages||'[]') });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/conversations', auth, async (req,res) => {
  try {
    const {title,provider,model} = req.body;
    const rows = await sb.insert('conversations', {
      user_id:req.user.id, title:title||'Nova conversa',
      provider:provider||'groq', model:model||'llama-3.3-70b-versatile', messages:'[]'
    });
    const conv = rows[0];
    res.json({ ...conv, messages:[] });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.delete('/api/conversations/:id', auth, async (req,res) => {
  try {
    await sb.delete('conversations', `?id=eq.${req.params.id}&user_id=eq.${req.user.id}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── Chat ──────────────────────────────────────────────────────────────────────
app.post('/api/chat', auth, async (req,res) => {
  try {
    const {messages, systemPrompt, provider, model, conversationId} = req.body;
    if (!provider) return res.status(400).json({ error:'Provedor não informado.' });

    const userRows = await sb.get('users', `?id=eq.${req.user.id}`);
    const userData = userRows[0];

    let apiKey;
    if (provider==='groq') {
      const cfgRows = await sb.get('config', `?key=eq.global_groq_key`);
      apiKey = userData?.personal_groq_key || cfgRows[0]?.value || process.env.GROQ_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Groq configurada.' });
    } else {
      const cfgRows = await sb.get('config', `?key=eq.global_gemini_key`);
      apiKey = userData?.personal_gemini_key || cfgRows[0]?.value || process.env.GEMINI_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Gemini configurada.' });
    }

    const usedModel = model || (provider==='groq' ? 'llama-3.3-70b-versatile' : 'gemini-2.0-flash');
    const reply = provider==='groq'
      ? await callGroq(apiKey, usedModel, messages, systemPrompt)
      : await callGemini(apiKey, usedModel, messages, systemPrompt);

    if (conversationId) {
      const convRows = await sb.get('conversations', `?id=eq.${conversationId}&user_id=eq.${req.user.id}`);
      if (convRows.length) {
        const conv = convRows[0];
        const updated = [...messages, { role:'assistant', content:reply }];
        let title = conv.title;
        if (title==='Nova conversa' && messages.length===1) title = (messages[0].content||'').slice(0,40);
        await sb.update('conversations', {
          messages: JSON.stringify(updated),
          title,
          updated_at: Math.floor(Date.now()/1000)
        }, `?id=eq.${conversationId}`);
      }
    }
    res.json({ reply });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

async function callGroq(apiKey, model, messages, sys) {
  const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`},
    body: JSON.stringify({ model, messages:[{role:'system',content:sys||'Você é um assistente prestativo. Responda em português.'},...messages], max_tokens:2048, temperature:0.7 })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`Groq erro ${r.status}`); }
  const d = await r.json();
  return d.choices?.[0]?.message?.content||'Sem resposta.';
}

async function callGemini(apiKey, model, messages, sys) {
  const contents = messages.map(m => ({ role:m.role==='assistant'?'model':'user', parts:[{text:m.content}] }));
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ system_instruction:{parts:[{text:sys||'Você é um assistente prestativo. Responda em português.'}]}, contents, generationConfig:{maxOutputTokens:2048,temperature:0.7} })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`Gemini erro ${r.status}`); }
  const d = await r.json();
  return d.candidates?.[0]?.content?.parts?.[0]?.text||'Sem resposta.';
}

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/config', auth, role('creator','admin'), async (req,res) => {
  try {
    const rows = await sb.get('config', `?key=in.(global_groq_key,global_gemini_key,global_groq_model,global_gemini_model)`);
    const cfg = {};
    rows.forEach(r => cfg[r.key]=r.value);
    res.json({
      groqKeyMasked: cfg.global_groq_key?cfg.global_groq_key.slice(0,8)+'••••':null, hasGroqKey:!!cfg.global_groq_key, groqModel:cfg.global_groq_model||'llama-3.3-70b-versatile',
      geminiKeyMasked: cfg.global_gemini_key?cfg.global_gemini_key.slice(0,8)+'••••':null, hasGeminiKey:!!cfg.global_gemini_key, geminiModel:cfg.global_gemini_model||'gemini-2.0-flash',
    });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/admin/config', auth, role('creator'), async (req,res) => {
  try {
    const {groqKey,geminiKey,groqModel,geminiModel} = req.body;
    const upsert = async (k,v) => {
      const ex = await sb.get('config', `?key=eq.${k}`);
      if (ex.length) await sb.update('config', {value:v}, `?key=eq.${k}`);
      else await sb.insert('config', {key:k,value:v});
    };
    if (groqKey) await upsert('global_groq_key', groqKey);
    if (geminiKey) await upsert('global_gemini_key', geminiKey);
    if (groqModel) await upsert('global_groq_model', groqModel);
    if (geminiModel) await upsert('global_gemini_model', geminiModel);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/users', auth, role('creator','admin'), async (req,res) => {
  try {
    const rows = await sb.get('users', `?order=created_at.desc&select=id,email,role,created_at,personal_groq_key,personal_gemini_key`);
    res.json(rows.map(u=>({...u, hasGroqKey:!!u.personal_groq_key, hasGeminiKey:!!u.personal_gemini_key, personal_groq_key:undefined, personal_gemini_key:undefined})));
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/admin/users', auth, role('creator','admin'), async (req,res) => {
  try {
    const {email,password,role:newRole} = req.body;
    if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
    if (newRole==='creator') return res.status(403).json({ error:'Não é possível criar outro criador.' });
    if (newRole==='admin'&&req.user.role!=='creator') return res.status(403).json({ error:'Apenas o criador pode criar admins.' });
    const ex = await sb.get('users', `?email=eq.${encodeURIComponent(email.toLowerCase())}`);
    if (ex.length) return res.status(400).json({ error:'Email já cadastrado.' });
    await sb.insert('users', { email:email.toLowerCase(), password:bcrypt.hashSync(password,10), role:newRole||'user' });
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.patch('/api/admin/users/:id/role', auth, role('creator'), async (req,res) => {
  try {
    const {role:newRole} = req.body;
    if (newRole==='creator') return res.status(400).json({ error:'Operação não permitida.' });
    const rows = await sb.get('users', `?id=eq.${req.params.id}`);
    if (!rows.length||rows[0].role==='creator') return res.status(400).json({ error:'Operação não permitida.' });
    await sb.update('users', {role:newRole}, `?id=eq.${req.params.id}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.delete('/api/admin/users/:id', auth, role('creator','admin'), async (req,res) => {
  try {
    const rows = await sb.get('users', `?id=eq.${req.params.id}`);
    if (!rows.length) return res.status(404).json({ error:'Usuário não encontrado.' });
    if (rows[0].role==='creator') return res.status(400).json({ error:'Não é possível deletar o criador.' });
    if (rows[0].role==='admin'&&req.user.role!=='creator') return res.status(403).json({ error:'Apenas o criador pode remover admins.' });
    await sb.delete('users', `?id=eq.${req.params.id}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, async () => {
  console.log(`🚀 Nexia rodando na porta ${PORT}`);
  await initDB();
});
