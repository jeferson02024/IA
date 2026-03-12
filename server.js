const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const JSZip = require('jszip');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const nodemailer = require('nodemailer');
const mailer = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.GMAIL_USER || 'nexiasuporte646@gmail.com',
    pass: process.env.GMAIL_PASS || 'lqfuxaeqdihhpcvh'
  },
  tls: { rejectUnauthorized: false }
});

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '932508182659-gevg6ph5ief33eq5jq532bqib6g4n3hb.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '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';
const BASE_URL = process.env.BASE_URL || 'https://ia-2-uvqg.onrender.com';
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexia-secret-2024';
const CREATOR_EMAIL = process.env.CREATOR_EMAIL || 'jefersonrotello@gmail.com';
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.use(session({ secret: JWT_SECRET, resave:false, saveUninitialized:false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  keepAlive: true,
});

pool.on('error', (err) => {
  console.error('Pool error (auto-recovering):', err.message);
});

const q = async (sql, p=[]) => {
  try {
    return await pool.query(sql, p);
  } catch(err) {
    if (err.code === 'ECONNRESET' || err.code === 'ECONNREFUSED' || err.message.includes('Connection terminated')) {
      console.log('[db] reconectando...');
      await new Promise(r => setTimeout(r, 1000));
      return await pool.query(sql, p);
    }
    throw err;
  }
};

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try { const r = await q('SELECT * FROM users WHERE id=$1',[id]); done(null, r.rows[0]||false); }
  catch(e) { done(e); }
});

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: BASE_URL + '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value.toLowerCase();
    let r = await q('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rows.length) {
      r = await q('INSERT INTO users (email,password,role) VALUES ($1,$2,$3) RETURNING *',
        [email, 'google-oauth', 'user']);
    }
    done(null, r.rows[0]);
  } catch(e) { done(e); }
}));

async function initDB() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', personal_groq_key TEXT, personal_gemini_key TEXT,
    personal_mistral_key TEXT, personal_openrouter_key TEXT, personal_deepseek_key TEXT,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )`);
  await q(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`);
  await q(`CREATE TABLE IF NOT EXISTS shared_rooms (
    code TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    participants TEXT NOT NULL DEFAULT '[]',
    messages TEXT NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
  )`);
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
  if (process.env.OPENROUTER_API_KEY) await q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', ['global_openrouter_key', process.env.OPENROUTER_API_KEY]);
  if (process.env.TOGETHER_API_KEY) await q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', ['global_together_key', process.env.TOGETHER_API_KEY]);
  await q(`CREATE TABLE IF NOT EXISTS reset_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at BIGINT NOT NULL
  )`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS personal_openrouter_key TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS personal_mistral_key TEXT`);
  await q(`CREATE TABLE IF NOT EXISTS backup_keys (
    id SERIAL PRIMARY KEY,
    provider TEXT NOT NULL,
    key_value TEXT NOT NULL,
    label TEXT,
    active BOOLEAN DEFAULT true,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen BIGINT DEFAULT 0`);
  await q(`CREATE TABLE IF NOT EXISTS support_tickets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    user_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'app',
    status TEXT NOT NULL DEFAULT 'open',
    assigned_to INTEGER DEFAULT NULL,
    assigned_email TEXT DEFAULT NULL,
    rating INTEGER DEFAULT NULL,
    rating_comment TEXT DEFAULT NULL,
    messages JSONB NOT NULL DEFAULT '[]',
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    closed_at BIGINT DEFAULT NULL
  )`);
  console.log('✅ Banco pronto!');
}

function signToken(u) { return jwt.sign({ id:u.id, email:u.email, role:u.role }, JWT_SECRET, { expiresIn:'7d' }); }
function auth(req,res,next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ','');
  if (!token) return res.status(401).json({ error:'Não autenticado.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    // Update last_seen async (don't await to not slow down requests)
    pool.query('UPDATE users SET last_seen=$1 WHERE id=$2', [Math.floor(Date.now()/1000), req.user.id]).catch(()=>{});
    next();
  }
  catch { res.status(401).json({ error:'Sessão expirada.' }); }
}
// Roles: creator > subdono > admin > vip > user
function role(...roles) {
  return (req,res,next) => { if (!roles.includes(req.user.role)) return res.status(403).json({ error:'Acesso negado.' }); next(); };
}

app.post('/api/register', async (req,res) => {
  try {
    const {email,password} = req.body;
    if (!email||!password) return res.status(400).json({ error:'Email e senha obrigatórios.' });
    if (password.length<6) return res.status(400).json({ error:'Senha mínima: 6 caracteres.' });
    // Check if registration is blocked
    const regCfg = await q("SELECT value FROM config WHERE key='allowRegistration'");
    if (regCfg.rows[0]?.value === 'false') return res.status(403).json({ error:'Cadastro de novos usuários está temporariamente desativado.' });
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
    // Log login
    loginLog.push({ email: user.email, role: user.role, ts: Date.now() });
    if (loginLog.length > 100) loginLog.shift();
    res.cookie('token', signToken(user), { httpOnly:true, maxAge:7*24*60*60*1000 });
    res.json({ ok:true, user:{ email:user.email, role:user.role } });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/logout', (req,res) => { res.clearCookie('token'); res.json({ ok:true }); });

app.get('/api/me', auth, async (req,res) => {
  try {
    const r = await q('SELECT id,email,role,personal_groq_key,personal_gemini_key,personal_openrouter_key,personal_deepseek_key FROM users WHERE id=$1', [req.user.id]);
    const user = r.rows[0];
    res.json({ id:user.id, email:user.email, role:user.role, hasGroqKey:!!user.personal_groq_key, hasGeminiKey:!!user.personal_gemini_key, hasMistralKey:!!user.personal_mistral_key, hasOpenrouterKey:!!user.personal_openrouter_key, hasDeepseekKey:!!user.personal_deepseek_key });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/my-key', auth, async (req,res) => {
  try {
    const {groqKey,geminiKey} = req.body;
    if (groqKey!==undefined) await q('UPDATE users SET personal_groq_key=$1 WHERE id=$2', [groqKey||null, req.user.id]);
    if (geminiKey!==undefined) await q('UPDATE users SET personal_gemini_key=$1 WHERE id=$2', [geminiKey||null, req.user.id]);
    const {mistralKey, openrouterKey, deepseekKey} = req.body;
    if (mistralKey!==undefined) await q('UPDATE users SET personal_mistral_key=$1 WHERE id=$2', [mistralKey||null, req.user.id]);
    if (openrouterKey!==undefined) await q('UPDATE users SET personal_openrouter_key=$1 WHERE id=$2', [openrouterKey||null, req.user.id]);
    if (deepseekKey!==undefined) await q('UPDATE users SET personal_deepseek_key=$1 WHERE id=$2', [deepseekKey||null, req.user.id]);
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


app.post('/api/upload', auth, async (req,res) => {
  try {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      const body = Buffer.concat(chunks);
      const contentType = req.headers['content-type'] || '';
      const boundary = contentType.split('boundary=')[1];
      if (!boundary) return res.status(400).json({ error: 'Requisição inválida.' });

      const boundaryBuf = Buffer.from('--' + boundary);
      const parts = [];
      let start = 0;
      while (true) {
        const idx = body.indexOf(boundaryBuf, start);
        if (idx === -1) break;
        const end = body.indexOf(boundaryBuf, idx + boundaryBuf.length);
        if (end === -1) break;
        parts.push(body.slice(idx + boundaryBuf.length + 2, end - 2));
        start = end;
      }

      for (const part of parts) {
        const headerEnd = part.indexOf('\r\n\r\n');
        if (headerEnd === -1) continue;
        const headers = part.slice(0, headerEnd).toString();
        const content = part.slice(headerEnd + 4);
        const nameMatch = headers.match(/name="([^"]+)"/);
        const filenameMatch = headers.match(/filename="([^"]+)"/);
        if (!nameMatch || nameMatch[1] !== 'file' || !filenameMatch) continue;
        const filename = filenameMatch[1];
        const ext = filename.split('.').pop().toLowerCase();

        // Imagens
        const imageExts = ['jpg','jpeg','png','gif','webp'];
        if (imageExts.includes(ext)) {
          const mimeMap = {jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',gif:'image/gif',webp:'image/webp'};
          return res.json({ type:'image', mimeType: mimeMap[ext]||'image/jpeg', base64: content.toString('base64') });
        }

        // ZIP — extrai todos os arquivos de texto
        if (ext === 'zip') {
          const zip = await JSZip.loadAsync(content);
          const textExts = ['js','ts','py','html','css','json','md','txt','sh','jsx','tsx','vue','php','go','rs','java','cpp','c','env','yaml','yml','toml','xml','sql'];
          let extracted = [];
          for (const [name, file] of Object.entries(zip.files)) {
            if (file.dir) continue;
            const fext = name.split('.').pop().toLowerCase();
            if (!textExts.includes(fext)) continue;
            const text = await file.async('string');
            extracted.push({ name, content: text.slice(0, 10000) });
            if (extracted.length >= 30) break; // limite de 30 arquivos
          }
          if (!extracted.length) return res.json({ type:'text', filename, content: '[ZIP sem arquivos de texto legíveis]' });
          const summary = extracted.map(f => `### ${f.name}
\`\`\`
${f.content}
\`\`\``).join('\n\n');
          return res.json({ type:'zip', filename, files: extracted, content: summary, fileCount: extracted.length });
        }

        // Texto normal
        return res.json({ type:'text', filename, content: content.toString('utf-8').slice(0, 50000) });
      }
      res.status(400).json({ error: 'Nenhum arquivo encontrado.' });
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/conversations', auth, async (req,res) => {
  try {
    const r = await q('SELECT id,title,provider,model,updated_at FROM conversations WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [req.user.id]);
    console.log('Conversas user', req.user.id, ':', r.rows.length);
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
    const {messages: rawMessages, systemPrompt: clientSystemPrompt, provider, model, conversationId} = req.body;
    if (!provider) return res.status(400).json({ error:'Provedor não informado.' });
    console.log('[chat] provider:', provider, 'msgs:', (rawMessages||[]).length);

    // Load global systemPrompt from DB (personality setting)
    let systemPrompt = clientSystemPrompt;
    if (!systemPrompt) {
      const sp = await q("SELECT value FROM config WHERE key='systemPrompt'");
      systemPrompt = sp.rows[0]?.value || 'Você é Nexia, assistente de IA. Responda sempre em português.';
    }
    // Always append image generation rules
    const imageRules = '\n\nREGRAS DE IMAGEM (OBRIGATÓRIO):\n1. SÓ use a tag ##IMG## se o usuário EXPLICITAMENTE pedir para CRIAR, GERAR ou DESENHAR uma imagem/foto/ilustração.\n2. Quando gerar imagem: escreva uma frase curta em português e adicione ##IMG## descrição detalhada em inglês ##ENDIMG##.\n3. NUNCA exiba a tag ##IMG## como texto visível.\n4. Para conversas normais, responda normalmente SEM tags de imagem.';
    if (!systemPrompt.includes('##IMG##')) systemPrompt += imageRules;

    // Sanitize messages
    const messages = (rawMessages||[]).map(m => {
      if (Array.isArray(m.content)) {
        const textParts = m.content.filter(p => p.type === 'text').map(p => p.text).join(' ');
        return { ...m, content: textParts || '[imagem]' };
      }
      if (typeof m.content !== 'string') return { ...m, content: String(m.content || '') };
      return m;
    });
    const ur = await q('SELECT personal_groq_key,personal_gemini_key,personal_openrouter_key,personal_deepseek_key FROM users WHERE id=$1', [req.user.id]);
    const userData = ur.rows[0];
    let apiKey;
    if (provider==='groq') {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_groq_key']);
      apiKey = userData?.personal_groq_key || ck.rows[0]?.value || process.env.GROQ_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Groq configurada.' });
    } else if (provider==='gemini') {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_gemini_key']);
      apiKey = userData?.personal_gemini_key || ck.rows[0]?.value || process.env.GEMINI_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Gemini configurada.' });
    } else if (provider==='openrouter') {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_openrouter_key']);
      apiKey = userData?.personal_openrouter_key || ck.rows[0]?.value || process.env.OPENROUTER_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do OpenRouter configurada.' });
    } else if (provider==='deepseek') {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_deepseek_key']);
      apiKey = userData?.personal_deepseek_key || ck.rows[0]?.value || process.env.DEEPSEEK_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do DeepSeek configurada.' });
    } else {
      const ck = await q('SELECT value FROM config WHERE key=$1', ['global_mistral_key']);
      apiKey = userData?.personal_mistral_key || ck.rows[0]?.value || process.env.MISTRAL_API_KEY;
      if (!apiKey) return res.status(503).json({ error:'Nenhuma API key do Mistral configurada.' });
    }
    // Blacklist check
    const blCfg = await q("SELECT value FROM config WHERE key='blacklist'");
    const blacklist = blCfg.rows[0]?.value ? JSON.parse(blCfg.rows[0].value) : [];
    if(blacklist.length){
      const lastText = messages.filter(m=>m.role==='user').slice(-1)[0]?.content||'';
      const textLower = (typeof lastText==='string'?lastText:JSON.stringify(lastText)).toLowerCase();
      const blocked = blacklist.find(w=>textLower.includes(w));
      if(blocked) return res.status(400).json({ error:`Mensagem bloqueada: contém palavra proibida.` });
    }

    const chatStart = Date.now();
    const usedModel = model || defaultModels[provider] || 'llama-3.3-70b-versatile';
    // Use fallback system only when not using personal key
    const hasPersonalKey = (provider==='groq' && userData?.personal_groq_key)
      || (provider==='gemini' && userData?.personal_gemini_key)
      || (provider==='openrouter' && userData?.personal_openrouter_key)
      || (provider==='mistral' && userData?.personal_mistral_key);

    let reply;
    if (hasPersonalKey) {
      reply = provider==='groq' ? await callGroq(apiKey, usedModel, messages, systemPrompt)
        : provider==='gemini' ? await callGemini(apiKey, usedModel, messages, systemPrompt)
        : provider==='openrouter' ? await callOpenRouter(apiKey, usedModel, messages, systemPrompt)
        : await callMistral(apiKey, usedModel, messages, systemPrompt);
    } else {
      const callFn = provider==='groq' ? callGroq
        : provider==='gemini' ? callGemini
        : provider==='openrouter' ? callOpenRouter
        : provider==='deepseek' ? callDeepSeek
        : callMistral;
      reply = await tryWithFallback(provider, apiKey, callFn, usedModel, messages, systemPrompt);
    }
    recordResponseTime(provider, Date.now() - chatStart);
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
    // Detecta pedido de imagem no reply e extrai prompt
    let imagePrompt = null;
    let cleanReply = reply;

    // Só gera imagem se a IA retornou a tag ##IMG## explicitamente
    const patterns = [
      /##IMG##([\s\S]+?)##ENDIMG##/i,
      /\[GERAR_IMAGEM:\s*([\s\S]+?)\]/i,
      /\[GENERATE_IMAGE:\s*([\s\S]+?)\]/i,
      /\[IMAGE:\s*([\s\S]+?)\]/i,
    ];
    for (const pat of patterns) {
      const m = reply.match(pat);
      if (m) {
        imagePrompt = m[1].trim();
        cleanReply = reply.replace(pat, '').trim();
        break;
      }
    }

    if (imagePrompt) {
      const shortPrompt = imagePrompt.slice(0, 300);
      try {
        const cfAccRow = await q("SELECT value FROM config WHERE key='cf_account_id'");
        const cfTokRow = await q("SELECT value FROM config WHERE key='cf_api_token'");
        const CF_ACCOUNT = cfAccRow.rows[0]?.value;
        const CF_TOKEN = cfTokRow.rows[0]?.value;
        if (CF_ACCOUNT && CF_TOKEN) {
          console.log('[image] gerando via Cloudflare AI:', shortPrompt.slice(0,60));
          const cfRes = await fetch(
            `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/ai/run/@cf/stabilityai/stable-diffusion-xl-base-1.0`,
            {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${CF_TOKEN}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ prompt: shortPrompt }),
              signal: AbortSignal.timeout(30000)
            }
          );
          if (cfRes.ok) {
            const buf = await cfRes.arrayBuffer();
            const b64 = Buffer.from(buf).toString('base64');
            console.log('[image] Cloudflare sucesso, size:', buf.byteLength);
            return res.json({ reply: cleanReply, imageUrl: `data:image/png;base64,${b64}` });
          } else {
            const err = await cfRes.text();
            console.error('[image] Cloudflare erro:', cfRes.status, err.slice(0,100));
          }
        } else {
          console.log('[image] sem keys CF configuradas');
        }
      } catch(e) {
        console.error('[image] Cloudflare falhou:', e.message);
      }
      return res.json({ reply: cleanReply, imageUrl: null, imagePrompt: shortPrompt });
    }

    // Last resort: strip any remaining image tags from reply before sending
    const finalReply = reply
      .replace(/\[GERAR_IMAGEM:[^\]]*\]/gi, '')
      .replace(/\[GENERATE_IMAGE:[^\]]*\]/gi, '')
      .replace(/\[IMAGE:[^\]]*\]/gi, '')
      .replace(/##IMG##[\s\S]*?##ENDIMG##/gi, '')
      .trim();
    res.json({ reply: finalReply });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// Try main key first, if fails try backup keys in order
async function tryWithFallback(provider, mainKey, callFn, model, messages, sys) {
  const errors = [];
  // Try main key
  try {
    return await callFn(mainKey, model, messages, sys);
  } catch(e) {
    errors.push(`Main: ${e.message}`);
  }
  // Try backup keys
  const backups = await q('SELECT key_value,label FROM backup_keys WHERE provider=$1 AND active=true ORDER BY id ASC', [provider]);
  for (const bk of backups.rows) {
    try {
      console.log(`[fallback] Tentando key backup: ${bk.label||bk.key_value.slice(0,8)}`);
      return await callFn(bk.key_value, model, messages, sys);
    } catch(e) {
      errors.push(`Backup ${bk.label||'?'}: ${e.message}`);
    }
  }
  throw new Error(`Todas as keys falharam. Detalhes: ${errors.join(' | ')}`);
}

async function callGroq(apiKey, model, messages, sys) {
  const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`},
    body: JSON.stringify({ model, messages:[{role:'system',content:sys||'Você é um assistente prestativo. Responda em português.'},...messages], max_tokens:2048, temperature:0.7 })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`Groq erro ${r.status}`); }
  return (await r.json()).choices?.[0]?.message?.content||'Sem resposta.';
}

async function callMistral(apiKey, model, messages, sys) {
  const r = await fetch('https://api.mistral.ai/v1/chat/completions', {
    method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`},
    body: JSON.stringify({ model, messages:[{role:'system',content:sys||'Você é um assistente prestativo. Responda em português.'},...messages], max_tokens:2048, temperature:0.7 })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.message||`Mistral erro ${r.status}`); }
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


async function callOpenRouter(apiKey, model, messages, sys) {
  const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`,'HTTP-Referer':'https://ia-2-uvqg.onrender.com','X-Title':'Nexia'},
    body: JSON.stringify({ model, messages:[{role:'system',content:sys||'Você é Nexia, uma IA assistente prestativa. Responda em português.'},...messages], max_tokens:2048, temperature:0.7 })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`OpenRouter erro ${r.status}`); }
  return (await r.json()).choices?.[0]?.message?.content||'Sem resposta.';
}

async function callDeepSeek(apiKey, model, messages, sys) {
  const r = await fetch('https://api.deepseek.com/chat/completions', {
    method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`},
    body: JSON.stringify({ model, messages:[{role:'system',content:sys||'Você é Nexia, uma IA assistente prestativa. Responda em português.'},...messages], max_tokens:2048, temperature:0.7 })
  });
  if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`DeepSeek erro ${r.status}`); }
  return (await r.json()).choices?.[0]?.message?.content||'Sem resposta.';
}

app.get('/api/admin/stats', auth, role('creator','admin'), async (req,res) => {
  try {
    const totalUsers = await q("SELECT COUNT(*) as c FROM users WHERE role='user'");
    const totalAdmins = await q("SELECT COUNT(*) as c FROM users WHERE role='admin'");
    const totalConvs = await q("SELECT COUNT(*) as c FROM conversations");
    const totalMsgs = await q("SELECT messages FROM conversations");
    let msgCount = 0;
    totalMsgs.rows.forEach(r => { try { msgCount += JSON.parse(r.messages).length; } catch{} });
    const byUser = await q(`SELECT u.email, u.role, COUNT(c.id) as convs, MAX(c.updated_at) as last_active
      FROM users u LEFT JOIN conversations c ON c.user_id=u.id
      GROUP BY u.id, u.email, u.role ORDER BY last_active DESC NULLS LAST`);
    const modelUsage = await q("SELECT model, COUNT(*) as c FROM conversations GROUP BY model ORDER BY c DESC");
    const providerUsage = await q("SELECT provider, COUNT(*) as c FROM conversations GROUP BY provider ORDER BY c DESC");
    const dailyUsage = await q(`SELECT TO_CHAR(TO_TIMESTAMP(updated_at), 'YYYY-MM-DD') as day, COUNT(*) as c
      FROM conversations WHERE updated_at IS NOT NULL
      GROUP BY day ORDER BY day DESC LIMIT 14`);
    res.json({
      totalUsers: parseInt(totalUsers.rows[0].c),
      totalAdmins: parseInt(totalAdmins.rows[0].c),
      totalConvs: parseInt(totalConvs.rows[0].c),
      totalMsgs: msgCount,
      byUser: byUser.rows,
      modelUsage: modelUsage.rows,
      providerUsage: providerUsage.rows,
      dailyUsage: dailyUsage.rows.reverse(),
    });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/config', auth, role('creator','admin'), async (req,res) => {
  try {
    const r = await q("SELECT key,value FROM config WHERE key IN ('global_groq_key','global_gemini_key','global_groq_model','global_gemini_model','global_mistral_key','global_mistral_model','global_openrouter_key','global_together_key','theme_accent','theme_bg','theme_sidebar','theme_surface','cf_account_id','cf_api_token','personalityMode','systemPrompt','customPrompt','aiName','welcomeMsg','msgLimitPerDay','maxTokens','bannerText','bannerType','maintenance','allowRegistration')");
    const cfg = {};
    r.rows.forEach(row => cfg[row.key]=row.value);
    res.json({
      groqKeyMasked: cfg.global_groq_key?cfg.global_groq_key.slice(0,8)+'••••':null, hasGroqKey:!!cfg.global_groq_key, groqModel:cfg.global_groq_model||'llama-3.3-70b-versatile',
      geminiKeyMasked: cfg.global_gemini_key?cfg.global_gemini_key.slice(0,8)+'••••':null, hasGeminiKey:!!cfg.global_gemini_key, geminiModel:cfg.global_gemini_model||'gemini-2.0-flash',
      mistralKeyMasked: cfg.global_mistral_key?cfg.global_mistral_key.slice(0,8)+'••••':null, hasMistralKey:!!cfg.global_mistral_key, mistralModel:cfg.global_mistral_model||'mistral-large-latest',
      openrouterKeyMasked: cfg.global_openrouter_key?cfg.global_openrouter_key.slice(0,8)+'••••':null, hasOpenrouterKey:!!cfg.global_openrouter_key,
      togetherKeyMasked: cfg.global_together_key?cfg.global_together_key.slice(0,8)+'••••':null, hasTogetherKey:!!cfg.global_together_key,
      theme: { accent: cfg.theme_accent||'#19c37d', bg: cfg.theme_bg||'#0f0f0f', sidebar: cfg.theme_sidebar||'#171717', surface: cfg.theme_surface||'#1e1e1e' },
      hasCfToken: !!cfg.cf_api_token, cfTokenMasked: cfg.cf_api_token?cfg.cf_api_token.slice(0,8)+'••••':null,
      hasCfAccount: !!cfg.cf_account_id,
      personalityMode: cfg.personalityMode||'padrao',
      systemPrompt: cfg.systemPrompt||'',
      customPrompt: cfg.customPrompt||'',
      aiName: cfg.aiName||'Nexia',
      welcomeMsg: cfg.welcomeMsg||'',
      msgLimitPerDay: parseInt(cfg.msgLimitPerDay)||0,
      maxTokens: parseInt(cfg.maxTokens)||1024,
      bannerText: cfg.bannerText||'',
      bannerType: cfg.bannerType||'',
      maintenance: cfg.maintenance==='true',
      allowRegistration: cfg.allowRegistration!=='false',
    });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/admin/config', auth, role('creator'), async (req,res) => {
  try {
    const upsert = (k,v) => q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [k,v]);
    const {groqKey,geminiKey,groqModel,geminiModel,mistralKey,mistralModel,openrouterKey,togetherKey,cfAccountId,cfApiToken,accentColor,bgColor,sidebarColor,surfaceColor} = req.body;
    if (groqKey) await upsert('global_groq_key', groqKey);
    if (geminiKey) await upsert('global_gemini_key', geminiKey);
    if (groqModel) await upsert('global_groq_model', groqModel);
    if (geminiModel) await upsert('global_gemini_model', geminiModel);
    if (mistralKey) await upsert('global_mistral_key', mistralKey);
    if (mistralModel) await upsert('global_mistral_model', mistralModel);
    if (openrouterKey) await upsert('global_openrouter_key', openrouterKey);
    if (togetherKey) await upsert('global_together_key', togetherKey);
    if (cfAccountId) await upsert('cf_account_id', cfAccountId);
    if (cfApiToken) await upsert('cf_api_token', cfApiToken);
    if (accentColor) await upsert('theme_accent', accentColor);
    if (bgColor) await upsert('theme_bg', bgColor);
    if (sidebarColor) await upsert('theme_sidebar', sidebarColor);
    if (surfaceColor) await upsert('theme_surface', surfaceColor);
    // Personality
    const {personalityMode,systemPrompt,customPrompt,aiName,welcomeMsg,msgLimitPerDay,maxTokens} = req.body;
    if (personalityMode!==undefined) await upsert('personalityMode', personalityMode);
    if (systemPrompt!==undefined) await upsert('systemPrompt', systemPrompt);
    if (customPrompt!==undefined) await upsert('customPrompt', customPrompt);
    if (aiName!==undefined) await upsert('aiName', aiName||'Nexia');
    if (welcomeMsg!==undefined) await upsert('welcomeMsg', welcomeMsg);
    if (msgLimitPerDay!==undefined) await upsert('msgLimitPerDay', String(msgLimitPerDay||0));
    if (maxTokens!==undefined) await upsert('maxTokens', String(maxTokens||1024));
    // Banner & controls
    const {bannerText,bannerType,maintenance,allowRegistration,supportPhone,supportMsg,supportChatUrl} = req.body;
    if (bannerText!==undefined) await upsert('bannerText', bannerText);
    if (bannerType!==undefined) await upsert('bannerType', bannerType);
    if (maintenance!==undefined) await upsert('maintenance', String(maintenance));
    if (allowRegistration!==undefined) await upsert('allowRegistration', String(allowRegistration));
    if (supportPhone!==undefined) await upsert('supportPhone', supportPhone);
    if (supportMsg!==undefined) await upsert('supportMsg', supportMsg);
    if (supportChatUrl!==undefined) await upsert('supportChatUrl', supportChatUrl);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/users', auth, role('creator','admin'), async (req,res) => {
  try {
    const r = await q('SELECT id,email,role,created_at,last_seen,personal_groq_key,personal_gemini_key,personal_openrouter_key FROM users ORDER BY created_at DESC');
    res.json(r.rows.map(u=>({...u,hasGroqKey:!!u.personal_groq_key,hasGeminiKey:!!u.personal_gemini_key,hasOpenrouterKey:!!u.personal_openrouter_key,hasDeepseekKey:!!u.personal_deepseek_key,personal_groq_key:undefined,personal_gemini_key:undefined,personal_openrouter_key:undefined,personal_deepseek_key:undefined})));
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

app.patch('/api/admin/users/:id/password', auth, role('creator'), async (req,res) => {
  try {
    const {newPassword} = req.body;
    if (!newPassword||newPassword.length<6) return res.status(400).json({ error:'Senha mínima: 6 caracteres.' });
    const t = await q('SELECT * FROM users WHERE id=$1', [req.params.id]);
    if (!t.rows.length) return res.status(404).json({ error:'Usuário não encontrado.' });
    if (t.rows[0].role==='creator') return res.status(400).json({ error:'Não é possível alterar a senha do criador por aqui.' });
    await q('UPDATE users SET password=$1 WHERE id=$2', [bcrypt.hashSync(newPassword,10), req.params.id]);
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

app.post('/api/forgot-password', async (req,res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email obrigatório.' });
    const r = await q('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    if (!r.rows.length) return res.json({ ok:true }); // não revela se existe
    const user = r.rows[0];
    if (user.password === 'google-oauth') return res.status(400).json({ error: 'Esta conta usa login com Google.' });
    const token = require('crypto').randomBytes(32).toString('hex');
    const expires = Math.floor(Date.now()/1000) + 3600; // 1 hora
    await q('DELETE FROM reset_tokens WHERE user_id=$1', [user.id]);
    await q('INSERT INTO reset_tokens (token,user_id,expires_at) VALUES ($1,$2,$3)', [token, user.id, expires]);
    const link = `${BASE_URL}/reset-password.html?token=${token}`;
    console.log('📧 Enviando email para:', email);
    const mailResult = await mailer.sendMail({
      from: '"Nexia Suporte" <nexiasuporte646@gmail.com>',
      to: email,
      subject: 'Redefinir senha — Nexia',
      html: `
        <div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;background:#0f0f0f;color:#ececec;border-radius:16px;padding:32px;border:1px solid #2a2a2a">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
            <div style="width:36px;height:36px;background:#19c37d;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px">🤖</div>
            <span style="font-size:18px;font-weight:700">Nexia</span>
          </div>
          <h2 style="margin:0 0 8px;font-size:20px">Redefinir sua senha</h2>
          <p style="color:#8e8ea0;margin:0 0 24px;font-size:14px">Clique no botão abaixo para criar uma nova senha. O link expira em 1 hora.</p>
          <a href="${link}" style="display:inline-block;background:#19c37d;color:#000;text-decoration:none;border-radius:10px;padding:12px 24px;font-weight:700;font-size:15px">Redefinir senha</a>
          <p style="color:#555;margin:24px 0 0;font-size:12px">Se você não solicitou isso, ignore este email.</p>
        </div>
      `
    });
    console.log('✅ Email enviado:', mailResult.messageId);
    res.json({ ok:true });
  } catch(e) { console.error('❌ Erro email:', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/reset-password', async (req,res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Dados inválidos.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Senha mínima: 6 caracteres.' });
    const r = await q('SELECT * FROM reset_tokens WHERE token=$1', [token]);
    if (!r.rows.length) return res.status(400).json({ error: 'Link inválido ou expirado.' });
    const rt = r.rows[0];
    if (Math.floor(Date.now()/1000) > rt.expires_at) {
      await q('DELETE FROM reset_tokens WHERE token=$1', [token]);
      return res.status(400).json({ error: 'Link expirado. Solicite um novo.' });
    }
    await q('UPDATE users SET password=$1 WHERE id=$2', [require('bcryptjs').hashSync(newPassword,10), rt.user_id]);
    await q('DELETE FROM reset_tokens WHERE token=$1', [token]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Backup keys endpoints
app.get('/api/admin/backup-keys', auth, role('creator','admin'), async (req,res) => {
  try {
    const r = await q(`SELECT id,provider,label,active,created_at,LEFT(key_value,8)||'••••' as key_masked FROM backup_keys ORDER BY provider,id`);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/backup-keys', auth, role('creator','admin'), async (req,res) => {
  try {
    const { provider, key_value, label } = req.body;
    if (!provider || !key_value) return res.status(400).json({ error: 'provider e key obrigatórios.' });
    await q('INSERT INTO backup_keys (provider,key_value,label) VALUES ($1,$2,$3)', [provider, key_value, label||null]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/backup-keys/:id', auth, role('creator','admin'), async (req,res) => {
  try {
    await q('DELETE FROM backup_keys WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/backup-keys/:id', auth, role('creator','admin'), async (req,res) => {
  try {
    await q('UPDATE backup_keys SET active=$1 WHERE id=$2', [req.body.active, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/clear-old-conversations', auth, role('creator'), async (req,res) => {
  try {
    const { cutoff } = req.body;
    const r = await q('DELETE FROM conversations WHERE updated_at < $1', [cutoff]);
    res.json({ deleted: r.rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ===== ERROR LOG (in-memory, last 100) =====
const errorLog = [];
function logError(provider, model, message){
  errorLog.push({ provider, model, message, ts: Date.now() });
  if(errorLog.length > 100) errorLog.shift();
}
app.get('/api/admin/error-log', auth, role('creator','admin'), (req,res) => res.json(errorLog.slice().reverse()));
app.delete('/api/admin/error-log', auth, role('creator'), (req,res) => { errorLog.length=0; res.json({ok:true}); });

// ===== RESPONSE TIMES (in-memory) =====
const responseTimes = {};
function recordResponseTime(provider, ms){
  if(!responseTimes[provider]) responseTimes[provider]={total:0,count:0};
  responseTimes[provider].total += ms;
  responseTimes[provider].count++;
}
app.get('/api/admin/response-times', auth, role('creator','admin'), (req,res) => {
  const out = {};
  Object.entries(responseTimes).forEach(([p,v]) => { out[p] = { avg: Math.round(v.total/v.count), count: v.count }; });
  res.json(out);
});

// ===== TEST KEY =====
app.post('/api/admin/test-key', auth, role('creator','admin'), async (req,res) => {
  const { provider } = req.body;
  try{
    const keyMap = { groq:'global_groq_key', gemini:'global_gemini_key', mistral:'global_mistral_key', openrouter:'global_openrouter_key' };
    const cfg = await q('SELECT value FROM config WHERE key=$1', [keyMap[provider]]);
    const key = cfg.rows[0]?.value;
    if(!key) return res.json({ ok:false, error:'Key não configurada.' });
    const start = Date.now();
    let ok = false, message = '';
    if(provider==='groq'){
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{'Authorization':`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({model:'llama-3.1-8b-instant',messages:[{role:'user',content:'hi'}],max_tokens:5}),signal:AbortSignal.timeout(10000)});
      ok = r.ok; if(!ok){ const d=await r.json(); message=d.error?.message||'Erro'; }
    } else if(provider==='gemini'){
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contents:[{parts:[{text:'hi'}]}]}),signal:AbortSignal.timeout(10000)});
      ok = r.ok; if(!ok){ const d=await r.json(); message=d.error?.message||'Erro'; }
    } else if(provider==='mistral'){
      const r = await fetch('https://api.mistral.ai/v1/chat/completions',{method:'POST',headers:{'Authorization':`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({model:'mistral-small-latest',messages:[{role:'user',content:'hi'}],max_tokens:5}),signal:AbortSignal.timeout(10000)});
      ok = r.ok; if(!ok){ const d=await r.json(); message=d.message||'Erro'; }
    } else if(provider==='openrouter'){
      const r = await fetch('https://openrouter.ai/api/v1/chat/completions',{method:'POST',headers:{'Authorization':`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({model:'openrouter/auto',messages:[{role:'user',content:'hi'}],max_tokens:5}),signal:AbortSignal.timeout(10000)});
      ok = r.ok; if(!ok){ const d=await r.json(); message=d.error?.message||'Erro'; }
    }
    const latency = Date.now()-start;
    if(ok) return res.json({ ok:true, message:'Respondendo normalmente', latency });
    else return res.json({ ok:false, error: message, latency });
  }catch(e){ res.json({ ok:false, error: e.message }); }
});

// ===== BLACKLIST =====
app.get('/api/admin/blacklist', auth, role('creator','admin'), async (req,res) => {
  try{
    const r = await q("SELECT value FROM config WHERE key='blacklist'");
    const words = r.rows[0]?.value ? JSON.parse(r.rows[0].value) : [];
    res.json({ words });
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/blacklist', auth, role('creator','admin'), async (req,res) => {
  try{
    const { words: newWords } = req.body;
    const r = await q("SELECT value FROM config WHERE key='blacklist'");
    const existing = r.rows[0]?.value ? JSON.parse(r.rows[0].value) : [];
    const merged = [...new Set([...existing, ...newWords.map(w=>w.toLowerCase())])];
    await q("INSERT INTO config (key,value) VALUES ('blacklist',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [JSON.stringify(merged)]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.delete('/api/admin/blacklist', auth, role('creator','admin'), async (req,res) => {
  try{
    const { word } = req.body;
    const r = await q("SELECT value FROM config WHERE key='blacklist'");
    const existing = r.rows[0]?.value ? JSON.parse(r.rows[0].value) : [];
    const filtered = existing.filter(w=>w!==word);
    await q("INSERT INTO config (key,value) VALUES ('blacklist',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [JSON.stringify(filtered)]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// ===== CHANGELOG =====
app.get('/api/admin/changelog', auth, role('creator','admin'), async (req,res) => {
  try{
    const r = await q("SELECT value FROM config WHERE key='changelog'");
    const log = r.rows[0]?.value ? JSON.parse(r.rows[0].value) : [];
    res.json(log.slice(-100).reverse());
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/changelog', auth, async (req,res) => {
  try{
    const { action } = req.body;
    const r = await q("SELECT value FROM config WHERE key='changelog'");
    const log = r.rows[0]?.value ? JSON.parse(r.rows[0].value) : [];
    log.push({ action, email: req.user?.email||'sistema', ts: Date.now() });
    const trimmed = log.slice(-500);
    await q("INSERT INTO config (key,value) VALUES ('changelog',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [JSON.stringify(trimmed)]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.delete('/api/admin/changelog', auth, role('creator'), async (req,res) => {
  try{
    await q("DELETE FROM config WHERE key='changelog'");
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

app.get('/api/theme', async (req,res) => {
  try {
    const r = await q("SELECT key,value FROM config WHERE key IN ('theme_accent','theme_bg','theme_sidebar','theme_surface')");
    const t = {};
    r.rows.forEach(row => t[row.key] = row.value);
    res.json({ accent: t.theme_accent||'#19c37d', bg: t.theme_bg||'#0f0f0f', sidebar: t.theme_sidebar||'#171717', surface: t.theme_surface||'#1e1e1e' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/online', auth, role('creator','admin'), async (req,res) => {
  try {
    const fiveMin = Math.floor(Date.now()/1000) - 300;
    const thirtyMin = Math.floor(Date.now()/1000) - 1800;
    const online = await q('SELECT id,email,role,last_seen FROM users WHERE last_seen>$1 ORDER BY last_seen DESC', [fiveMin]);
    const recent = await q('SELECT id,email,role,last_seen FROM users WHERE last_seen>$1 AND last_seen<=$2 ORDER BY last_seen DESC', [thirtyMin, fiveMin]);
    const hourly = await q(`SELECT EXTRACT(HOUR FROM TO_TIMESTAMP(updated_at)) as hour, COUNT(*) as c
      FROM conversations
      WHERE updated_at > EXTRACT(EPOCH FROM NOW()) - 86400
      GROUP BY hour ORDER BY hour`);
    res.json({ online: online.rows, recent: recent.rows, hourly: hourly.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/generate-image', auth, async (req,res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt obrigatório.' });
    const seed = Math.floor(Math.random() * 999999);
    const encoded = encodeURIComponent(prompt);
    const imgUrl = `https://image.pollinations.ai/prompt/${encoded}?width=512&height=512&nologo=true&seed=${seed}`;
    // Verifica se a imagem carrega
    const r = await fetch(imgUrl, { signal: AbortSignal.timeout(25000) });
    if (!r.ok) throw new Error('Erro ao gerar imagem.');
    res.json({ url: imgUrl });
  } catch(e) { res.status(500).json({ error: 'Não consegui gerar a imagem. Tente novamente.' }); }
});

app.get('/auth/google', passport.authenticate('google', { scope:['profile','email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect:'/?error=google' }),
  (req, res) => {
    const token = require('jsonwebtoken').sign(
      { id:req.user.id, email:req.user.email, role:req.user.role },
      JWT_SECRET, { expiresIn:'7d' }
    );
    res.cookie('token', token, { httpOnly:true, maxAge:7*24*60*60*1000 });
    if (req.user.role === 'user') res.redirect('/chat.html');
    else res.redirect('/admin.html');
  }
);

// Necessário para Deep Link Android funcionar
app.get('/.well-known/assetlinks.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.sendFile(path.join(__dirname, 'public', '.well-known', 'assetlinks.json'));
});

// ===== SHARED ROOMS — persistido no PostgreSQL =====
function genCode(){ return Math.random().toString(36).substring(2,8).toUpperCase(); }

// Criar ou entrar na sala
app.post('/api/shared-room', auth, async (req,res) => {
  try{
    const { action, code } = req.body;
    const email = req.user.email;

    if(action === 'create'){
      const newCode = genCode();
      await q(`INSERT INTO shared_rooms (code, created_by, participants, messages, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$5)`,
        [newCode, email, JSON.stringify([{email, joinedAt: Date.now()}]), '[]', Date.now()]);
      return res.json({ code: newCode });
    }

    if(action === 'join'){
      const r = await q('SELECT * FROM shared_rooms WHERE code=$1', [code]);
      if(!r.rows.length) return res.status(404).json({ error: 'Sala não encontrada.' });
      const room = r.rows[0];
      const participants = JSON.parse(room.participants);
      if(participants.length >= 8 && !participants.find(p=>p.email===email))
        return res.status(400).json({ error: 'Sala cheia (máx 8 pessoas).' });
      if(!participants.find(p=>p.email===email)){
        participants.push({ email, joinedAt: Date.now() });
        await q('UPDATE shared_rooms SET participants=$1, updated_at=$2 WHERE code=$3',
          [JSON.stringify(participants), Date.now(), code]);
      }
      return res.json({ ok: true, code });
    }

    res.status(400).json({ error: 'Ação inválida.' });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Buscar mensagens (polling)
app.get('/api/shared-room/:code/messages', auth, async (req,res) => {
  try{
    const r = await q('SELECT * FROM shared_rooms WHERE code=$1', [req.params.code]);
    if(!r.rows.length) return res.status(404).json({ error: 'Sala não encontrada.' });
    const room = r.rows[0];
    const participants = JSON.parse(room.participants);
    const messages = JSON.parse(room.messages);
    const email = req.user.email;

    // Auto-join if not already in
    if(!participants.find(p=>p.email===email)){
      participants.push({ email, joinedAt: Date.now() });
      await q('UPDATE shared_rooms SET participants=$1, updated_at=$2 WHERE code=$3',
        [JSON.stringify(participants), Date.now(), req.params.code]);
    }

    const since = parseInt(req.query.since||'0');
    const newMsgs = messages.filter(m => m.ts > since);
    res.json({
      messages: newMsgs,
      allMessages: messages.slice(-100),
      participants,
      code: room.code,
      createdBy: room.created_by
    });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Enviar mensagem + chamar IA
app.post('/api/shared-room/:code/messages', auth, async (req,res) => {
  try{
    const r = await q('SELECT * FROM shared_rooms WHERE code=$1', [req.params.code]);
    if(!r.rows.length) return res.status(404).json({ error: 'Sala não encontrada.' });
    const room = r.rows[0];
    const { text, provider, model, displayName, photo } = req.body;
    if(!text) return res.status(400).json({ error: 'Texto vazio.' });

    const messages = JSON.parse(room.messages);
    const participants = JSON.parse(room.participants);
    const userMsg = { id: Date.now(), email: req.user.email, role: 'user', content: text, ts: Date.now(), displayName: displayName||null, photo: photo||null };
    messages.push(userMsg);
    // Keep max 500 messages
    const trimmed = messages.slice(-500);
    await q('UPDATE shared_rooms SET messages=$1, updated_at=$2 WHERE code=$3',
      [JSON.stringify(trimmed), Date.now(), req.params.code]);
    res.json({ ok: true, msg: userMsg });

    // Call AI in background
    (async () => {
      try{
        const cfg = await q("SELECT key, value FROM config WHERE key IN ('global_groq_key','global_gemini_key','global_mistral_key','global_openrouter_key','systemPrompt')");
        const cfgMap = {};
        cfg.rows.forEach(row => cfgMap[row.key] = row.value);

        const history = trimmed.slice(-20)
          .filter(m => m.role==='user'||m.role==='assistant')
          .map(m => ({ role: m.role, content: typeof m.content==='string'?m.content:JSON.stringify(m.content) }));

        const globalSysPrompt = cfgMap['systemPrompt'];
        const systemPrompt = globalSysPrompt
          || `Você é Nexia, assistente de IA. Esta é uma sala compartilhada com ${participants.length} pessoas. Responda sempre em português. Se pedirem imagem use: ##IMG## descrição em inglês ##ENDIMG##`;

        const selectedProvider = provider || 'groq';
        const selectedModel = model || 'llama-3.3-70b-versatile';
        let aiText = '';

        if(selectedProvider === 'groq'){
          const key = cfgMap['global_groq_key']; if(!key) return;
          const res = await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{'Authorization':`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({model:selectedModel,messages:[{role:'system',content:systemPrompt},...history],max_tokens:1024}),signal:AbortSignal.timeout(30000)});
          if(!res.ok) return; const data = await res.json(); aiText = data.choices?.[0]?.message?.content||'';
        } else if(selectedProvider === 'gemini'){
          const key = cfgMap['global_gemini_key']; if(!key) return;
          const contents = history.map(m=>({role:m.role==='assistant'?'model':'user',parts:[{text:m.content}]}));
          const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${selectedModel||'gemini-2.0-flash'}:generateContent?key=${key}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({systemInstruction:{parts:[{text:systemPrompt}]},contents,generationConfig:{maxOutputTokens:1024}}),signal:AbortSignal.timeout(30000)});
          if(!res.ok) return; const data = await res.json(); aiText = data.candidates?.[0]?.content?.parts?.[0]?.text||'';
        } else if(selectedProvider === 'mistral'){
          const key = cfgMap['global_mistral_key']; if(!key) return;
          const res = await fetch('https://api.mistral.ai/v1/chat/completions',{method:'POST',headers:{'Authorization':`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({model:selectedModel||'mistral-large-latest',messages:[{role:'system',content:systemPrompt},...history],max_tokens:1024}),signal:AbortSignal.timeout(30000)});
          if(!res.ok) return; const data = await res.json(); aiText = data.choices?.[0]?.message?.content||'';
        } else if(selectedProvider === 'openrouter'){
          const key = cfgMap['global_openrouter_key']; if(!key) return;
          const res = await fetch('https://openrouter.ai/api/v1/chat/completions',{method:'POST',headers:{'Authorization':`Bearer ${key}`,'Content-Type':'application/json','HTTP-Referer':'https://ia-2-uvqg.onrender.com'},body:JSON.stringify({model:selectedModel||'openrouter/auto',messages:[{role:'system',content:systemPrompt},...history],max_tokens:1024}),signal:AbortSignal.timeout(30000)});
          if(!res.ok) return; const data = await res.json(); aiText = data.choices?.[0]?.message?.content||'';
        }

        if(!aiText) return;
        // Re-fetch latest messages to avoid race condition
        const latest = await q('SELECT messages FROM shared_rooms WHERE code=$1', [req.params.code]);
        if(!latest.rows.length) return;
        const latestMsgs = JSON.parse(latest.rows[0].messages);
        const aiMsg = { id: Date.now()+1, email: 'Nexia', role: 'assistant', content: aiText, ts: Date.now() };
        latestMsgs.push(aiMsg);
        await q('UPDATE shared_rooms SET messages=$1, updated_at=$2 WHERE code=$3',
          [JSON.stringify(latestMsgs.slice(-500)), Date.now(), req.params.code]);
      }catch(e){ console.error('AI shared room error:', e.message); }
    })();

  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Sair da sala
app.delete('/api/shared-room/:code/leave', auth, async (req,res) => {
  try{
    const r = await q('SELECT * FROM shared_rooms WHERE code=$1', [req.params.code]);
    if(!r.rows.length) return res.json({ ok: true });
    const participants = JSON.parse(r.rows[0].participants).filter(p=>p.email!==req.user.email);
    if(participants.length === 0){
      await q('DELETE FROM shared_rooms WHERE code=$1', [req.params.code]);
    } else {
      await q('UPDATE shared_rooms SET participants=$1, updated_at=$2 WHERE code=$3',
        [JSON.stringify(participants), Date.now(), req.params.code]);
    }
    res.json({ ok: true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Admin - listar salas
app.get('/api/admin/shared-rooms', auth, role('creator','admin'), async (req,res) => {
  try{
    const r = await q('SELECT * FROM shared_rooms ORDER BY created_at DESC');
    const now = Date.now();
    const rooms = r.rows.map(room => {
      const participants = JSON.parse(room.participants);
      const messages = JSON.parse(room.messages);
      const ageMs = now - room.created_at;
      const ageStr = ageMs < 60000 ? 'agora mesmo'
        : ageMs < 3600000 ? `há ${Math.floor(ageMs/60000)}min`
        : `há ${Math.floor(ageMs/3600000)}h`;
      return {
        code: room.code,
        createdBy: room.created_by,
        participants: participants.length,
        participantList: participants.map(p=>p.email),
        messageCount: messages.length,
        age: ageStr,
        createdAt: room.created_at
      };
    });
    res.json(rooms);
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Admin - encerrar sala
app.delete('/api/admin/shared-rooms/:code', auth, role('creator','admin'), async (req,res) => {
  try{
    await q('DELETE FROM shared_rooms WHERE code=$1', [req.params.code]);
    res.json({ ok: true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Admin - ver mensagens de uma sala
app.get('/api/admin/shared-rooms/:code/messages', auth, role('creator','admin'), async (req,res) => {
  try{
    const r = await q('SELECT * FROM shared_rooms WHERE code=$1', [req.params.code]);
    if(!r.rows.length) return res.status(404).json({ error: 'Sala não encontrada.' });
    const messages = JSON.parse(r.rows[0].messages);
    const participants = JSON.parse(r.rows[0].participants);
    res.json({ messages: messages.slice(-50), participants });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Login log (in-memory, last 100)
const loginLog = [];

// Override the /api/me to also log logins — patch after auth routes
// We'll log on /api/login instead
// Already handled below by patching login route

// Admin: login log
app.get('/api/admin/login-log', auth, role('creator','admin'), (req,res) => {
  res.json(loginLog.slice(-50).reverse());
});

// Admin: force logout all (increment JWT version in config)
app.post('/api/admin/force-logout-all', auth, role('creator'), async (req,res) => {
  try{
    const newV = Date.now();
    await q('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', ['jwt_version', String(newV)]);
    res.json({ ok: true });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// Banner & maintenance: served via /api/app-config (public)
app.get('/api/app-config', async (req,res) => {
  try{
    const r = await q("SELECT key,value FROM config WHERE key IN ('bannerText','bannerType','maintenance','allowRegistration','systemPrompt','aiName','welcomeMsg','personalityMode','msgLimitPerDay','maxTokens','supportPhone','supportMsg','supportChatUrl')");
    const cfg = {};
    r.rows.forEach(row => cfg[row.key] = row.value);
    res.json({
      bannerText: cfg.bannerText||'',
      bannerType: cfg.bannerType||'',
      maintenance: cfg.maintenance==='true',
      allowRegistration: cfg.allowRegistration!=='false',
      aiName: cfg.aiName||'Nexia',
      welcomeMsg: cfg.welcomeMsg||'',
      personalityMode: cfg.personalityMode||'padrao',
      systemPrompt: cfg.systemPrompt||'',
      msgLimitPerDay: parseInt(cfg.msgLimitPerDay)||0,
      maxTokens: parseInt(cfg.maxTokens)||1024,
      supportPhone: cfg.supportPhone||'',
      supportMsg: cfg.supportMsg||'Olá! Preciso de ajuda com o Nexia.',
      supportChatUrl: cfg.supportChatUrl||''
    });
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/logo', auth, role('creator','admin'), async (req,res) => {
  try {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      const body = Buffer.concat(chunks);
      const contentType = req.headers['content-type'] || '';
      const boundary = contentType.split('boundary=')[1];
      if (!boundary) return res.status(400).json({ error: 'Requisição inválida.' });
      const boundaryBuf = Buffer.from('--' + boundary);
      let start = 0;
      while (true) {
        const idx = body.indexOf(boundaryBuf, start);
        if (idx === -1) break;
        const end = body.indexOf(boundaryBuf, idx + boundaryBuf.length);
        if (end === -1) break;
        const part = body.slice(idx + boundaryBuf.length + 2, end - 2);
        const headerEnd = part.indexOf('\r\n\r\n');
        if (headerEnd === -1) { start = end; continue; }
        const headers = part.slice(0, headerEnd).toString();
        const content = part.slice(headerEnd + 4);
        const nameMatch = headers.match(/name="([^"]+)"/);
        if (!nameMatch || nameMatch[1] !== 'logo') { start = end; continue; }
        const ctMatch = headers.match(/Content-Type:\s*(\S+)/i);
        const ct = ctMatch ? ctMatch[1] : 'image/png';
        if (!['image/png','image/jpeg','image/jpg'].includes(ct)) {
          return res.status(400).json({ error: 'Apenas PNG/JPG permitido.' });
        }
        const ext = ct.includes('png') ? '.png' : '.jpg';
        const logoPath = path.join(__dirname, 'public', 'logo' + ext);
        require('fs').writeFileSync(logoPath, content);
        // If not png, also overwrite logo.png
        if (ext !== '.png') {
          require('fs').writeFileSync(path.join(__dirname, 'public', 'logo.png'), content);
        }
        return res.json({ ok: true });
      }
      res.status(400).json({ error: 'Arquivo não encontrado.' });
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Public: get support phones (no auth needed)
app.get('/api/support/phones-public', async (req,res) => {
  try{
    const r = await q("SELECT value FROM config WHERE key='supportPhones'");
    res.json(JSON.parse(r.rows[0]?.value||'[]'));
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// ===== SUPPORT TICKETS =====

// User: open a ticket
app.post('/api/support/tickets', auth, async (req,res) => {
  try{
    const { subject, channel, firstMessage } = req.body;
    if(!subject||!channel) return res.status(400).json({ error:'subject e channel obrigatórios.' });
    const msgs = firstMessage ? [{ role:'user', text:firstMessage, email:req.user.email, ts:Date.now() }] : [];
    const r = await q(
      `INSERT INTO support_tickets (user_id,user_email,subject,channel,messages) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, req.user.email, subject, channel, JSON.stringify(msgs)]
    );
    res.json(r.rows[0]);
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// User: get my tickets
app.get('/api/support/tickets/mine', auth, async (req,res) => {
  try{
    const r = await q('SELECT * FROM support_tickets WHERE user_id=$1 ORDER BY updated_at DESC', [req.user.id]);
    res.json(r.rows);
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// User: get one ticket (must be owner or support staff)
app.get('/api/support/tickets/:id', auth, async (req,res) => {
  try{
    const r = await q('SELECT * FROM support_tickets WHERE id=$1', [req.params.id]);
    const t = r.rows[0]; if(!t) return res.status(404).json({ error:'Não encontrado.' });
    const isStaff = ['creator','subdono','admin'].includes(req.user.role);
    if(t.user_id !== req.user.id && !isStaff) return res.status(403).json({ error:'Acesso negado.' });
    res.json(t);
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// User: send message in ticket
app.post('/api/support/tickets/:id/messages', auth, async (req,res) => {
  try{
    const { text } = req.body;
    if(!text?.trim()) return res.status(400).json({ error:'Mensagem vazia.' });
    const r = await q('SELECT * FROM support_tickets WHERE id=$1', [req.params.id]);
    const t = r.rows[0]; if(!t) return res.status(404).json({ error:'Não encontrado.' });
    const isStaff = ['creator','subdono','admin'].includes(req.user.role);
    if(t.user_id !== req.user.id && !isStaff) return res.status(403).json({ error:'Acesso negado.' });
    if(t.status === 'closed') return res.status(400).json({ error:'Ticket encerrado.' });
    const msgs = Array.isArray(t.messages) ? t.messages : JSON.parse(t.messages||'[]');
    msgs.push({ role: isStaff ? 'support' : 'user', text: text.trim(), email: req.user.email, ts: Date.now() });
    const now = Math.floor(Date.now()/1000);
    await q('UPDATE support_tickets SET messages=$1,updated_at=$2 WHERE id=$3', [JSON.stringify(msgs), now, t.id]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// Staff: list all open tickets
app.get('/api/support/tickets', auth, role('creator','subdono','admin'), async (req,res) => {
  try{
    const status = req.query.status || 'open';
    const r = await q(`SELECT * FROM support_tickets WHERE status=$1 ORDER BY updated_at DESC`, [status]);
    res.json(r.rows);
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// Staff: claim a ticket
app.post('/api/support/tickets/:id/claim', auth, role('creator','subdono','admin'), async (req,res) => {
  try{
    const r = await q('SELECT * FROM support_tickets WHERE id=$1', [req.params.id]);
    const t = r.rows[0]; if(!t) return res.status(404).json({ error:'Não encontrado.' });
    if(t.assigned_to && t.assigned_to !== req.user.id) return res.status(400).json({ error:'Já atribuído a outro atendente.' });
    await q('UPDATE support_tickets SET assigned_to=$1,assigned_email=$2,updated_at=$3 WHERE id=$4',
      [req.user.id, req.user.email, Math.floor(Date.now()/1000), t.id]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// Staff: close ticket
app.post('/api/support/tickets/:id/close', auth, role('creator','subdono','admin'), async (req,res) => {
  try{
    const now = Math.floor(Date.now()/1000);
    await q('UPDATE support_tickets SET status=$1,closed_at=$2,updated_at=$3 WHERE id=$4',
      ['closed', now, now, req.params.id]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// User: rate a closed ticket
app.post('/api/support/tickets/:id/rate', auth, async (req,res) => {
  try{
    const { rating, comment } = req.body;
    if(!rating || rating < 1 || rating > 5) return res.status(400).json({ error:'Rating 1-5 obrigatório.' });
    const r = await q('SELECT * FROM support_tickets WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    const t = r.rows[0]; if(!t) return res.status(404).json({ error:'Não encontrado.' });
    if(t.status !== 'closed') return res.status(400).json({ error:'Só é possível avaliar tickets encerrados.' });
    await q('UPDATE support_tickets SET rating=$1,rating_comment=$2 WHERE id=$3', [rating, comment||'', t.id]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// Admin: support phone numbers (multiple)
app.get('/api/admin/support-phones', auth, role('creator','subdono','admin'), async (req,res) => {
  try{
    const r = await q("SELECT value FROM config WHERE key='supportPhones'");
    res.json(JSON.parse(r.rows[0]?.value||'[]'));
  }catch(e){ res.status(500).json({ error:e.message }); }
});
app.post('/api/admin/support-phones', auth, role('creator','subdono'), async (req,res) => {
  try{
    const { phones } = req.body; // array of {label, number}
    await q("INSERT INTO config (key,value) VALUES ('supportPhones',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [JSON.stringify(phones)]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

// Support stats for admin dashboard
app.get('/api/support/stats', auth, role('creator','subdono','admin'), async (req,res) => {
  try{
    const open = await q("SELECT COUNT(*) FROM support_tickets WHERE status='open'");
    const closed = await q("SELECT COUNT(*) FROM support_tickets WHERE status='closed'");
    const avgRating = await q("SELECT ROUND(AVG(rating),1) as avg FROM support_tickets WHERE rating IS NOT NULL");
    res.json({ open: parseInt(open.rows[0].count), closed: parseInt(closed.rows[0].count), avgRating: parseFloat(avgRating.rows[0].avg)||0 });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, async () => {
  console.log(`🚀 Nexia rodando na porta ${PORT}`);
  await initDB().catch(console.error);
});
