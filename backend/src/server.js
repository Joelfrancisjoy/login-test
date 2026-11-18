import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { rateLimit } from 'express-rate-limit';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(__dirname, '../data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, 'inventory.sqlite'));
db.exec(`PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_name TEXT NOT NULL, last_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE, phone TEXT UNIQUE,
  password_hash TEXT, verified INTEGER NOT NULL DEFAULT 0,
  provider TEXT NOT NULL DEFAULT 'password',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS verification_tokens (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);`);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
const port = Number(process.env.PORT || 4000);
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const hash = (v) => crypto.createHash('sha256').update(v).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const now = () => Date.now();
const emailPattern = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
const validName = (s) => typeof s === 'string' && /^[\p{L}][\p{L} '-]{0,59}$/u.test(s.trim());
const validPhone = (s) => typeof s === 'string' && /^[6-9]\d{9}$/.test(s) && !/(\d)\1{4,}/.test(s) && !/^(\d{5})\1$/.test(s);
const validPassword = (s) => typeof s === 'string' && s.length === 8 && /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s) && /[^A-Za-z0-9]/.test(s);
const publicUser = (u) => ({ id:u.id, firstName:u.first_name, lastName:u.last_name, email:u.email, verified:Boolean(u.verified), provider:u.provider });

// For a frontend and backend running on different origins in development, Vite proxies /api.
// Check Origin on mutating requests as defense in depth for cookie-based sessions.
app.use('/api', (req, res, next) => {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin && origin !== frontendUrl) return res.status(403).json({ error:'Untrusted origin' });
  }
  next();
});
const authLimiter = rateLimit({ windowMs:15*60*1000, limit:20, standardHeaders:'draft-7', legacyHeaders:false, message:{error:'Too many attempts. Try again later.'} });

function startSession(res, userId) {
  const token = newToken();
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token), userId, now() + 7*24*3600*1000);
  res.cookie('session', token, { httpOnly:true, sameSite:'lax', secure:process.env.NODE_ENV === 'production', path:'/', maxAge:7*24*3600*1000 });
}
function requireAuth(req,res,next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({error:'Authentication required'});
  const row = db.prepare(`SELECT users.* FROM sessions JOIN users ON sessions.user_id=users.id
    WHERE sessions.token_hash=? AND sessions.expires_at>?`).get(hash(token), now());
  if (!row) return res.status(401).json({error:'Authentication required'});
  req.user = row; next();
}
async function sendVerification(email, link) {
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    const transporter = nodemailer.createTransport({host:process.env.SMTP_HOST, port:Number(process.env.SMTP_PORT||587), secure:Number(process.env.SMTP_PORT)===465, auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
    await transporter.sendMail({from:process.env.SMTP_FROM || process.env.SMTP_USER, to:email, subject:'Verify your Inventory Marketplace email', text:`Open this link to verify your email (expires in one hour): ${link}`});
  } else if (process.env.NODE_ENV !== 'production') {
    console.log(`\n[LOCAL EMAIL VERIFICATION] For ${email}:\n${link}\n`);
  } else {
    throw new Error('SMTP must be configured in production');
  }
}
app.get('/api/health', (_req,res) => res.json({ok:true}));
app.post('/api/auth/register',authLimiter,async(req,res) => {
  const { firstName,lastName,email,phone,password,confirmPassword } = req.body || {};
  const mail = typeof email === 'string' ? email.trim().toLowerCase() : '';
  if (!validName(firstName) || !validName(lastName)) return res.status(400).json({error:'Enter valid first and last names'});
  if (mail.length > 254 || !emailPattern.test(mail)) return res.status(400).json({error:'Enter a valid email address'});
  if (!validPhone(phone)) return res.status(400).json({error:'Improper Number – Please enter a valid 10-digit mobile number.'});
  if (!validPassword(password)) return res.status(400).json({error:'Weak Password – Password must contain exactly 8 characters, including uppercase, lowercase, numeric and special characters.'});
  if (password !== confirmPassword) return res.status(400).json({error:'Password Mismatch'});
  if (db.prepare('SELECT id FROM users WHERE email=? OR phone=?').get(mail,phone)) return res.status(409).json({error:'Email or phone already registered'});
  const pwdHash = await bcrypt.hash(password,12);
  let id;
  try { id = Number(db.prepare('INSERT INTO users(first_name,last_name,email,phone,password_hash) VALUES(?,?,?,?,?)').run(firstName.trim(),lastName.trim(),mail,phone,pwdHash).lastInsertRowid); }
  catch {return res.status(409).json({error:'Email or phone already registered'});}
  const token = newToken();
  db.prepare('INSERT INTO verification_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),id,now()+3600_000);
  try { await sendVerification(mail, `${(process.env.BACKEND_URL || `http://localhost:${port}`).replace(/\/$/, '')}/api/auth/verify-email?token=${encodeURIComponent(token)}`); }
  catch(e) { console.error('Email delivery failed:',e.message); return res.status(503).json({error:'Account saved, but verification email could not be sent. Contact support.'}); }
  res.status(201).json({message:'Account created. Verify your email before signing in.'});
});
app.get('/api/auth/verify-email',(req,res) => {
  const token = typeof req.query.token==='string'?req.query.token:'';
  const row = db.prepare('SELECT user_id,expires_at FROM verification_tokens WHERE token_hash=?').get(hash(token));
  if (!row || row.expires_at < now()) return res.redirect(`${frontendUrl}/login?verified=invalid`);
  db.prepare('UPDATE users SET verified=1 WHERE id=?').run(row.user_id);
  db.prepare('DELETE FROM verification_tokens WHERE user_id=?').run(row.user_id);
  res.redirect(`${frontendUrl}/login?verified=success`);
});
app.post('/api/auth/login',authLimiter,async(req,res) => {
  const mail = String(req.body?.email||'').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(mail);
  // Avoid leaking whether an address exists.
  if (!user || !user.password_hash || !(await bcrypt.compare(String(req.body?.password||''),user.password_hash))) return res.status(401).json({error:'Invalid email or password'});
  if (!user.verified) return res.status(403).json({error:'Verify your email before logging in'});
  startSession(res,user.id); res.json({user:publicUser(user)});
});
app.post('/api/auth/google',authLimiter,async(req,res) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.status(503).json({error:'Google login is not configured'});
  try {
    const ticket = await googleClient.verifyIdToken({idToken:String(req.body?.credential||''),audience:process.env.GOOGLE_CLIENT_ID});
    const payload = ticket.getPayload();
    if (!payload?.email || !payload.email_verified || !payload.sub) return res.status(401).json({error:'Google account email is not verified'});
    const mail=payload.email.toLowerCase();
    let user=db.prepare('SELECT * FROM users WHERE email=?').get(mail);
    if (!user) {
      const first=String(payload.given_name||'Google').slice(0,60), last=String(payload.family_name||'User').slice(0,60);
      const id=Number(db.prepare('INSERT INTO users(first_name,last_name,email,verified,provider) VALUES(?,?,?,1,?)').run(first,last,mail,'google').lastInsertRowid);
      user=db.prepare('SELECT * FROM users WHERE id=?').get(id);
    } else if (!user.verified) {
      // Verified Google identity proves ownership of this email.
      db.prepare('UPDATE users SET verified=1 WHERE id=?').run(user.id);
      user=db.prepare('SELECT * FROM users WHERE id=?').get(user.id);
    }
    startSession(res,user.id); res.json({user:publicUser(user)});
  } catch (e) { console.error('Google verification error:',e.message); res.status(401).json({error:'Google authentication failed'}); }
});
app.get('/api/auth/me',requireAuth,(req,res)=>res.json({user:publicUser(req.user)}));
app.post('/api/auth/logout',(req,res)=>{
  if(req.cookies.session) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(req.cookies.session));
  res.clearCookie('session',{path:'/',sameSite:'lax',secure:process.env.NODE_ENV==='production'});
  res.json({message:'Logged out'});
});
app.get('/api/inventory',requireAuth,(_req,res) => res.json({demo:true,items:[
  {id:1,name:'Precision Socket Set',category:'Mechanical Tools',price:2499,stock:14,emoji:'🔧',description:'Durable 24-piece workshop socket kit.'},
  {id:2,name:'Wireless Headphones',category:'Electronics',price:3299,stock:21,emoji:'🎧',description:'Over-ear listening with long battery life.'},
  {id:3,name:'Brake Disc Assembly',category:'Automotive Components',price:1890,stock:8,emoji:'🚗',description:'Demo automotive replacement component.'},
  {id:4,name:'Industrial Drill',category:'Industrial Equipment',price:5799,stock:6,emoji:'⚙️',description:'High-torque drill for workshop projects.'},
  {id:5,name:'Fastener Collection',category:'Hardware and Accessories',price:499,stock:110,emoji:'🔩',description:'Assorted bolts, nuts and washers.'},
  {id:6,name:'Motor Spare Kit',category:'Spare Parts',price:1299,stock:17,emoji:'🛠️',description:'Essential components for maintenance.'}
]}));
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Unexpected server error'});});
app.listen(port,()=>console.log(`API running at http://localhost:${port}`));
