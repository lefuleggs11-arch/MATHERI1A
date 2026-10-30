// Number Heroes online server: accounts, cloud saves, gold leaderboard, 1-4 player co-op boss fights.
// Run:  npm install && npm start     (then open http://localhost:3000)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.txt');
const PUBLIC_DIR = path.join(__dirname, 'public');

fs.mkdirSync(DATA_DIR, { recursive: true });
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) {}
let SECRET;
try { SECRET = fs.readFileSync(SECRET_FILE, 'utf8'); } catch (e) {
  SECRET = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, SECRET);
}

let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(USERS_FILE + '.tmp', JSON.stringify(users), err => {
      if (!err) fs.rename(USERS_FILE + '.tmp', USERS_FILE, () => {});
    });
  }, 300);
}

// ---------- auth helpers ----------
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 64).toString('hex'); }
function makeToken(name) {
  const exp = Date.now() + 30 * 24 * 3600 * 1000;
  const body = name + '.' + exp;
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  return body + '.' + sig;
}
function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [name, exp, sig] = parts;
  const good = crypto.createHmac('sha256', SECRET).update(name + '.' + exp).digest('hex');
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  if (Date.now() > Number(exp)) return null;
  return users[name.toLowerCase()] ? users[name.toLowerCase()] : null;
}

// ---------- HTTP ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif', '.json': 'application/json' };

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 200000) { reject(new Error('too big')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
  });
}
function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}
function authUser(req) {
  const h = req.headers['authorization'] || '';
  return verifyToken(h.replace(/^Bearer\s+/i, ''));
}

// very small rate limit on auth endpoints
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > 20;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  // CORS so the game can also be opened as a plain file and still reach this server
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  try {
    if (url.pathname === '/api/register' && req.method === 'POST') {
      if (limited(req.socket.remoteAddress)) return send(res, 429, { error: 'Too many attempts, wait a minute.' });
      const { username, password } = await readBody(req);
      if (!NAME_RE.test(username || '')) return send(res, 400, { error: 'Name must be 3-16 letters, numbers or _' });
      if (typeof password !== 'string' || password.length < 4) return send(res, 400, { error: 'Password must be at least 4 characters' });
      const key = username.toLowerCase();
      if (users[key]) return send(res, 409, { error: 'That name is taken' });
      const salt = crypto.randomBytes(16).toString('hex');
      users[key] = { name: username, salt, hash: hashPw(password, salt), save: null, gold: 0, level: 1, rebirths: 0, updated: Date.now() };
      persist();
      return send(res, 200, { token: makeToken(key), username, save: null });
    }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (limited(req.socket.remoteAddress)) return send(res, 429, { error: 'Too many attempts, wait a minute.' });
      const { username, password } = await readBody(req);
      const u = users[String(username || '').toLowerCase()];
      if (!u || typeof password !== 'string') return send(res, 401, { error: 'Wrong name or password' });
      const a = Buffer.from(hashPw(password, u.salt)), b = Buffer.from(u.hash);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return send(res, 401, { error: 'Wrong name or password' });
      return send(res, 200, { token: makeToken(u.name.toLowerCase()), username: u.name, save: u.save });
    }
    if (url.pathname === '/api/save') {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: 'Please log in again' });
      if (req.method === 'GET') return send(res, 200, { save: u.save });
      if (req.method === 'PUT') {
        const { save } = await readBody(req);
        if (!save || typeof save !== 'object') return send(res, 400, { error: 'Bad save' });
        u.save = save;
        u.gold = Math.max(0, Math.floor(Number(save.coins) || 0));
        u.level = Math.max(1, Math.floor(Number(save.level) || 1));
        u.rebirths = Math.max(0, Math.floor(Number(save.resetCount) || 0));
        u.updated = Date.now();
        persist();
        return send(res, 200, { ok: true });
      }
    }
    if (url.pathname === '/api/leaderboard' && req.method === 'GET') {
      const rows = Object.values(users)
        .map(u => ({ name: u.name, gold: u.gold || 0, level: u.level || 1, rebirths: u.rebirths || 0 }))
        .sort((a, b) => b.gold - a.gold)
        .slice(0, 50);
      return send(res, 200, { rows });
    }
    if (url.pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found' });

    // static files
    let file = url.pathname === '/' ? '/index.html' : url.pathname;
    const full = path.normalize(path.join(PUBLIC_DIR, file));
    if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end(); }
    fs.readFile(full, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
      res.end(buf);
    });
  } catch (e) {
    send(res, 400, { error: 'Bad request' });
  }
});

// ---------- CO-OP BOSS ROOMS (2 players: front + back) ----------
// Flow per player: answer question -> (correct) -> timing bar -> attack with x0.5 / x1 / x2.
// Every PEARL_EVERY_MS the boss throws a pearl: each player must click the circle during the
// 3-2-1 countdown or within 1 second after it, otherwise they lose HP.
const rooms = new Map();
const MAX_PLAYERS = 2;
const HEROES = ['Addy', 'Subtra', 'Max', 'Divina', 'Lastly'];
const BOSS_HP_PER_PLAYER = { Easy: 60000, Normal: 150000, Hard: 600000 };
const WIN_GOLD = { Easy: 2000, Normal: 5000, Hard: 15000 };
const RANGE = { Easy: 5, Normal: 15, Hard: 50 };
const Q_SECONDS = { Easy: 30, Normal: 20, Hard: 10 };   // same answer time as the normal game
const MAX_POWER = 50000;                                 // per-hit cap so a hacked client can't one-shot the boss
const PEARL_EVERY_MS = Number(process.env.PEARL_EVERY_MS) || 9000;
const PEARL_COUNTDOWN_MS = 3000;
const PEARL_GRACE_MS = 1000;
const CLICK_SLACK_MS = 400;                              // network lag allowance
const PEARL_DMG_PCT = 0.15;
const WRONG_DMG_PCT = 0.08;
const ATTACK_WAIT_MS = 6000;                             // auto-attack (x0.5) if the player never presses the timing bar

function makeCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c;
  do { c = Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join(''); } while (rooms.has(c));
  return c;
}
function makeQuestion(difficulty) {
  const r = RANGE[difficulty] || 15;
  const ops = ['+', '-', 'x', '/'];
  const op = ops[Math.floor(Math.random() * ops.length)];
  let a = 1 + Math.floor(Math.random() * r), b = 1 + Math.floor(Math.random() * r), ans;
  if (op === '-' && b > a) [a, b] = [b, a];
  if (op === 'x') { a = 1 + Math.floor(Math.random() * Math.min(r, 12)); b = 1 + Math.floor(Math.random() * Math.min(r, 12)); }
  if (op === '/') { b = 2 + Math.floor(Math.random() * Math.min(r, 10)); a = b * (1 + Math.floor(Math.random() * Math.min(r, 10))); }
  ans = op === '+' ? a + b : op === '-' ? a - b : op === 'x' ? a * b : a / b;
  return { text: `${a} ${op} ${b} = ?`, answer: ans };
}
function roomState(room) {
  return {
    type: 'state', code: room.code, status: room.status, difficulty: room.difficulty,
    host: room.host, boss: { hp: room.bossHp, max: room.bossMax },
    players: room.players.map((p, i) => ({
      name: p.name, hero: p.hero, role: i === 0 ? 'front' : 'back',
      hp: p.hp, maxHp: p.maxHp, alive: p.hp > 0, damage: p.damageDone
    }))
  };
}
function broadcast(room, msg) {
  const s = JSON.stringify(msg);
  room.players.forEach(p => { if (p.ws.readyState === 1) p.ws.send(s); });
}
function pushState(room) { broadcast(room, roomState(room)); }
function sendTo(p, msg) { if (p.ws.readyState === 1) p.ws.send(JSON.stringify(msg)); }

function newQuestion(room, p) {
  const secs = Q_SECONDS[room.difficulty] || 20;
  p.q = makeQuestion(room.difficulty);
  p.awaiting = false;
  p.qDeadline = Date.now() + secs * 1000;
  sendTo(p, { type: 'question', text: p.q.text, seconds: secs });
}
function hurt(p, pct) {
  const dmg = Math.max(3, Math.floor(p.maxHp * pct));
  p.hp = Math.max(0, p.hp - dmg);
  return dmg;
}
function allDown(room) { return !room.players.some(p => p.hp > 0); }

function endFight(room, won) {
  room.status = won ? 'won' : 'lost';
  clearInterval(room.timer);
  room.pearl = null;
  const gold = won ? WIN_GOLD[room.difficulty] || 0 : 0;
  broadcast(room, { type: 'end', won, gold });
  pushState(room);
}

function doAttack(room, p, mult) {
  const dmg = Math.floor(p.power * mult);
  room.bossHp = Math.max(0, room.bossHp - dmg);
  p.damageDone += dmg;
  p.awaiting = false;
  broadcast(room, { type: 'hit', name: p.name, dmg, mult });
  broadcast(room, { type: 'log', text: `${p.name} hit the boss for ${dmg.toLocaleString()}!` });
  if (room.bossHp <= 0) return endFight(room, true);
  if (p.hp > 0) newQuestion(room, p);
  pushState(room);
}

function tick(room) {
  if (room.status !== 'fighting') return;
  const now = Date.now();

  for (const p of room.players) {
    if (p.hp <= 0) continue;
    if (p.awaiting) {
      if (now > p.attackDeadline) { doAttack(room, p, 0.5); if (room.status !== 'fighting') return; }
    } else if (p.q && now > p.qDeadline) {
      const dmg = hurt(p, WRONG_DMG_PCT);
      sendTo(p, { type: 'timeout' });
      broadcast(room, { type: 'log', text: `${p.name} ran out of time and lost ${dmg} HP.` });
      if (allDown(room)) return endFight(room, false);
      if (p.hp > 0) newQuestion(room, p);
      pushState(room);
    }
  }

  // the boss throws a pearl
  if (now >= room.nextPearl) {
    room.pearlId++;
    room.pearl = { id: room.pearlId, deadline: now + PEARL_COUNTDOWN_MS + PEARL_GRACE_MS, clicked: new Set() };
    room.nextPearl = now + PEARL_EVERY_MS;
    broadcast(room, { type: 'pearl', id: room.pearl.id, countdown: PEARL_COUNTDOWN_MS, grace: PEARL_GRACE_MS });
  }

  // check who clicked in time
  if (room.pearl && now >= room.pearl.deadline + CLICK_SLACK_MS) {
    const results = {};
    for (const p of room.players) {
      if (p.hp <= 0) continue;
      const ok = room.pearl.clicked.has(p.name);
      results[p.name] = ok;
      if (!ok) {
        const dmg = hurt(p, PEARL_DMG_PCT);
        broadcast(room, { type: 'log', text: `${p.name} was hit by the pearl for ${dmg} HP!` });
      }
    }
    const id = room.pearl.id;
    room.pearl = null;
    broadcast(room, { type: 'pearlResult', id, results });
    if (allDown(room)) return endFight(room, false);
    pushState(room);
  }
}

function startFight(room) {
  room.status = 'fighting';
  room.bossMax = (BOSS_HP_PER_PLAYER[room.difficulty] || 150000) * room.players.length;
  room.bossHp = room.bossMax;
  room.pearl = null;
  room.pearlId = 0;
  room.nextPearl = Date.now() + PEARL_EVERY_MS;
  room.players.forEach(p => { p.hp = p.maxHp; p.damageDone = 0; newQuestion(room, p); });
  pushState(room);
  clearInterval(room.timer);
  room.timer = setInterval(() => tick(room), 200);
}

function removePlayer(room, ws) {
  const i = room.players.findIndex(p => p.ws === ws);
  if (i === -1) return;
  const [p] = room.players.splice(i, 1);
  if (!room.players.length) { clearInterval(room.timer); rooms.delete(room.code); return; }
  if (room.host === p.name) room.host = room.players[0].name;
  broadcast(room, { type: 'log', text: `${p.name} left.` });
  if (room.status === 'fighting' && allDown(room)) return endFight(room, false);
  pushState(room);
}

function join(room, ws, m) {
  const maxHp = Math.min(5000, Math.max(50, Math.floor(Number(m.maxHp) || 100)));
  const power = Math.min(MAX_POWER, Math.max(1, Math.floor(Number(m.power) || 10)));
  const hero = HEROES.includes(m.hero) ? m.hero : 'Addy';
  room.players.push({ ws, name: ws.user.name, hero, hp: maxHp, maxHp, power, damageDone: 0, q: null, awaiting: false });
  ws.room = room;
  broadcast(room, { type: 'log', text: `${ws.user.name} joined.` });
  pushState(room);
}

// ---- minimal dependency-free WebSocket server (RFC 6455, text frames) ----
class MiniWS {
  constructor(socket) {
    this.socket = socket; this.readyState = 1; this.handlers = {}; this.buf = Buffer.alloc(0);
    socket.on('data', d => this._data(d));
    socket.on('close', () => this._closed());
    socket.on('error', () => this._closed());
  }
  on(ev, fn) { this.handlers[ev] = fn; }
  _closed() { if (this.readyState === 3) return; this.readyState = 3; if (this.handlers.close) this.handlers.close(); }
  _frame(opcode, payload) {
    const len = payload.length;
    const head = len < 126 ? Buffer.from([0x80 | opcode, len])
      : Buffer.from([0x80 | opcode, 126, len >> 8, len & 255]);
    return Buffer.concat([head, payload]);
  }
  send(text) { if (this.readyState === 1) this.socket.write(this._frame(1, Buffer.from(text))); }
  close() {
    if (this.readyState !== 1) return;
    this.readyState = 2;
    try { this.socket.write(this._frame(8, Buffer.alloc(0))); } catch (e) {}
    this.socket.end();
  }
  _data(d) {
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length > 16384) return this.socket.destroy();
    while (this.buf.length >= 2) {
      const b0 = this.buf[0], b1 = this.buf[1];
      const opcode = b0 & 15, masked = !!(b1 & 128);
      let len = b1 & 127, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) return this.socket.destroy(); // too large for this game
      if (!masked || len > 4096 || !(b0 & 128)) return this.socket.destroy();
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.slice(off, off + 4);
      const payload = Buffer.from(this.buf.slice(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
      this.buf = this.buf.slice(off + 4 + len);
      if (opcode === 1) { if (this.handlers.message) this.handlers.message(payload.toString('utf8')); }
      else if (opcode === 8) { this.close(); return; }
      else if (opcode === 9) { this.socket.write(this._frame(10, payload)); }
    }
  }
}
const wss = {
  handlers: {}, on(ev, fn) { this.handlers[ev] = fn; }
};
server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x');
  const key = req.headers['sec-websocket-key'];
  if (url.pathname !== '/ws' || !key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  wss.handlers.connection(new MiniWS(socket), req);
});

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const u = verifyToken(url.searchParams.get('token'));
  if (!u) { ws.send(JSON.stringify({ type: 'error', text: 'Please log in first.' })); return ws.close(); }
  ws.user = u;
  ws.room = null;

  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;
    const room = ws.room;

    if (m.type === 'create' && !room) {
      const diff = ['Easy', 'Normal', 'Hard'].includes(m.difficulty) ? m.difficulty : 'Normal';
      const r = { code: makeCode(), status: 'lobby', difficulty: diff, host: u.name, players: [], bossHp: 0, bossMax: 0, timer: null, pearl: null, pearlId: 0, nextPearl: 0 };
      rooms.set(r.code, r);
      join(r, ws, m);
    } else if (m.type === 'join' && !room) {
      const r = rooms.get(String(m.code || '').toUpperCase());
      if (!r) return ws.send(JSON.stringify({ type: 'error', text: 'Room not found.' }));
      if (r.status !== 'lobby') return ws.send(JSON.stringify({ type: 'error', text: 'That fight already started.' }));
      if (r.players.length >= MAX_PLAYERS) return ws.send(JSON.stringify({ type: 'error', text: 'Room is full (2 players).' }));
      if (r.players.some(p => p.name === u.name)) return ws.send(JSON.stringify({ type: 'error', text: 'You are already in that room.' }));
      join(r, ws, m);
    } else if (m.type === 'start' && room && room.status === 'lobby' && room.host === u.name) {
      startFight(room);
    } else if (m.type === 'answer' && room && room.status === 'fighting') {
      const p = room.players.find(x => x.ws === ws);
      if (!p || p.hp <= 0 || !p.q || p.awaiting) return;
      if (Number(m.value) === p.q.answer) {
        // correct: now the player gets the timing bar
        p.awaiting = true;
        p.attackDeadline = Date.now() + ATTACK_WAIT_MS;
        sendTo(p, { type: 'correct' });
      } else {
        const dmg = hurt(p, WRONG_DMG_PCT);
        sendTo(p, { type: 'wrong', answer: p.q.answer });
        broadcast(room, { type: 'log', text: `${p.name} answered wrong and lost ${dmg} HP.` });
        if (allDown(room)) return endFight(room, false);
        if (p.hp > 0) newQuestion(room, p);
        pushState(room);
      }
    } else if (m.type === 'attack' && room && room.status === 'fighting') {
      const p = room.players.find(x => x.ws === ws);
      if (!p || p.hp <= 0 || !p.awaiting) return;
      const mult = [0.5, 1, 2].includes(Number(m.mult)) ? Number(m.mult) : 1;
      doAttack(room, p, mult);
    } else if (m.type === 'pearlClick' && room && room.status === 'fighting' && room.pearl) {
      const p = room.players.find(x => x.ws === ws);
      if (!p || p.hp <= 0) return;
      if (Number(m.id) === room.pearl.id && Date.now() <= room.pearl.deadline + CLICK_SLACK_MS) {
        room.pearl.clicked.add(p.name);
      }
    } else if (m.type === 'leave' && room) {
      removePlayer(room, ws);
      ws.room = null;
      ws.send(JSON.stringify({ type: 'left' }));
    }
  });
  ws.on('close', () => { if (ws.room) removePlayer(ws.room, ws); });
});

server.listen(PORT, () => console.log(`Number Heroes server running on http://localhost:${PORT}`));
