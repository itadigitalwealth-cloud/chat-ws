// ========================================
// PegasusChat – backend finale stabile
// ========================================

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const WebSocket = require("ws");

const PORT = process.env.PORT || 8080;

const app = express();
app.use(express.json());

// CORS minimale
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ===== JSON DB =====
const USERS_FILE = path.join(__dirname, "data", "users.json");
const MESSAGES_FILE = path.join(__dirname, "data", "messages.json");

const load = (file, fallback) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
};

const save = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
};

// ========================================
// REGISTER
// ========================================
app.post("/api/register", async (req, res) => {
  const { username, password, publicKey } = req.body || {};

  if (!username || !password || !publicKey) {
    return res.status(400).json({ error: "username, password e publicKey obbligatori" });
  }

  if (!username.startsWith("@") || username.length < 3) {
    return res.status(400).json({ error: "lo username deve iniziare con @ e avere almeno 3 caratteri" });
  }

  const users = load(USERS_FILE, []);
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "username esistente" });
  }

  const hash = await bcrypt.hash(password, 11);

  const user = {
    id: uuid(),
    username,
    passwordHash: hash,
    publicKey,
    createdAt: Date.now()
  };

  users.push(user);
  save(USERS_FILE, users);

  res.json({ ok: true });
});

// ========================================
// LOGIN
// ========================================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};

  const users = load(USERS_FILE, []);
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());

  if (!user) return res.status(401).json({ error: "credenziali errate" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "credenziali errate" });

  res.json({ ok: true, username: user.username });
});

// ========================================
// LISTA UTENTI / PUBLIC KEY
// ========================================
app.get("/api/user/:username", (req, res) => {
  const users = load(USERS_FILE, []);
  const user = users.find(u => u.username === req.params.username);
  if (!user) return res.status(404).json({ error: "utente non trovato" });

  res.json({
    username: user.username,
    publicKey: user.publicKey
  });
});

app.get("/api/users", (req, res) => {
  const q = (req.query.search || "").toLowerCase();
  const users = load(USERS_FILE, []);
  const list = users
    .filter(u => u.username.toLowerCase().includes(q))
    .map(u => ({ username: u.username }));
  res.json(list);
});

// ========================================
// CHAT E MESSAGGI
// ========================================
app.get("/api/conversations", (req, res) => {
  const me = req.query.me;
  if (!me) return res.status(400).json({ error: "me obbligatorio" });

  const msgs = load(MESSAGES_FILE, []);
  const set = new Set();

  for (const m of msgs) {
    if (m.from === me) set.add(m.to);
    if (m.to === me) set.add(m.from);
  }

  res.json([...set].map(u => ({ username: u })));
});

app.get("/api/messages", (req, res) => {
  const me = req.query.me;
  const other = req.query.with;

  const msgs = load(MESSAGES_FILE, []);
  const conv = msgs.filter(m =>
    (m.from === me && m.to === other) ||
    (m.from === other && m.to === me)
  );

  res.json(conv);
});

// POST nuovo messaggio
app.post("/api/messages", (req, res) => {
  const { from, to, iv, ciphertext, ts } = req.body || {};

  if (!from || !to || !iv || !ciphertext) {
    return res.status(400).json({ error: "campi mancanti" });
  }

  const msg = {
    id: uuid(),
    from,
    to,
    iv,
    ciphertext,
    ts: ts || Date.now()
  };

  const msgs = load(MESSAGES_FILE, []);
  msgs.push(msg);
  save(MESSAGES_FILE, msgs);

  pushToUser(to, msg);

  res.json({ ok: true });
});

// ========================================
// WEBSOCKET
// ========================================
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

/** username -> Set<ws> */
const online = new Map();

function pushToUser(username, msg) {
  const sockets = online.get(username);
  if (!sockets) return;

  const payload = JSON.stringify({ type: "message", msg });

  for (const ws of sockets) {
    if (ws.readyState === WebSocket.OPEN) ws.send(payload);
  }
}

wss.on("connection", ws => {
  let me = null;

  ws.on("message", raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch { return; }

    if (data.type === "auth") {
      me = data.username;
      if (!online.has(me)) online.set(me, new Set());
      online.get(me).add(ws);

      ws.send(JSON.stringify({ type: "auth-ok" }));
    }
  });

  ws.on("close", () => {
    if (me && online.has(me)) {
      const set = online.get(me);
      set.delete(ws);
      if (set.size === 0) online.delete(me);
    }
  });
});

// ========================================
// SERVE FRONTEND STATICO
// ========================================
app.use(express.static(path.join(__dirname, "../frontend")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

server.listen(PORT, () =>
  console.log("PegasusChat backend in ascolto su " + PORT)
);
