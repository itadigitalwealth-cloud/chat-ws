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

// CORS base (frontend su dominio/porta diversa)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ----- "DB" JSON ----- //

const USERS_FILE = path.join(__dirname, "data", "users.json");
const MESSAGES_FILE = path.join(__dirname, "data", "messages.json");

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

// ----- AUTH ----- //

// POST /api/register
// body: { username, password, publicKey }
app.post("/api/register", async (req, res) => {
  const { username, password, publicKey } = req.body || {};

  if (!username || !password || !publicKey) {
    return res.status(400).json({ error: "username, password e publicKey obbligatori" });
  }
  if (!username.startsWith("@") || username.length < 3) {
    return res.status(400).json({ error: "lo username deve iniziare con @ e avere almeno 3 caratteri" });
  }

  const users = loadJson(USERS_FILE, []);

  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "username già esistente" });
  }

  const passwordHash = await bcrypt.hash(password, 11);

  const user = {
    id: uuid(),
    username,
    passwordHash,
    publicKey,       // chiave pubblica ECDH lato client (base64)
    createdAt: Date.now()
  };

  users.push(user);
  saveJson(USERS_FILE, users);

  res.json({ ok: true });
});

// POST /api/login
// body: { username, password }
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username e password obbligatori" });
  }

  const users = loadJson(USERS_FILE, []);
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: "credenziali errate" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "credenziali errate" });
  }

  // il server NON restituisce password o hash
  res.json({
    ok: true,
    username: user.username
  });
});

// GET /api/user/:username
// ritorna solo { username, publicKey }
app.get("/api/user/:username", (req, res) => {
  const username = req.params.username;
  const users = loadJson(USERS_FILE, []);
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: "utente non trovato" });

  res.json({
    username: user.username,
    publicKey: user.publicKey
  });
});

// GET /api/users?search=...
// per la ricerca globale
app.get("/api/users", (req, res) => {
  const search = (req.query.search || "").toLowerCase();
  const users = loadJson(USERS_FILE, []);
  const list = users
    .filter(u => u.username.toLowerCase().includes(search))
    .map(u => ({ username: u.username }));
  res.json(list);
});

// ----- CHAT / CONVERSAZIONI ----- //

// GET /api/conversations?me=@user
// ritorna la lista dei contatti con cui "me" ha messaggi
app.get("/api/conversations", (req, res) => {
  const me = req.query.me;
  if (!me) return res.status(400).json({ error: "parametro 'me' obbligatorio" });

  const messages = loadJson(MESSAGES_FILE, []);
  const set = new Set();

  for (const m of messages) {
    if (m.from === me) set.add(m.to);
    if (m.to === me) set.add(m.from);
  }

  const list = Array.from(set).map(u => ({ username: u }));
  res.json(list);
});

// GET /api/messages?me=@user&with=@altro
// restituisce la cronologia cifrata
app.get("/api/messages", (req, res) => {
  const me = req.query.me;
  const other = req.query.with;
  if (!me || !other) {
    return res.status(400).json({ error: "parametri 'me' e 'with' obbligatori" });
  }

  const messages = loadJson(MESSAGES_FILE, []);
  const conv = messages.filter(
    m =>
      (m.from === me && m.to === other) ||
      (m.from === other && m.to === me)
  );

  res.json(conv);
});

// POST /api/messages
// body: { from, to, iv, ciphertext, ts }
app.post("/api/messages", (req, res) => {
  const { from, to, iv, ciphertext, ts } = req.body || {};

  if (!from || !to || !iv || !ciphertext) {
    return res.status(400).json({ error: "campi obbligatori mancanti" });
  }

  const messages = loadJson(MESSAGES_FILE, []);
  const msg = {
    id: uuid(),
    from,
    to,
    iv,          // base64
    ciphertext,  // base64
    ts: ts || Date.now()
  };
  messages.push(msg);
  saveJson(MESSAGES_FILE, messages);

  // push in realtime via WS all'altro utente
  pushToUser(to, msg);

  res.json({ ok: true, id: msg.id });
});

// ----- WEBSOCKET ----- //

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

/** mappa: username -> Set<ws> */
const online = new Map();

function pushToUser(username, msg) {
  const sockets = online.get(username);
  if (!sockets) return;
  const payload = JSON.stringify({ type: "message", msg });
  for (const ws of sockets) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  }
}

wss.on("connection", ws => {
  let currentUser = null;

  ws.on("message", raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (data.type === "auth") {
      const username = data.username;
      if (!username) return;

      currentUser = username;
      if (!online.has(username)) online.set(username, new Set());
      online.get(username).add(ws);

      ws.send(JSON.stringify({ type: "auth-ok" }));
    }
  });

  ws.on("close", () => {
    if (currentUser && online.has(currentUser)) {
      const set = online.get(currentUser);
      set.delete(ws);
      if (set.size === 0) {
        online.delete(currentUser);
      }
    }
  });
});

server.listen(PORT, () => {
  console.log("PegasusChat backend in ascolto sulla porta " + PORT);
});
