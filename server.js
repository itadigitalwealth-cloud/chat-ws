// server.js
const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const { randomUUID } = require("crypto");

const PORT = process.env.PORT || 8080;
const USERS_FILE = path.join(__dirname, "users.json");

// ---- DB UTENTI (file JSON) ----

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

// ---- RATE LIMIT WS ----

const WINDOW_MS = 5000;
const MAX_MSG_PER_WINDOW = 30;
const rateState = new Map(); // ws -> [timestamps]

function checkRate(ws) {
  const now = Date.now();
  let arr = rateState.get(ws) || [];
  const cutoff = now - WINDOW_MS;
  arr = arr.filter(t => t >= cutoff);
  arr.push(now);
  rateState.set(ws, arr);
  return arr.length <= MAX_MSG_PER_WINDOW;
}

// ---- MAPPATURA UTENTI ONLINE ----
// username -> Set<ws>
const onlineUsers = new Map();

// ---- HTTP SERVER ----

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method || "GET";

  // API: registrazione anonima
  if (method === "POST" && url.pathname === "/api/register") {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 1e6) req.destroy(); // sicurezza brutale
    });
    req.on("end", () => {
      try {
        const data = JSON.parse(body.toString("utf8"));
        const username = (data.username || "").trim();
        const publicKey = (data.publicKey || "").trim();

        if (!username.startsWith("@") || username.length < 3) {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "Username non valido (deve iniziare con @ e avere almeno 3 caratteri)" }));
        }

        if (!/^[a-zA-Z0-9_@]+$/.test(username)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "Username può contenere solo lettere, numeri e _" }));
        }

        if (!publicKey) {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "publicKey mancante" }));
        }

        const users = loadUsers();
        if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
          res.writeHead(409, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "Username già esistente" }));
        }

        const user = {
          userId: randomUUID(),
          username,
          publicKey,
          createdAt: new Date().toISOString()
        };
        users.push(user);
        saveUsers(users);

        res.writeHead(201, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          userId: user.userId,
          username: user.username
        }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "JSON non valido" }));
      }
    });
    return;
  }

  // API: ricerca utenti
  if (method === "GET" && url.pathname === "/api/users") {
    const search = (url.searchParams.get("search") || "").toLowerCase();
    const users = loadUsers();
    const filtered = search
      ? users.filter(u => u.username.toLowerCase().includes(search))
      : users;
    const mapped = filtered.slice(0, 50).map(u => ({
      username: u.username,
      publicKey: u.publicKey
    }));
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(mapped));
  }

  // API: dettaglio utente /api/users/@username
  if (method === "GET" && url.pathname.startsWith("/api/users/@")) {
    const handle = url.pathname.replace("/api/users/", "").trim();
    const users = loadUsers();
    const user = users.find(u => u.username.toLowerCase() === handle.toLowerCase());
    if (!user) {
      res.writeHead(404, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Utente non trovato" }));
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      username: user.username,
      publicKey: user.publicKey
    }));
  }

  // Tutto il resto: serve index.html
  const filePath = path.join(__dirname, "index.html");
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500);
      return res.end("Errore interno");
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(data);
  });
});

// ---- WEBSOCKET: DM cifrati (server vede solo ciphertext) ----

const wss = new WebSocket.Server({ server });

wss.on("connection", (ws, req) => {
  let username = null;

  ws.on("message", raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    // Autenticazione: associa ws a uno username
    if (data.type === "auth") {
      const handle = (data.username || "").trim();
      if (!handle.startsWith("@")) {
        ws.send(JSON.stringify({ type: "error", message: "Username non valido" }));
        return;
      }
      username = handle;

      if (!onlineUsers.has(username)) {
        onlineUsers.set(username, new Set());
      }
      onlineUsers.get(username).add(ws);

      ws.send(JSON.stringify({ type: "auth-ok", username }));
      return;
    }

    // Messaggio DM cifrato
    if (data.type === "dm") {
      if (!username) {
        ws.send(JSON.stringify({ type: "error", message: "Non autenticato" }));
        return;
      }

      if (!checkRate(ws)) {
        ws.send(JSON.stringify({
          type: "error",
          message: "Stai inviando troppi messaggi, rallenta."
        }));
        return;
      }

      const to = (data.to || "").trim();
      const ciphertext = data.ciphertext;

      if (!to || !ciphertext) return;

      const targets = onlineUsers.get(to);
      if (!targets || targets.size === 0) {
        // destinatario offline: per ora ignoriamo, niente store di messaggi
        return;
      }

      const payload = JSON.stringify({
        type: "dm",
        from: username,
        ciphertext
      });

      for (const client of targets) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(payload);
        }
      }
      return;
    }
  });

  ws.on("close", () => {
    if (username && onlineUsers.has(username)) {
      const set = onlineUsers.get(username);
      set.delete(ws);
      if (set.size === 0) {
        onlineUsers.delete(username);
      }
    }
    rateState.delete(ws);
  });
});

server.listen(PORT, () => {
  console.log("Server attivo su porta " + PORT);
});
