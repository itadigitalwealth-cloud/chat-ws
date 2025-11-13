const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const PORT = process.env.PORT || 8080;

const USERS_FILE = path.join(__dirname, "db/users.json");
const MESSAGES_FILE = path.join(__dirname, "db/messages.json");

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadMessages() {
  try {
    return JSON.parse(fs.readFileSync(MESSAGES_FILE, "utf8"));
  } catch {
    return {};
  }
}

function saveMessages(msg) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(msg, null, 2));
}

// USER ONLINE STATUS
const online = new Map(); // username -> Set<ws>

function send(ws, obj) {
  ws.send(JSON.stringify(obj));
}

// ----------- HTTP API --------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://x`);
  const method = req.method;

  // Serve frontend
  const FRONT = path.join(__dirname, "../client");
  const filePath = path.join(FRONT, url.pathname === "/" ? "index.html" : url.pathname);

  if (method === "GET" && url.pathname.startsWith("/api")) {
    return apiHandler(req, res, url, method);
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<h1>404</h1>");
    }
    res.writeHead(200);
    res.end(data);
  });
});

// ----------- API LOGICA --------------
async function apiHandler(req, res, url, method) {
  const pathname = url.pathname;

  if (pathname === "/api/register" && method === "POST") {
    let body = "";
    req.on("data", ch => body += ch);
    req.on("end", async () => {
      try {
        const d = JSON.parse(body);
        const { username, password, publicKey, vaultCiphertext } = d;

        if (!username.startsWith("@") || username.length < 3) {
          return error(res, 400, "Username invalido");
        }

        if (!password || password.length < 6)
          return error(res, 400, "Password troppo corta");

        let users = loadUsers();
        if (users.some(u => u.username === username))
          return error(res, 409, "Esiste già");

        const hash = await bcrypt.hash(password, 12);

        const user = {
          username,
          passwordHash: hash,
          publicKey,
          vaultCiphertext,
          userId: uuid()
        };

        users.push(user);
        saveUsers(users);

        ok(res, { userId: user.userId });
      } catch {
        error(res, 400, "Invalid JSON");
      }
    });
    return;
  }

  if (pathname === "/api/login" && method === "POST") {
    let body = "";
    req.on("data", ch => body += ch);
    req.on("end", async () => {
      try {
        const { username, password } = JSON.parse(body);
        let users = loadUsers();
        const user = users.find(u => u.username === username);
        if (!user) return error(res, 404, "Non trovato");

        const okPass = await bcrypt.compare(password, user.passwordHash);
        if (!okPass) return error(res, 403, "Password errata");

        ok(res, {
          username,
          publicKey: user.publicKey,
          vaultCiphertext: user.vaultCiphertext
        });
      } catch {
        error(res, 400, "Bad request");
      }
    });
    return;
  }

  if (pathname === "/api/messages" && method === "POST") {
    let body = "";
    req.on("data", ch => body += ch);
    req.on("end", () => {
      try {
        const { chatId, msg } = JSON.parse(body);
        let db = loadMessages();
        if (!db[chatId]) db[chatId] = [];
        db[chatId].push(msg);
        saveMessages(db);
        ok(res, { saved: true });
      } catch {
        error(res, 400, "Invalid");
      }
    });
    return;
  }

  if (pathname === "/api/history" && method === "GET") {
    const chatId = url.searchParams.get("chatId");
    let db = loadMessages();
    ok(res, db[chatId] || []);
    return;
  }

  error(res, 404, "Unknown API");
}

function ok(res, data) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function error(res, code, msg) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: msg }));
}

// ------------ WEBSOCKET ----------------
const wss = new WebSocket.Server({ server });

wss.on("connection", ws => {
  let username = null;

  ws.on("message", raw => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    if (data.type === "auth") {
      username = data.username;
      if (!online.has(username)) online.set(username, new Set());
      online.get(username).add(ws);
      send(ws, { type: "auth-ok" });
      return;
    }

    if (data.type === "dm") {
      const target = data.to;
      if (!online.has(target)) return;
      for (const sock of online.get(target)) {
        if (sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify(data));
      }
      return;
    }
  });

  ws.on("close", () => {
    if (username && online.has(username)) {
      online.get(username).delete(ws);
      if (online.get(username).size === 0) {
        online.delete(username);
      }
    }
  });
});

server.listen(PORT, () => console.log("SERVER OK"));
