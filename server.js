// server.js
const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");

const PORT = process.env.PORT || 8080;

// RATE LIMIT
const WINDOW_MS = 5000;
const MAX_MSG_PER_WINDOW = 20;
const rateState = new Map();

function checkRate(ws) {
  const now = Date.now();
  let arr = rateState.get(ws);
  if (!arr) arr = [];
  const cutoff = now - WINDOW_MS;
  arr = arr.filter(t => t >= cutoff);
  arr.push(now);
  rateState.set(ws, arr);
  return arr.length <= MAX_MSG_PER_WINDOW;
}

// MAPPA STANZE
const rooms = new Map();

// SERVER HTTP PER SERVIRE index.html
const server = http.createServer((req, res) => {
  const file = path.join(__dirname, "index.html");
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(500);
      return res.end("Errore interno");
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(data);
  });
});

// WEBSOCKET
const wss = new WebSocket.Server({ server });

function broadcast(room, data, exclude) {
  const r = rooms.get(room);
  if (!r) return;
  const payload = JSON.stringify(data);
  for (const client of r) {
    if (client !== exclude && client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

wss.on("connection", (ws, req) => {
  const ip = req.socket.remoteAddress;
  let roomPassword = null;

  ws.on("message", msg => {
    let data;
    try {
      data = JSON.parse(msg.toString());
    } catch {
      return;
    }

    // JOIN
    if (data.type === "join") {
      const password = data.password;
      roomPassword = password;

      if (!rooms.has(password)) rooms.set(password, new Set());
      rooms.get(password).add(ws);

      ws.send(JSON.stringify({ 
        type: "welcome",
        message: "Sei connesso alla stanza cifrata."
      }));
      return;
    }

    // MESSAGGIO
    if (data.type === "message") {
      if (!checkRate(ws)) {
        ws.send(JSON.stringify({ type: "error", message: "Rallenta." }));
        return;
      }

      const ciphertext = data.ciphertext;
      if (!ciphertext) return;

      broadcast(roomPassword, {
        type: "message",
        ciphertext
      }, ws);
    }
  });

  ws.on("close", () => {
    if (roomPassword && rooms.has(roomPassword)) {
      rooms.get(roomPassword).delete(ws);
      if (rooms.get(roomPassword).size === 0)
        rooms.delete(roomPassword);
    }
    rateState.delete(ws);
  });
});

server.listen(PORT, () => {
  console.log("Server attivo su porta " + PORT);
});
