// server.js
const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");

const PORT = process.env.PORT || 8080;

// rate limiting: max N messaggi per finestra
const WINDOW_MS = 5000;
const MAX_MSG_PER_WINDOW = 20;
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

// roomId (SHA-256 hex) -> Set di socket
const rooms = new Map();

// HTTP server che serve index.html
const server = http.createServer((req, res) => {
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

const wss = new WebSocket.Server({ server });

function broadcast(roomId, data, excludeSocket) {
  const room = rooms.get(roomId);
  if (!room) return;
  const payload = JSON.stringify(data);
  for (const client of room) {
    if (client !== excludeSocket && client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

wss.on("connection", (ws, req) => {
  const ip = req.socket.remoteAddress;
  let roomId = null;

  ws.on("message", message => {
    let data;
    try {
      data = JSON.parse(message.toString());
    } catch {
      return;
    }

    if (data.type === "join") {
      // join stanza: riceviamo SOLO l'hash (roomId), non la password
      const rid = data.roomId;
      if (!rid || typeof rid !== "string") return;

      roomId = rid;

      if (!rooms.has(roomId)) {
        rooms.set(roomId, new Set());
      }
      rooms.get(roomId).add(ws);

      ws.send(JSON.stringify({
        type: "welcome",
        message: "Sei connesso alla stanza cifrata."
      }));
      return;
    }

    if (data.type === "message") {
      if (!roomId) {
        ws.send(JSON.stringify({
          type: "error",
          message: "Non sei in nessuna stanza."
        }));
        return;
      }

      if (!checkRate(ws)) {
        ws.send(JSON.stringify({
          type: "error",
          message: "Stai inviando troppi messaggi, rallenta."
        }));
        return;
      }

      const ciphertext = data.ciphertext;
      if (!ciphertext) return;

      // inoltra il ciphertext a tutti gli altri della stanza
      broadcast(roomId, { type: "message", ciphertext }, ws);
      return;
    }
  });

  ws.on("close", () => {
    if (roomId && rooms.has(roomId)) {
      const room = rooms.get(roomId);
      room.delete(ws);
      if (room.size === 0) rooms.delete(roomId);
    }
    rateState.delete(ws);
  });
});

server.listen(PORT, () => {
  console.log("Server attivo su porta " + PORT);
});
