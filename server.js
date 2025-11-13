// server.js
const WebSocket = require("ws");
const http = require("http");

const PORT = process.env.PORT || 8080;

// roomPassword -> Set di socket
const rooms = new Map();

// rate limiting: max N messaggi ogni finestraMs per socket
const WINDOW_MS = 5000;      // 5 secondi
const MAX_MSG_PER_WINDOW = 20;

// socket -> array timestamps messaggi
const rateState = new Map();

function logMinimal(msg) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

function checkRateLimit(ws) {
  const now = Date.now();
  let arr = rateState.get(ws);
  if (!arr) {
    arr = [];
    rateState.set(ws, arr);
  }
  // tieni solo gli ultimi WINDOW_MS
  const cutoff = now - WINDOW_MS;
  const recent = arr.filter(t => t >= cutoff);
  recent.push(now);
  rateState.set(ws, recent);
  return recent.length <= MAX_MSG_PER_WINDOW;
}

function broadcastToRoom(roomPassword, data, excludeSocket = null) {
  const room = rooms.get(roomPassword);
  if (!room) return;

  const payload = JSON.stringify(data);

  for (const clientSocket of room) {
    if (
      clientSocket !== excludeSocket &&
      clientSocket.readyState === WebSocket.OPEN
    ) {
      clientSocket.send(payload);
    }
  }
}

const server = http.createServer();
const wss = new WebSocket.Server({ server });

wss.on("connection", (ws, req) => {
  const ip = req.socket.remoteAddress;
  logMinimal(`Nuova connessione da ${ip}`);

  let roomPassword = null;

  ws.on("message", (message) => {
    let data;
    try {
      data = JSON.parse(message.toString());
    } catch {
      return;
    }

    if (data.type === "join") {
      const { password } = data;
      if (!password) {
        ws.send(JSON.stringify({ type: "error", message: "Password mancante" }));
        return;
      }

      roomPassword = password;

      if (!rooms.has(password)) {
        rooms.set(password, new Set());
      }
      rooms.get(password).add(ws);

      logMinimal(`Client da ${ip} entrato nella stanza ${password}`);

      ws.send(
        JSON.stringify({
          type: "welcome",
          message: "Sei connesso alla stanza cifrata.",
        })
      );

    } else if (data.type === "message") {
      if (!roomPassword) {
        ws.send(
          JSON.stringify({
            type: "error",
            message: "Non sei in nessuna stanza.",
          })
        );
        return;
      }

      if (!checkRateLimit(ws)) {
        logMinimal(`Rate limit superato da ${ip} in stanza ${roomPassword}`);
        ws.send(
          JSON.stringify({
            type: "error",
            message: "Stai inviando troppi messaggi, rallenta.",
          })
        );
        return;
      }

      const { ciphertext } = data;
      if (!ciphertext) return;

      // il server NON decifra niente, inoltra solo blob cifrati
      broadcastToRoom(roomPassword, {
        type: "message",
        ciphertext,
      }, ws);

    } else {
      ws.send(
        JSON.stringify({
          type: "error",
          message: "Tipo di messaggio sconosciuto",
        })
      );
    }
  });

  ws.on("close", () => {
    if (roomPassword) {
      const room = rooms.get(roomPassword);
      if (room) {
        room.delete(ws);
        if (room.size === 0) rooms.delete(roomPassword);
      }
      logMinimal(`Client da ${ip} uscito dalla stanza ${roomPassword}`);
    } else {
      logMinimal(`Client da ${ip} disconnesso senza stanza`);
    }
    rateState.delete(ws);
  });
});

server.listen(PORT, () => {
  logMinimal(`Server WebSocket in ascolto sulla porta ${PORT}`);
});
