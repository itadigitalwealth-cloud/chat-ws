/* ============================================================
   PEGASUSCHAT FRONTEND LOGIC
   - Login / Register
   - WebSocket
   - Search Users
   - Open Chat
   - E2EE (ECDH + AES-GCM) con accettazione stile Signal
   ============================================================ */

/* ==========================
   VARIABILI GLOBALI
   ========================== */
let me = null;                 // @username loggato
let ws = null;                 // websocket
let currentChat = null;        // @destinatario aperto
let sessionKeys = {};          // per ogni utente: AES key derivata
let myKeyPair = null;          // chiavi ECDH del client
let trustedKeys = {};          // chiavi pubbliche "accettate"

/* ==========================
   API BASE URL
   ========================== */
const API = window.location.origin;   // Cambia quando deployi su Render


/* ============================================================
   FUNZIONI UTILI
   ============================================================ */

// Wrapper per POST
async function post(url, data) {
  const r = await fetch(API + url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  return r.json();
}

// Wrapper per GET
async function get(url) {
  const r = await fetch(API + url);
  return r.json();
}


/* ============================================================
   E2EE — FUNZIONI CRITTOGRAFICHE
   ============================================================ */

// genera coppia di chiavi ECDH
async function generateECDH() {
  return crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveKey"]
  );
}

// esporta chiave pubblica in base64
async function exportKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// importa key pubblica da base64
async function importPublicKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

// deriva AES da ECDH
async function deriveAES(myPrivate, theirPublicKey) {
  return crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: theirPublicKey
    },
    myPrivate,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// cifra testo
async function encrypt(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  return {
    iv: btoa(String.fromCharCode(...iv)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
  };
}

// decifra testo
async function decrypt(key, ivB64, ctB64) {
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ct
  );

  return new TextDecoder().decode(decrypted);
}


/* ============================================================
   LOGIN / REGISTER
   ============================================================ */

async function registerUser() {
  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value.trim();
  const status = document.getElementById("loginStatus");

  if (!username.startsWith("@")) {
    status.textContent = "Lo username deve iniziare con @";
    return;
  }

  myKeyPair = await generateECDH();
  const publicKey = await exportKey(myKeyPair.publicKey);

  const r = await post("/api/register", {
    username,
    password,
    publicKey
  });

  if (r.error) {
    status.textContent = r.error;
    return;
  }

  status.style.color = "#4a7dff";
  status.textContent = "Registrato! Ora fai login.";
}

async function loginUser() {
  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value.trim();
  const status = document.getElementById("loginStatus");

  const r = await post("/api/login", {
    username,
    password
  });

  if (!r.ok) {
    status.textContent = r.error;
    return;
  }

  me = username;
  document.getElementById("meUsername").textContent = me;

  await loadMyKey(); // recupera la chiave privata se c'è │ generala se no
  connectWS();

  document.getElementById("loginView").style.display = "none";
  document.getElementById("chatView").style.display = "flex";

  loadConversations();
}

/* ============================================================
   RECUPERO / GENERAZIONE CHIAVI LOCALI
   ============================================================ */
async function loadMyKey() {
  // Per ora, generiamo chiave ogni volta (in futuro: salvare su localStorage)
  myKeyPair = await generateECDH();
}


/* ============================================================
   WEBSOCKET
   ============================================================ */

function connectWS() {
  const proto = API.startsWith("https") ? "wss://" : "ws://";
  ws = new WebSocket(proto + API.replace(/^https?:\/\//, ""));

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", username: me }));
  };

  ws.onmessage = async (ev) => {
    const data = JSON.parse(ev.data);

    if (data.type === "message") {
      const m = data.msg;
      if (m.from === currentChat || m.to === currentChat) {
        await displayIncoming(m);
      }
    }
  };
}


/* ============================================================
   CERCA UTENTI
   ============================================================ */
async function searchUsers() {
  const q = document.getElementById("searchInput").value;
  const results = await get("/api/users?search=" + encodeURIComponent(q));

  const box = document.getElementById("searchResults");
  box.innerHTML = "";

  results.forEach(u => {
    if (u.username === me) return;
    const div = document.createElement("div");
    div.textContent = u.username;
    div.onclick = () => openChat(u.username);
    box.appendChild(div);
  });
}


/* ============================================================
   LISTA CHAT RECENTI
   ============================================================ */
async function loadConversations() {
  const list = await get(`/api/conversations?me=${me}`);

  const box = document.getElementById("chatList");
  box.innerHTML = "";

  list.forEach(c => {
    const div = document.createElement("div");
    div.textContent = c.username;
    div.onclick = () => openChat(c.username);
    box.appendChild(div);
  });
}


/* ============================================================
   APRI CHAT
   ============================================================ */
async function openChat(username) {
  currentChat = username;

  // mostra header
  document.getElementById("chatHeader").textContent = username;

  // recupera chiave pubblica dell'altro
  const other = await get(`/api/user/${username}`);

  if (!trustedKeys[username]) {
    const ok = confirm(
      `Vuoi accettare la chiave pubblica di ${username}?\n` +
      `Una volta accettata, avrete la vostra chiave E2EE.`
    );
    if (!ok) return;

    trustedKeys[username] = other.publicKey;
  }

  // deriviamo la session key
  const theirPub = await importPublicKey(trustedKeys[username]);
  sessionKeys[username] = await deriveAES(myKeyPair.privateKey, theirPub);

  // carica storico cifrato
  const history = await get(`/api/messages?me=${me}&with=${username}`);

  const box = document.getElementById("messagesBox");
  box.innerHTML = "";

  for (const msg of history) {
    await displayIncoming(msg);
  }
}


/* ============================================================
   INVIO MESSAGGI
   ============================================================ */
async function sendMessage() {
  if (!currentChat) return;

  const text = document.getElementById("messageInput").value;
  if (!text) return;

  const key = sessionKeys[currentChat];
  const { iv, ciphertext } = await encrypt(key, text);

  // POST al backend
  await post("/api/messages", {
    from: me,
    to: currentChat,
    iv,
    ciphertext,
    ts: Date.now()
  });

  displayBubble("me", text);
  document.getElementById("messageInput").value = "";
}


/* ============================================================
   RICEZIONE MESSAGGI
   ============================================================ */

async function displayIncoming(msg) {
  const key = sessionKeys[msg.from] || sessionKeys[msg.to];
  if (!key) return;

  const text = await decrypt(key, msg.iv, msg.ciphertext);

  if (msg.from === me) {
    displayBubble("me", text);
  } else {
    displayBubble("them", text);
  }
}


/* ============================================================
   BOLLE GRAFICHE
   ============================================================ */

function displayBubble(type, text) {
  const box = document.getElementById("messagesBox");

  const div = document.createElement("div");
  div.className = `message ${type}`;
  div.textContent = text;

  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}
