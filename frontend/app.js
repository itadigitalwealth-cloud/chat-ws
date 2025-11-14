/* ============================================================
   PEGASUSCHAT - FRONTEND (STILE TELEGRAM, E2EE FIXATA)
   ============================================================ */

/* ==========================
   CONFIG
   ========================== */

// Backend e frontend stanno sullo stesso dominio (Render)
const API = window.location.origin;
// WebSocket sullo stesso host
const WS_URL = API.replace(/^http/, "ws");

/* ==========================
   STATE
   ========================== */

let me = null;                 // @username loggato
let ws = null;                 // websocket
let currentChat = null;        // @contatto aperto

let myKeyPair = null;          // chiavi ECDH locali (per questo utente)
const sessionKeys = {};        // { "@other": CryptoKey AES-GCM }

/* ==========================
   UTILS HTTP
   ========================== */

async function post(url, data) {
  const res = await fetch(API + url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  return res.json();
}

async function get(url) {
  const res = await fetch(API + url);
  return res.json();
}

/* ============================================================
   CRITTOGRAFIA E2EE
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

// esporta pubblica in base64
async function exportPublicKeyBase64(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// importa chiave pubblica da base64
async function importPublicKeyBase64(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

// salva chiavi in localStorage (per username)
async function saveKeyPairForUser(username, keyPair) {
  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const payload = { pubJwk, privJwk };
  localStorage.setItem("pegasus_keypair_" + username, JSON.stringify(payload));
}

// carica chiavi da localStorage, senza generarne di nuove
async function loadKeyPairForUser(username) {
  const raw = localStorage.getItem("pegasus_keypair_" + username);
  if (!raw) throw new Error("chiave locale non trovata per " + username);
  const parsed = JSON.parse(raw);

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    parsed.pubJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    parsed.privJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"]
  );

  return { publicKey, privateKey };
}

// deriva AES-GCM da ECDH
async function deriveSessionKey(myPrivate, theirPublicKey) {
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
async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(text);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return {
    iv: btoa(String.fromCharCode(...iv)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
  };
}

// decifra testo
async function decryptText(key, ivB64, ctB64) {
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
   AUTH
   ============================================================ */

async function registerUser() {
  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value.trim();
  const status = document.getElementById("loginStatus");

  if (!username.startsWith("@")) {
    status.textContent = "Lo username deve iniziare con @";
    return;
  }
  if (password.length < 4) {
    status.textContent = "Password troppo corta";
    return;
  }

  // genera coppia di chiavi una volta per sempre per questo utente
  const keyPair = await generateECDH();
  myKeyPair = keyPair;

  // salva localmente
  await saveKeyPairForUser(username, keyPair);

  // manda solo la PUBLIC al server
  const publicKeyB64 = await exportPublicKeyBase64(keyPair.publicKey);

  const r = await post("/api/register", {
    username,
    password,
    publicKey: publicKeyB64
  });

  if (r.error) {
    status.textContent = r.error;
    return;
  }

  status.style.color = "#4ade80";
  status.textContent = "Registrato. Ora fai login.";
}

async function loginUser() {
  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value.trim();
  const status = document.getElementById("loginStatus");

  status.textContent = "";

  const r = await post("/api/login", {
    username,
    password
  });

  if (!r.ok) {
    status.textContent = r.error || "Credenziali errate";
    return;
  }

  me = r.username;
  document.getElementById("meUsername").textContent = me;

  try {
    // carica la chiave usata in fase di registrazione
    myKeyPair = await loadKeyPairForUser(me);
  } catch (e) {
    status.textContent = "Chiave locale non trovata. Registrati di nuovo con un nuovo account.";
    return;
  }

  connectWS();
  document.getElementById("loginView").style.display = "none";
  document.getElementById("chatView").style.display = "flex";

  await loadConversations();
}

/* ============================================================
   WEBSOCKET
   ============================================================ */

function connectWS() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", username: me }));
  };

  ws.onmessage = async (event) => {
    const data = JSON.parse(event.data);

    if (data.type === "message") {
      const msg = data.msg;
      await handleIncomingWSMessage(msg);
    }
  };
}

/* ============================================================
   UTENTI / RICERCA / CHAT LIST
   ============================================================ */

async function searchUsers() {
  const q = document.getElementById("searchInput").value.trim();
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

async function loadConversations() {
  const list = await get("/api/conversations?me=" + encodeURIComponent(me));

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
   GESTIONE CHATS
   ============================================================ */

// prepara sessionKey con un utente specifico (EC(DH))
async function ensureSessionKeyFor(otherUsername) {
  if (sessionKeys[otherUsername]) return sessionKeys[otherUsername];

  // prendi la chiave pubblica dell'altro dal server
  const other = await get("/api/user/" + encodeURIComponent(otherUsername));
  const theirPub = await importPublicKeyBase64(other.publicKey);

  const aesKey = await deriveSessionKey(myKeyPair.privateKey, theirPub);
  sessionKeys[otherUsername] = aesKey;
  return aesKey;
}

async function openChat(username) {
  currentChat = username;

  // aggiorna header
  document.getElementById("chatHeader").textContent = username;

  // prepara session key
  await ensureSessionKeyFor(username);

  // carica storico
  const history = await get(`/api/messages?me=${encodeURIComponent(me)}&with=${encodeURIComponent(username)}`);

  const box = document.getElementById("messagesBox");
  box.innerHTML = "";

  for (const msg of history) {
    await displayDecryptedMessage(msg);
  }
}

/* ============================================================
   INVIO MESSAGGI
   ============================================================ */

async function sendMessage() {
  if (!currentChat) return;

  const input = document.getElementById("messageInput");
  const text = input.value.trim();
  if (!text) return;

  // assicura che la sessionKey esista
  const key = await ensureSessionKeyFor(currentChat);

  const { iv, ciphertext } = await encryptText(key, text);

  // manda al server
  await post("/api/messages", {
    from: me,
    to: currentChat,
    iv,
    ciphertext,
    ts: Date.now()
  });

  // mostra subito il tuo messaggio nella chat
  addBubble("me", text);
  input.value = "";
}

/* ============================================================
   RICEZIONE MESSAGGI
   ============================================================ */

// gestione messaggi arrivati via WS
async function handleIncomingWSMessage(msg) {
  // chi è l'altro nella conversazione?
  const other = msg.from === me ? msg.to : msg.from;

  // prepara session key per quell'utente, se non esiste
  await ensureSessionKeyFor(other);

  // se la chat aperta è quella giusta, mostra messaggio
  if (currentChat === other) {
    await displayDecryptedMessage(msg);
  } else {
    // in futuro: potresti highlightare la chat nella sidebar
    await displayDecryptedMessage(msg); // opzionale: comunque appendi
  }

  // aggiorna lista conversazioni (se nuovo contatto)
  loadConversations();
}

// decifra e mostra un messaggio da DB/WS
async function displayDecryptedMessage(msg) {
  try {
    const other = msg.from === me ? msg.to : msg.from;
    const key = sessionKeys[other] || sessionKeys[msg.from] || sessionKeys[msg.to];
    if (!key) return;

    const text = await decryptText(key, msg.iv, msg.ciphertext);

    if (msg.from === me) {
      addBubble("me", text);
    } else {
      addBubble("them", text);
    }
  } catch (e) {
    console.error("Errore decrittando messaggio:", e);
  }
}

/* ============================================================
   UI BOLLE MESSAGGI
   ============================================================ */

function addBubble(type, text) {
  const box = document.getElementById("messagesBox");

  const div = document.createElement("div");
  div.className = "message " + type;
  div.textContent = text;

  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}
