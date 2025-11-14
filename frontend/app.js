/* ================================================
   PegasusChat - frontend finale
   ================================================ */

// Backend e frontend sullo stesso host (Render)
const API = window.location.origin;
const WS_URL = API.replace(/^http/, "ws");

// Stato
let me = null;                 // @username loggato
let ws = null;                 // websocket
let currentChat = null;        // utente con cui sto chattando
let myKeyPair = null;          // chiave ECDH locale (pub+priv)
const sessionKeys = {};        // "@altro" -> CryptoKey AES-GCM

// ===== HTTP helpers =====
async function post(url, body) {
  const res = await fetch(API + url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  return res.json();
}

async function get(url) {
  const res = await fetch(API + url);
  return res.json();
}

// ===== CRITTOGRAFIA E2EE =====

// genera coppia ECDH P-256
async function generateECDH() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
}

// esporta publicKey in base64 (raw)
async function exportPublicKeyBase64(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// importa publicKey base64 (raw)
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

// salva coppia chiavi per utente in localStorage (JWK)
async function saveKeyPairForUser(username, keyPair) {
  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const obj = { pubJwk, privJwk };
  localStorage.setItem("pegasus_keypair_" + username, JSON.stringify(obj));
}

// carica coppia chiavi per utente da localStorage
async function loadKeyPairForUser(username) {
  const raw = localStorage.getItem("pegasus_keypair_" + username);
  if (!raw) throw new Error("Keypair non trovato per " + username);
  const obj = JSON.parse(raw);

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    obj.pubJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    obj.privJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"]
  );

  return { publicKey, privateKey };
}

// deriva chiave di sessione AES-GCM da ECDH
async function deriveSessionKey(privateKey, otherPublicKey) {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: otherPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// cifra testo con AES-GCM
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

// ===== AUTH =====

async function registerUser() {
  const userEl = document.getElementById("regUser");
  const passEl = document.getElementById("regPass");
  const statusEl = document.getElementById("loginErr");

  const username = userEl.value.trim();
  const password = passEl.value.trim();

  statusEl.textContent = "";
  statusEl.style.color = "red";

  if (!username.startsWith("@") || username.length < 3) {
    statusEl.textContent = "Lo username deve iniziare con @ ed essere lungo almeno 3 caratteri.";
    return;
  }
  if (password.length < 4) {
    statusEl.textContent = "Password troppo corta.";
    return;
  }

  try {
    // genera coppia chiavi una sola volta
    const keyPair = await generateECDH();
    myKeyPair = keyPair;

    // salva in localStorage
    await saveKeyPairForUser(username, keyPair);

    // manda al server solo la publicKey
    const publicKeyB64 = await exportPublicKeyBase64(keyPair.publicKey);

    const res = await post("/api/register", {
      username,
      password,
      publicKey: publicKeyB64
    });

    if (res.error) {
      statusEl.textContent = res.error;
      return;
    }

    statusEl.style.color = "#4ade80";
    statusEl.textContent = "Registrato. Ora effettua il login.";
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Errore durante la registrazione.";
  }
}

async function loginUser() {
  const userEl = document.getElementById("logUser");
  const passEl = document.getElementById("logPass");
  const statusEl = document.getElementById("loginErr");

  const username = userEl.value.trim();
  const password = passEl.value.trim();

  statusEl.textContent = "";
  statusEl.style.color = "red";

  if (!username || !password) {
    statusEl.textContent = "Inserisci username e password.";
    return;
  }

  try {
    const res = await post("/api/login", { username, password });
    if (!res.ok) {
      statusEl.textContent = res.error || "Credenziali errate.";
      return;
    }

    me = res.username;
    localStorage.setItem("pegasus_username", me);

    try {
      myKeyPair = await loadKeyPairForUser(me);
    } catch (err) {
      statusEl.textContent = "Chiave locale non trovata per questo utente su questo device. Registrati da qui.";
      return;
    }

    // passa alla view di chat
    document.getElementById("loginView").style.display = "none";
    document.getElementById("chatView").style.display = "flex";
    const meBox = document.querySelector(".me-box");
    if (meBox) meBox.textContent = me;

    connectWS();
    await loadConversations();

  } catch (err) {
    console.error(err);
    statusEl.textContent = "Errore di connessione al server.";
  }
}

// auto-login se è salvato qualcosa
async function tryAutoLogin() {
  const savedUser = localStorage.getItem("pegasus_username");
  if (!savedUser) return;

  const statusEl = document.getElementById("loginErr");
  try {
    me = savedUser;
    myKeyPair = await loadKeyPairForUser(me);

    document.getElementById("loginView").style.display = "none";
    document.getElementById("chatView").style.display = "flex";
    const meBox = document.querySelector(".me-box");
    if (meBox) meBox.textContent = me;

    connectWS();
    await loadConversations();
  } catch (err) {
    console.warn("Auto-login fallito:", err);
    statusEl.textContent = "Impossibile ricaricare la sessione salvata.";
  }
}

// ===== WEBSOCKET =====

function connectWS() {
  if (!me) return;

  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", username: me }));
  };

  ws.onmessage = async (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch {
      return;
    }

    if (data.type === "message") {
      await handleIncomingWSMessage(data.msg);
    }
  };

  ws.onclose = () => {
    // tenta di riconnettersi dopo 1 secondo
    setTimeout(() => {
      connectWS();
    }, 1000);
  };
}

// ===== UTENTI / CONVERSAZIONI =====

async function searchUsers() {
  const q = document.getElementById("searchUser").value.trim();
  let list = [];
  try {
    list = await get("/api/users?search=" + encodeURIComponent(q));
  } catch (err) {
    console.error(err);
    return;
  }

  const box = document.getElementById("convList");
  box.innerHTML = "";

  list.forEach(u => {
    if (u.username === me) return;
    const div = document.createElement("div");
    div.className = "conv";
    div.textContent = u.username;
    div.onclick = () => openChat(u.username);
    box.appendChild(div);
  });
}

async function loadConversations() {
  if (!me) return;
  let list = [];
  try {
    list = await get("/api/conversations?me=" + encodeURIComponent(me));
  } catch (err) {
    console.error(err);
    return;
  }

  const box = document.getElementById("convList");
  box.innerHTML = "";

  list.forEach(c => {
    const div = document.createElement("div");
    div.className = "conv";
    div.textContent = c.username;
    div.onclick = () => openChat(c.username);
    box.appendChild(div);
  });
}

// ===== CHAT =====

async function ensureSessionKeyFor(other) {
  if (sessionKeys[other]) return sessionKeys[other];

  // ottieni chiave pubblica dell'altro
  const info = await get("/api/user/" + encodeURIComponent(other));
  const theirPub = await importPublicKeyBase64(info.publicKey);

  const aesKey = await deriveSessionKey(myKeyPair.privateKey, theirPub);
  sessionKeys[other] = aesKey;
  return aesKey;
}

async function openChat(username) {
  if (!me) return;

  currentChat = username;
  document.getElementById("chatHeader").textContent = username;

  const msgsBox = document.getElementById("chatMessages");
  msgsBox.innerHTML = "";

  // prepara session key
  await ensureSessionKeyFor(username);

  // scarica storico
  let history = [];
  try {
    history = await get(
      "/api/messages?me=" +
      encodeURIComponent(me) +
      "&with=" +
      encodeURIComponent(username)
    );
  } catch (err) {
    console.error(err);
    return;
  }

  for (const msg of history) {
    await displayDecryptedMessage(msg);
  }
}

async function sendMessage() {
  if (!me || !currentChat) return;

  const input = document.getElementById("msgBox");
  const text = input.value.trim();
  if (!text) return;

  try {
    const key = await ensureSessionKeyFor(currentChat);
    const { iv, ciphertext } = await encryptText(key, text);

    // salva lato server + push via WS
    await post("/api/messages", {
      from: me,
      to: currentChat,
      iv,
      ciphertext,
      ts: Date.now()
    });

    addBubble("me", text);
    input.value = "";
  } catch (err) {
    console.error("Errore invio:", err);
  }
}

// messaggio in arrivo via WS
async function handleIncomingWSMessage(msg) {
  const other =
    msg.from === me
      ? msg.to
      : msg.from;

  try {
    await ensureSessionKeyFor(other);
    if (!currentChat || currentChat === other) {
      await displayDecryptedMessage(msg);
    } else {
      // chat diversa: in futuro potresti evidenziare la conversazione
      // per ora comunque non spammiamo
    }
    // aggiorna lista chat (se nuovo contatto appare)
    loadConversations();
  } catch (err) {
    console.error("Errore handleIncomingWSMessage:", err);
  }
}

// decifra + mostra bubble
async function displayDecryptedMessage(msg) {
  try {
    const other = msg.from === me ? msg.to : msg.from;
    const key =
      sessionKeys[other] ||
      sessionKeys[msg.from] ||
      sessionKeys[msg.to];

    if (!key) return;

    const text = await decryptText(key, msg.iv, msg.ciphertext);

    if (msg.from === me) {
      addBubble("me", text);
    } else {
      addBubble("other", text);
    }
  } catch (err) {
    console.error("Errore decrypt msg:", err);
  }
}

function addBubble(type, text) {
  const box = document.getElementById("chatMessages");
  const div = document.createElement("div");
  div.className = "msg " + type;
  div.textContent = text;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

// ===== INIT =====

window.addEventListener("load", () => {
  // bottoni auth
  document.getElementById("regBtn").onclick = registerUser;
  document.getElementById("logBtn").onclick = loginUser;

  // invio messaggio
  document.getElementById("sendBtn").onclick = sendMessage;

  document.getElementById("msgBox").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  });

  // ricerca utenti
  document.getElementById("searchUser").addEventListener("input", () => {
    const val = document.getElementById("searchUser").value.trim();
    if (val.length === 0) {
      loadConversations();
    } else {
      searchUsers();
    }
  });

  // auto login se possibile
  tryAutoLogin();
});
