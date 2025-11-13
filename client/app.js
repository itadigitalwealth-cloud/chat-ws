/********************************************************************
 *  AnonCipher Messenger – Frontend completo
 *  Login, registrazione, E2EE, vault cifrato, chat 1-to-1, file, ecc.
 ********************************************************************/

const api = {
  register: "/api/register",
  login: "/api/login",
  saveMsg: "/api/messages",
  history: "/api/history"
};

let me = null;
let masterKey = null;
let privateKey = null;
let publicKey = null;
let vault = null;
let ws = null;
let activeChat = null;
let sessionKeys = {};  // chatId -> AES key

//------------------------------------------------------------------
// UI
//------------------------------------------------------------------

const loginScreen = document.getElementById("loginScreen");
const chatScreen  = document.getElementById("chatScreen");

const tabLogin    = document.getElementById("tabLogin");
const tabRegister = document.getElementById("tabRegister");
const loginForm   = document.getElementById("loginForm");
const regForm     = document.getElementById("registerForm");

tabLogin.onclick = () => {
  tabLogin.classList.add("active");
  tabRegister.classList.remove("active");
  loginForm.classList.remove("hidden");
  regForm.classList.add("hidden");
};

tabRegister.onclick = () => {
  tabRegister.classList.add("active");
  tabLogin.classList.remove("active");
  regForm.classList.remove("hidden");
  loginForm.classList.add("hidden");
};

document.getElementById("loginBtn").onclick = login;
document.getElementById("registerBtn").onclick = register;

document.getElementById("logoutBtn").onclick = () => {
  localStorage.removeItem("vault");
  location.reload();
};

//------------------------------------------------------------------
// UTIL
//------------------------------------------------------------------

function enc(text) {
  return new TextEncoder().encode(text);
}

function dec(buf) {
  return new TextDecoder().decode(buf);
}

async function sha256(str) {
  const hash = await crypto.subtle.digest("SHA-256", enc(str));
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function deriveMasterKey(password) {
  const salt = enc("AnonCipherSaltV1");
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc(password), {name:"PBKDF2"}, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey({
    name:"PBKDF2",
    salt,
    iterations:200000,
    hash:"SHA-256"
  }, keyMaterial, {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
}

async function aesEncrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    {name:"AES-GCM", iv},
    key,
    data
  );
  return {
    iv : btoa(String.fromCharCode(...iv)),
    data: btoa(String.fromCharCode(...new Uint8Array(cipher)))
  };
}

async function aesDecrypt(key, obj) {
  const iv  = Uint8Array.from(atob(obj.iv),  c=>c.charCodeAt(0));
  const buf = Uint8Array.from(atob(obj.data),c=>c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt(
    {name:"AES-GCM", iv},
    key,
    buf
  );
  return new Uint8Array(plain);
}

//------------------------------------------------------------------
// VAULT (CIFRATO)
//------------------------------------------------------------------

async function saveVault() {
  const raw = {};
  raw.privateKey = await crypto.subtle.exportKey("pkcs8", privateKey);
  raw.sessionKeys = {}; // session keys le ricostruiamo
  raw.chats = Object.keys(sessionKeys);

  const plaintext = enc(JSON.stringify(raw));
  const cipher = await aesEncrypt(masterKey, plaintext);
  localStorage.setItem("vault", JSON.stringify(cipher));
}

async function loadVault(cipherObj, password) {
  masterKey = await deriveMasterKey(password);
  const data = await aesDecrypt(masterKey, cipherObj);
  const json = JSON.parse(dec(data));

  privateKey = await crypto.subtle.importKey(
    "pkcs8",
    json.privateKey,
    {name:"ECDH", namedCurve:"P-256"},
    false,
    ["deriveKey"]
  );
  return json;
}

//------------------------------------------------------------------
// REGISTRAZIONE
//------------------------------------------------------------------

async function register() {
  const u = document.getElementById("regUser").value.trim();
  const p = document.getElementById("regPass").value.trim();
  const out = document.getElementById("registerStatus");

  out.textContent = "";

  if (!u.startsWith("@") || u.length < 3) {
    out.textContent = "Username invalido.";
    return;
  }
  if (p.length < 6) {
    out.textContent = "Password troppo corta.";
    return;
  }

  // Genera chiave ECDH
  const keyPair = await crypto.subtle.generateKey(
    {name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey"]
  );
  privateKey = keyPair.privateKey;
  publicKey  = keyPair.publicKey;

  const pub = await crypto.subtle.exportKey("raw", publicKey);
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pub)));

  // Prepara vault iniziale
  masterKey = await deriveMasterKey(p);
  const vaultObj = {
    privateKey: await crypto.subtle.exportKey("pkcs8", privateKey),
    sessionKeys:{},
    chats:[]
  };
  const vaultCipher = await aesEncrypt(masterKey, enc(JSON.stringify(vaultObj)));

  // REGISTRA SUL SERVER
  const resp = await fetch(api.register, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({
      username:u,
      password:p,
      publicKey:pubB64,
      vaultCiphertext:vaultCipher
    })
  });
  const json = await resp.json();
  if (json.error) {
    out.textContent = json.error;
    return;
  }

  // salva vault localmente
  localStorage.setItem("vault", JSON.stringify(vaultCipher));
  me = u;

  showChat();
}

//------------------------------------------------------------------
// LOGIN
//------------------------------------------------------------------

async function login() {
  const u = document.getElementById("loginUser").value.trim();
  const p = document.getElementById("loginPass").value.trim();
  const out = document.getElementById("loginStatus");

  out.textContent = "";

  const resp = await fetch(api.login, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username:u, password:p})
  });
  const data = await resp.json();

  if (data.error) {
    out.textContent = data.error;
    return;
  }

  // carica vault
  const cipher = data.vaultCiphertext;
  const loc = localStorage.getItem("vault");
  const vaultCipher = loc ? JSON.parse(loc) : cipher;

  const v = await loadVault(vaultCipher, p);

  me = u;

  showChat();
}

//------------------------------------------------------------------
// MOSTRA CHAT SCREEN
//------------------------------------------------------------------

async function showChat() {
  document.getElementById("profileName").textContent = me;
  loginScreen.classList.remove("active");
  chatScreen.classList.add("active");

  connectWS();
}

//------------------------------------------------------------------
// WEBSOCKET
//------------------------------------------------------------------

function connectWS() {
  ws = new WebSocket(`wss://${location.host}`);

  ws.onopen = () => {
    ws.send(JSON.stringify({
      type:"auth",
      username:me
    }));
  };

  ws.onmessage = async (ev) => {
    const msg = JSON.parse(ev.data);

    if (msg.type === "dm") {
      await handleIncomingDM(msg);
    }
  };
}

//------------------------------------------------------------------
// ECDH SESSION KEY
//------------------------------------------------------------------

async function getSessionKey(targetUser) {
  const chatId = await sha256(me + targetUser);
  if (sessionKeys[chatId]) return sessionKeys[chatId];

  // prendi la publicKey dell'altro
  const resp = await fetch(`/api/users/${targetUser}`);
  const data = await resp.json();
  if (data.error) return null;

  const pub = Uint8Array.from(atob(data.publicKey), c=>c.charCodeAt(0));
  const otherPubKey = await crypto.subtle.importKey(
    "raw",
    pub,
    {name:"ECDH", namedCurve:"P-256"},
    true,
    []
  );

  const key = await crypto.subtle.deriveKey(
    {name:"ECDH", public:otherPubKey},
    privateKey,
    {name:"AES-GCM", length:256},
    false,
    ["encrypt","decrypt"]
  );
  sessionKeys[chatId] = key;
  return key;
}

//------------------------------------------------------------------
// INVIO MESSAGGI
//------------------------------------------------------------------

document.getElementById("sendBtn").onclick = sendMessage;
document.getElementById("msgInput").addEventListener("keypress", e=>{
  if (e.key === "Enter") sendMessage();
});

async function sendMessage() {
  if (!activeChat) return;

  const text = document.getElementById("msgInput").value.trim();
  if (!text) return;

  const key = await getSessionKey(activeChat);

  const cipher = await aesEncrypt(key, enc(text));

  ws.send(JSON.stringify({
    type:"dm",
    from:me,
    to:activeChat,
    ciphertext:cipher
  }));

  appendMsg("me", text);
  document.getElementById("msgInput").value = "";

  await saveMessageToServer(activeChat, cipher);
}

async function saveMessageToServer(target, cipher) {
  const chatId = await sha256(me + target);
  const msg = {
    from:me,
    to:target,
    ts:Date.now(),
    ciphertext:cipher,
    vaultCiphertext:cipher // doppio livello possibile ma ridondante
  };
  await fetch(api.saveMsg, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({chatId, msg})
  });
}

//------------------------------------------------------------------
// RICEZIONE MESSAGGI
//------------------------------------------------------------------

async function handleIncomingDM(data) {
  const {from, ciphertext} = data;

  const key = await getSessionKey(from);
  const plainBuf = await aesDecrypt(key, ciphertext);
  const text = dec(plainBuf);

  if (activeChat === from) {
    appendMsg("them", text);
  }

  await saveMessageToServer(from, ciphertext); 
}

//------------------------------------------------------------------
// VISUALIZZAZIONE CHAT
//------------------------------------------------------------------

document.getElementById("searchBtn").onclick = searchUser;
async function searchUser() {
  const t = document.getElementById("searchUser").value.trim();
  const resp = await fetch(`/api/users?search=${encodeURIComponent(t)}`);
  const list = await resp.json();

  const chatList = document.getElementById("chatList");
  chatList.innerHTML = "";

  for (const u of list) {
    if (u.username === me) continue;

    const div = document.createElement("div");
    div.className = "chat-item";
    div.textContent = u.username;
    div.onclick = () => openChat(u.username);
    chatList.appendChild(div);
  }
}

async function openChat(target) {
  activeChat = target;

  document.getElementById("chatTarget").textContent = target;
  document.getElementById("messages").innerHTML = "";

  const chatId = await sha256(me + target);
  const resp = await fetch(`/api/history?chatId=${chatId}`);
  const history = await resp.json();

  const key = await getSessionKey(target);

  for (const m of history) {
    const plain = await aesDecrypt(key, m.ciphertext);
    const text = dec(plain);

    appendMsg(m.from === me ? "me":"them", text);
  }
}

function appendMsg(who, text) {
  const div = document.createElement("div");
  div.className = "message " + who;
  div.textContent = text;
  document.getElementById("messages").appendChild(div);
  document.getElementById("messages").scrollTop = 9999999;
}

