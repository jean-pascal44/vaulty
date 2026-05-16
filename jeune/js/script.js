// --- LOGIQUE CORE : GESTIONNAIRE DE MOTS DE PASSE SECURISE (LAZY LOADING) ---

let masterKey = null;
// Ne stocke JAMAIS le mot de passe maître brut, uniquement l'objet CryptoKey dérivé
const RAM_CLEANUP_MS = 30000;
// Nettoyage de la RAM et du DOM après 30 secondes pour le mot de passe décodé

// Dictionnaire cryptographique simulé pour la génération de Passphrase
const wordlist = [
    "arbre", "soleil", "code", "crypto", "vague", "ombre", "lumiere", "falaise", "nuage", "source", 
    "planete", "atome", "boussole", "navire", "horizon", "sable", "foret", "etoile", "fleur", "torrent",
    "cascade", "rocher", "galaxie", "comete", "cristal", "aurore", "enigme", "bastion", "oracle", "abysse"
];

// --- 1. DERIVATION DE CLÉ (PBKDF2 SHA-256 via Web Crypto API) ---
async function deriveKey(masterPassword) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(masterPassword);
    
    // Sel cryptographique statique pour assurer la cohérence de la dérivation locale.
    const salt = encoder.encode("un-sel-unique-statique-et-long-pour-isoler-la-derivation-locale-du-coffre");
    const baseKey = await window.crypto.subtle.importKey(
        "raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false, // Reste isolé en mémoire, non exportable via script tiers ou console.
        ["encrypt", "decrypt"]
    );
}

// --- 2. INTERFACE D'AUTHENTIFICATION ---
async function handleAuth(e) {
    e.preventDefault();
    const pwdInput = document.getElementById('master-password');
    const pwd = pwdInput.value;
    if(!pwd) return;

    try {
        masterKey = await deriveKey(pwd);
        // Nettoyage immédiat de l'input brute en RAM
        pwdInput.value = "";
        // Transition d'écran
        document.getElementById('auth-screen').classList.add('hidden-vault');
        document.getElementById('app-screen').classList.remove('hidden-vault');
        // Premier rendu (Lazy loading initial de l'arborescence)
        renderVault();
    } catch (err) {
        alert("Échec de la génération de la clé de chiffrement.");
        console.error(err);
    }
}

function lockVault() {
    masterKey = null;
    document.getElementById('auth-screen').classList.remove('hidden-vault');
    document.getElementById('app-screen').classList.add('hidden-vault');
    resetForm();
}

// --- 3. ENGINS DE CHIFFREMENT / DÉCHIFFREMENT UNITAIRES ---
async function encryptData(plainText) {
    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV unique généré à chaque appel
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, masterKey, encoder.encode(plainText)
    );
    return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        iv: btoa(String.fromCharCode(...iv))
    };
}

async function decryptData(cipherTextB64, ivB64) {
    const iv = new Uint8Array(atob(ivB64).split("").map(c => c.charCodeAt(0)));
    const ciphertext = new Uint8Array(atob(cipherTextB64).split("").map(c => c.charCodeAt(0)));

    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, masterKey, ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

// --- 4. OPÉRATIONS CRUD SUR LE LOCALSTORAGE (ZÉRO METADONNÉES EN CLAIR) ---
function getStorage() {
    return JSON.parse(localStorage.getItem('secure_vault_v2')) || [];
}

function setStorage(entries) {
    localStorage.setItem('secure_vault_v2', JSON.stringify(entries));
}

async function saveEntry(e) {
    e.preventDefault();
    const id = document.getElementById('entry-id').value;
    const service = document.getElementById('entry-service').value;
    const login = document.getElementById('entry-login').value;
    const pass = document.getElementById('entry-pass').value;

    try {
        const encService = await encryptData(service);
        const encLogin = await encryptData(login);
        const encPass = await encryptData(pass);

        const entries = getStorage();
        const newEntry = {
            id: id || Date.now().toString(),
            service: encService,
            login: encLogin,
            encryptedPass: encPass.ciphertext,
            iv: encPass.iv
        };

        if (id) {
            const index = entries.findIndex(item => item.id === id);
            if(index !== -1) entries[index] = newEntry;
        } else {
            entries.push(newEntry);
        }

        setStorage(entries);
        resetForm();
        renderVault();
    } catch (err) {
        alert("Erreur lors du chiffrement et de la sauvegarde de la ligne.");
    }
}

function deleteEntry(id) {
    if(confirm("Supprimer définitivement cet identifiant de votre espace local ?")) {
        const entries = getStorage().filter(item => item.id !== id);
        setStorage(entries);
        renderVault();
    }
}

// --- 5. RENDER REPENSI : ÉLÉMENTS PLUS GRANDS, ENTRÉES EMBELLIES ---
async function renderVault() {
    const entries = getStorage();
    document.getElementById('vault-count').innerText = entries.length;
    const listContainer = document.getElementById('vault-list');
    listContainer.innerHTML = "";

    if(entries.length === 0) {
        listContainer.innerHTML = `<p class="text-purple-300/40 text-sm text-center py-12 border border-dashed border-purple-950 rounded-2xl">Ton coffre est vide pour l'instant. Ajoute tes premiers comptes à gauche ! 🚀</p>`;
        return;
    }

    for (const entry of entries) {
        try {
            const decService = await decryptData(entry.service.ciphertext, entry.service.iv);
            const decLogin = await decryptData(entry.login.ciphertext, entry.login.iv);

            const div = document.createElement('div');
            div.className = "bg-[#070414] p-5 rounded-2xl border border-purple-950/60 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 animate-fadeIn hover:border-purple-800/40 transition-all shadow-inner";
            div.innerHTML = `
                <div class="space-y-1 w-full sm:w-auto">
                    <h3 class="font-extrabold text-white text-base tracking-wide">${escapeHtml(decService)}</h3>
                    <p class="text-xs text-purple-300/70 font-medium">ID : <span class="text-gray-200 font-mono bg-purple-950/30 px-1.5 py-0.5 rounded border border-purple-950/40">${escapeHtml(decLogin)}</span></p>
                    <p class="text-xs text-gray-400 pt-1 flex items-center gap-2">
                        Clé : <span id="pass-display-${entry.id}" class="text-purple-900/80 font-bold tracking-widest text-sm">••••••••</span>
                    </p>
                </div>
                <div class="flex gap-2 w-full sm:w-auto justify-end border-t border-purple-950/40 sm:border-t-0 pt-3 sm:pt-0">
                    <button onclick="revealPassword('${entry.id}', 'pass-display-${entry.id}')" class="p-2.5 bg-[#140e2e] hover:bg-[#1f1747] border border-purple-900/40 rounded-xl text-purple-300 text-xs font-bold flex items-center gap-1.5 transition-colors">
                        👁️ Révéler
                    </button>
                    <button onclick="copyToClipboard('${entry.id}')" class="p-2.5 bg-[#140e2e] hover:bg-[#1f1747] border border-purple-900/40 rounded-xl text-purple-300 text-xs font-bold flex items-center gap-1.5 transition-colors">
                        📋 Copier
                    </button>
                    <button onclick="deleteEntry('${entry.id}')" class="p-2.5 bg-red-950/20 hover:bg-red-900/40 border border-red-950 text-red-400 text-xs font-bold rounded-xl transition-colors">
                        Effacer
                    </button>
                </div>
            `;
            listContainer.appendChild(div);
        } catch (e) {
            console.error("Échec du déchiffrement unitaire d'un bloc.");
        }
    }
}

// --- 6. LAZY LOADING MOT DE PASSE UNITAIRE STRICT & AUTO-CLEANUP ---
async function revealPassword(id, targetElementId) {
    const container = document.getElementById(targetElementId);
    const entries = getStorage();
    const entry = entries.find(item => item.id === id);

    if (!entry) return;
    try {
        const decryptedPassword = await decryptData(entry.encryptedPass, entry.iv);
        container.innerText = decryptedPassword;
        container.classList.remove('text-purple-900/80', 'tracking-widest', 'text-sm');
        container.classList.add('text-pink-400', 'font-mono', 'font-bold');

        setTimeout(() => {
            if (container.innerText === decryptedPassword) {
                container.innerText = "••••••••";
                container.classList.remove('text-pink-400', 'font-mono', 'font-bold');
                container.classList.add('text-purple-900/80', 'tracking-widest', 'text-sm');
            }
        }, RAM_CLEANUP_MS);
    } catch (err) {
        alert("Erreur lors du déchiffrement à la demande.");
    }
}

async function copyToClipboard(id) {
    const entries = getStorage();
    const entry = entries.find(item => item.id === id);
    if (!entry) return;

    try {
        const decryptedPassword = await decryptData(entry.encryptedPass, entry.iv);
        await navigator.clipboard.writeText(decryptedPassword);
        alert("Copié dans le presse-papier ! 📋");
    } catch (err) {
        alert("Impossible d'accéder au presse-papier.");
    }
}

// --- 7. GÉNÉRATEUR GAMIFIED (RANG / NIVEAU CYBER) ---
function generatePassphrase() {
    let words = [];
    const container = document.getElementById('gen-result-container');
    const resultDiv = document.getElementById('gen-result');

    const randomValues = new Uint32Array(4);
    window.crypto.getRandomValues(randomValues);

    for (let i = 0; i < randomValues.length; i++) {
        const index = randomValues[i] % wordlist.length;
        words.push(wordlist[index]);
    }

    const passphrase = words.join("-");
    resultDiv.innerText = passphrase;
    container.classList.remove('hidden');

    const analysis = zxcvbn(passphrase);
    const score = analysis.score;

    // Couleurs et paliers façon "Ranks de jeu vidéo"
    const colors = ["bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-purple-500", "bg-emerald-500"];
    const texts = ["Rank : Noob ❌", "Rank : Casual ⚠️", "Rank : Joueur 💻", "Rank : Hacker ⚡", "Rank : God Mode 👑 (NIST)"];

    const strengthBar = document.getElementById('pass-strength-bar');
    const strengthText = document.getElementById('pass-strength-text');
    
    strengthBar.className = `h-full rounded-full transition-all duration-300 ${colors[score]}`;
    strengthBar.style.width = `${(score + 1) * 20}%`;
    strengthText.innerText = texts[score];
    strengthText.className = `font-black text-xs uppercase tracking-wider ${score >= 3 ? 'text-emerald-400' : 'text-red-400'}`;
}

// --- 8. UTILS & SANITIZATION ---
function resetForm() {
    document.getElementById('entry-id').value = "";
    document.getElementById('entry-form').reset();
    document.getElementById('form-title').innerText = "Ajouter un compte";
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// --- 9. SUPPORT DE CODE PROGRESSIVE WEB APP ---
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        const swCode = `
            const CACHE_NAME = 'vault-cache-v2';
            const assets = ['./', './index.html', './css/style.css', './js/js.script'];
            self.addEventListener('install', e => {
                e.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(assets)));
            });
            self.addEventListener('fetch', e => {
                e.respondWith(caches.match(e.request).then(res => res || fetch(e.request)));
            });
        `;
        const blob = new Blob([swCode], { type: 'application/javascript' });
        const workerUrl = URL.createObjectURL(blob);
        navigator.serviceWorker.register(workerUrl).catch(err => console.debug("SW non enregistré", err));
    });
}