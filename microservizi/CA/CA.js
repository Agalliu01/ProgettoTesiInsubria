// CA.js
const USE_LOCALHOST = false; // Imposta a false per ascoltare su tutte le interfacce
const HOST = USE_LOCALHOST ? 'localhost' : '0.0.0.0';
const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const https = require('https');
const { execSync } = require('child_process'); // Per eseguire comandi OpenSSL
const app = express();
const PORT = 3000;

// --- Gestione automatica dei certificati SSL/TLS --- //
const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir);
}

const keyPath = path.join(certsDir, 'server.key');
const certPath = path.join(certsDir, 'server.cert');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    console.log("Certificati SSL/TLS non trovati, genero certificato self-signed ECC...");
    try {
        // Genera la chiave privata ECC usando la curva prime256v1
        execSync(`openssl ecparam -name prime256v1 -genkey -noout -out "${keyPath}"`);
        // Genera il certificato self-signed usando la chiave appena creata; imposta il CN a "localhost"
        execSync(`openssl req -new -x509 -key "${keyPath}" -out "${certPath}" -days 365 -subj "/CN=localhost"`);
        console.log("Certificati ECC generati in:", certsDir);
    } catch (err) {
        console.error("Errore nella generazione dei certificati ECC tramite OpenSSL:", err);
        process.exit(1);
    }
}

const sslOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
};
// --- Fine gestione certificati --- //

// Middleware per il parsing del JSON
app.use(express.json());

// Percorsi dei file per le chiavi ECC (salvate in formato esadecimale)
const PRIVATE_KEYS_FILE = path.join(__dirname, 'private_keys.json');
const PUBLIC_KEYS_FILE = path.join(__dirname, 'public_keys.json');

/**
 * Classe per gestire i certificati e le informazioni dei servizi.
 * Include la gestione dei token per l’autenticazione challenge–response.
 */
class CertificateAuthority {
    constructor() {
        // certificates: { serviceName: { serviceId, owner, description, ipAddress, tailscaleIp, privateKey, publicKey } }
        this.certificates = {};
        // pendingTokens: { serviceName: token }
        this.pendingTokens = {};
        this._loadCertificates();
    }

    _loadCertificates() {
        if (fs.existsSync(PRIVATE_KEYS_FILE)) {
            try {
                const privateData = JSON.parse(fs.readFileSync(PRIVATE_KEYS_FILE, 'utf8'));
                for (const [serviceName, { serviceId, key }] of Object.entries(privateData)) {
                    this.certificates[serviceName] = { serviceId, privateKey: key };
                }
            } catch (e) {
                console.error("Errore nel caricare il file delle chiavi private:", e);
            }
        }
        if (fs.existsSync(PUBLIC_KEYS_FILE)) {
            try {
                const publicData = JSON.parse(fs.readFileSync(PUBLIC_KEYS_FILE, 'utf8'));
                for (const [serviceName, { serviceId, key }] of Object.entries(publicData)) {
                    if (this.certificates[serviceName]) {
                        this.certificates[serviceName].publicKey = key;
                    }
                }
            } catch (e) {
                console.error("Errore nel caricare il file delle chiavi pubbliche:", e);
            }
        }
    }

    _updateKeyFile(filePath, serviceName, serviceId, key) {
        let data = {};
        if (fs.existsSync(filePath)) {
            try {
                data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            } catch (e) {
                console.error("Errore nel parsing di", filePath, e);
            }
        }
        data[serviceName] = { serviceId, key };
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

    // Registra/aggiorna un servizio usando ECC (generando coppia raw tramite ECDH)
    registerService(serviceInfo, privateKey, publicKey) {
        this.certificates[serviceInfo.serviceName] = {
            serviceId: serviceInfo.serviceId,
            owner: serviceInfo.owner,
            description: serviceInfo.description,
            ipAddress: serviceInfo.ipAddress,
            tailscaleIp: serviceInfo.tailscaleIp,
            privateKey, // raw in hex
            publicKey   // raw in hex
        };
        this._updateKeyFile(PRIVATE_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, privateKey);
        this._updateKeyFile(PUBLIC_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, publicKey);
    }

    // Ritorna la chiave (pubblica o privata) di un servizio
    loadKey(serviceName, type) {
        const filePath = type === 'private' ? PRIVATE_KEYS_FILE : PUBLIC_KEYS_FILE;
        if (fs.existsSync(filePath)) {
            try {
                const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                return data[serviceName] ? data[serviceName].key : null;
            } catch (e) {
                console.error("Errore nel parsing di", filePath, e);
                return null;
            }
        }
        return null;
    }

    // Autentica (metodo legacy): confronta la chiave privata
    authenticateService(serviceName, providedPrivateKey) {
        return (
            this.certificates[serviceName] &&
            this.certificates[serviceName].privateKey === providedPrivateKey
        );
    }
}

const ca = new CertificateAuthority();

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function askApproval(serviceInfo) {
    return new Promise((resolve) => {
        console.log("\nRichiesta di connessione ricevuta:");
        console.log(`- Nome servizio: ${serviceInfo.serviceName}`);
        console.log(`- ID servizio: ${serviceInfo.serviceId}`);
        console.log(`- Descrizione: ${serviceInfo.description}`);
        console.log(`- Proprietario: ${serviceInfo.owner}`);
        console.log(`- IP locale: ${serviceInfo.ipAddress}`);
        console.log(`- IP Tailscale: ${serviceInfo.tailscaleIp || 'non specificato'}`);
        rl.question('👉 Vuoi approvare la connessione? (si/no): ', (answer) => {
            resolve(answer.toLowerCase().trim().charAt(0) === 's');
        });
    });
}

/**
 * Endpoint per la registrazione/autenticazione.
 * Se non viene fornita la chiave privata, si considera una nuova registrazione.
 * Qui la coppia ECC viene generata tramite ECDH (raw in hex).
 */
app.post('/connectionRequest', async (req, res) => {
    const serviceInfo = req.body;

    // Verifica che siano forniti il nome e l'ID del servizio
    if (!serviceInfo.serviceName || !serviceInfo.serviceId) {
        return res.status(400).json({ error: "Il nome e l'ID del servizio sono obbligatori" });
    }

    if (serviceInfo.targetServiceId) {
        return res.status(400).json({ error: "Utilizzare l'endpoint /requestKey per richiedere la chiave privata di un target" });
    }
    const approved = await askApproval(serviceInfo);
    if(approved){

        // Verifica se il servizio è già registrato
        if (ca.certificates[serviceInfo.serviceName]) {
            console.log(`ℹ️ Il servizio ${serviceInfo.serviceName} è già registrato.`);
            const { privateKey, publicKey } = ca.certificates[serviceInfo.serviceName];
            return res.json({ approved: true,keys: { privateKey, publicKey } , message: "Servizio già registrato, autenticazione avvenuta." });
        }
        else{
            // Genera coppia ECC tramite ECDH (raw in hex)
            const ecdh = crypto.createECDH('prime256v1');
            ecdh.generateKeys();
            const privateKey = ecdh.getPrivateKey('hex');
            const publicKey = ecdh.getPublicKey('hex');
            ca.registerService(serviceInfo, privateKey, publicKey);
            console.log(`✅ Servizio ${serviceInfo.serviceName} registrato con nuove chiavi ECC.`);
            return res.json({ approved: true, keys: { privateKey, publicKey } });
        }
    }
    else {
        console.log(`❌ Richiesta di connessione da ${serviceInfo.serviceName} rifiutata dall'utente.`);
        return res.status(400).json({ error: "Registrazione rifiutata dall'utente." });
    }



});

/**
 * Endpoint per generare un token di challenge.
 * Il client dovrà calcolare un HMAC del token usando la propria chiave privata (raw).
 */
app.post('/generateToken', (req, res) => {
    const { serviceName } = req.body;
    if (!serviceName || !ca.certificates[serviceName]) {
        return res.status(404).json({ error: "Servizio non registrato" });
    }
    const token = crypto.randomBytes(32).toString('hex');
    ca.pendingTokens[serviceName] = token;
    console.log(`🔐 Token generato per ${serviceName}: ${token}`);
    res.json({ token });
});

/**
 * Endpoint per verificare l'HMAC inviato dal client.
 * Il server calcola l'HMAC (sha256) sul token usando la chiave privata (raw) e lo confronta.
 */
app.post('/authenticate', (req, res) => {
    const { serviceName, signature } = req.body;
    if (!serviceName || !signature) {
        return res.status(400).json({ error: "Richiesta incompleta: serviceName e signature sono obbligatori" });
    }
    const token = ca.pendingTokens[serviceName];
    if (!token) {
        return res.status(400).json({ error: "Token non trovato o scaduto per il servizio" });
    }
    const expectedSignature = crypto.createHmac('sha256', Buffer.from(ca.certificates[serviceName].privateKey, 'hex'))
        .update(token)
        .digest('hex');
    if (expectedSignature === signature) {
        delete ca.pendingTokens[serviceName];
        console.log(`✅ Autenticazione challenge–response riuscita per ${serviceName}`);
        return res.json({ authenticated: true });
    } else {
        console.error(`❌ Autenticazione challenge–response fallita per ${serviceName}`);
        return res.status(401).json({ error: "HMAC non valido" });
    }
});

/**
 * Endpoint per richiedere la chiave privata di un target.
 * (Attenzione: esporre chiavi private è estremamente rischioso in produzione.)
 */
app.post('/requestKey', async (req, res) => {
    const { requesterServiceId, requesterPrivateKey, targetServiceId } = req.body;
    if (!requesterServiceId || !requesterPrivateKey || !targetServiceId) {
        return res.status(400).json({ error: "Richiesta incompleta. Campi richiesti: requesterServiceId, requesterPrivateKey, targetServiceId" });
    }
    const requester = Object.values(ca.certificates).find(s => s.serviceId === requesterServiceId);
    if (!requester) {
        return res.status(404).json({ error: "Servizio richiedente non registrato" });
    }

    const target = Object.values(ca.certificates).find(s => s.serviceId === targetServiceId);
    if (!target) {
        return res.status(404).json({ error: "Target non registrato" });
    }
    console.log(`ℹ️ Richiesta di chiave privata per il target ${targetServiceId} da parte del richiedente ${requesterServiceId} autenticato.`);
    return res.json({ privateKey: target.privateKey });
});

// Endpoint per ottenere le chiavi (solo per scopi interni, non in produzione)
app.get('/publicKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    if (!ca.certificates[serviceName]) {
        return res.status(404).send("Servizio non registrato");
    }
    res.send(ca.certificates[serviceName].publicKey);
});

app.get('/privateKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    if (!ca.certificates[serviceName]) {
        return res.status(404).send("Servizio non registrato");
    }
    const privateKey = ca.loadKey(serviceName, 'private');
    if (!privateKey) {
        return res.status(404).send("Chiave privata non trovata");
    }
    res.send(privateKey);
});

// Avvio del server HTTPS
https.createServer(sslOptions, app).listen(PORT, HOST, () => {
    console.log(`Certificate Authority in ascolto su https://${HOST}:${PORT}`);
});
