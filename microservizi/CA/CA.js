// ca.js
const USE_LOCALHOST = false; // Imposta a false per ascoltare su tutte le interfacce
const HOST = USE_LOCALHOST ? 'localhost' : '0.0.0.0';
const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const NodeRSA = require('node-rsa');
const os = require('os');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

// Middleware per il parsing del JSON
app.use(express.json());

// Percorsi dei file per le chiavi
const PRIVATE_KEYS_FILE = path.join(__dirname, 'private_keys.json');
const PUBLIC_KEYS_FILE = path.join(__dirname, 'public_keys.json');

/**
 * Classe per gestire i certificati e le informazioni dei servizi.
 * Include la gestione dei token per l’autenticazione challenge–response.
 */
class CertificateAuthority {
    constructor() {
        // Certificati: chiave = serviceName, valore = { serviceId, owner, description, ipAddress, tailscaleIp, privateKey, publicKey }
        this.certificates = {};
        // Oggetto per memorizzare i token di challenge in attesa di verifica: { serviceName: token }
        this.pendingTokens = {};
        this._loadCertificates();
    }

    _loadCertificates() {
        // Carica le chiavi private
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
        // Carica le chiavi pubbliche
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

    // Registra o aggiorna un servizio
    registerService(serviceInfo, privateKey, publicKey) {
        this.certificates[serviceInfo.serviceName] = {
            serviceId: serviceInfo.serviceId,
            owner: serviceInfo.owner,
            description: serviceInfo.description,
            ipAddress: serviceInfo.ipAddress,
            tailscaleIp: serviceInfo.tailscaleIp,
            privateKey,
            publicKey
        };
        this._updateKeyFile(PRIVATE_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, privateKey);
        this._updateKeyFile(PUBLIC_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, publicKey);
    }

    // Aggiorna il file JSON specificato
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

    // Autentica un servizio confrontando la chiave privata (metodo legacy usato in /connectionRequest)
    authenticateService(serviceName, providedPrivateKey) {
        return (
            this.certificates[serviceName] &&
            this.certificates[serviceName].privateKey === providedPrivateKey
        );
    }
}

const ca = new CertificateAuthority();

// Interfaccia readline per il prompt di approvazione
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
 * Endpoint per la registrazione/autenticazione del servizio.
 * Se non viene fornita la chiave privata si considera una nuova registrazione.
 */
app.post('/connectionRequest', async (req, res) => {
    const serviceInfo = req.body;
    if (!serviceInfo.serviceName || !serviceInfo.serviceId) {
        return res.status(400).json({ error: "Il nome e l'ID del servizio sono obbligatori" });
    }
    if (serviceInfo.targetServiceId) {
        return res.status(400).json({ error: "Utilizzare l'endpoint /requestKey per richiedere la chiave privata di un target" });
    }

    // Nuova registrazione: il client non invia la chiave privata
    if (!serviceInfo.privateKey) {
        // Verifica se il serviceId è già presente
        const serviceIdAlreadyExists = Object.values(ca.certificates).some(
            s => s.serviceId === serviceInfo.serviceId
        );
        if (serviceIdAlreadyExists) {
            return res.status(400).json({ error: "Registrazione rifiutata: esiste già un servizio con questo serviceId. Utilizzare il metodo di autenticazione." });
        }
        // Mostra il prompt per l'approvazione
        const approved = await askApproval(serviceInfo);
        if (approved) {
            const key = new NodeRSA({ b: 2048 });
            const privateKey = key.exportKey('private');
            const publicKey = key.exportKey('public');
            ca.registerService(serviceInfo, privateKey, publicKey);
            console.log(`✅ Servizio ${serviceInfo.serviceName} registrato con nuove chiavi.`);
            return res.json({ approved: true, keys: { privateKey, publicKey } });
        } else {
            console.log(`❌ Richiesta di connessione da ${serviceInfo.serviceName} rifiutata dall'utente.`);
            return res.status(400).json({ error: "Registrazione rifiutata dall'utente." });
        }
    } else {
        // Richiesta di autenticazione legacy: il client invia la chiave privata
        if (!ca.certificates[serviceInfo.serviceName]) {
            return res.status(404).json({ error: "Servizio non registrato" });
        }
        if (ca.certificates[serviceInfo.serviceName].privateKey !== serviceInfo.privateKey) {
            return res.status(401).json({ error: "Autenticazione fallita: chiave privata non valida." });
        }
        console.log(`ℹ️ Il servizio ${serviceInfo.serviceName} è stato autenticato correttamente (metodo legacy).`);
        const { privateKey, publicKey } = ca.certificates[serviceInfo.serviceName];
        return res.json({ approved: true, keys: { privateKey, publicKey } });
    }
});

/**
 * Endpoint per generare un token di challenge per il client.
 * Il client dovrà firmare questo token con la sua chiave privata.
 */
app.post('/generateToken', (req, res) => {
    const { serviceName } = req.body;
    if (!serviceName || !ca.certificates[serviceName]) {
        return res.status(404).json({ error: "Servizio non registrato" });
    }
    // Genera un token casuale
    const token = crypto.randomBytes(32).toString('hex');
    // Salva il token associato al serviceName
    ca.pendingTokens[serviceName] = token;
    console.log(`🔐 Token generato per ${serviceName}: ${token}`);
    res.json({ token });
});

/**
 * Endpoint per verificare la firma inviata dal client.
 * Viene usata la chiave pubblica registrata per verificare la firma del token.
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
    // Recupera la chiave pubblica del servizio
    const publicKeyString = ca.certificates[serviceName].publicKey;
    if (!publicKeyString) {
        return res.status(404).json({ error: "Chiave pubblica non trovata per il servizio" });
    }
    const key = new NodeRSA(publicKeyString);
    // Verifica la firma: il client ha firmato il token con la propria chiave privata
    const isValid = key.verify(token, signature, 'utf8', 'base64');
    if (isValid) {
        // Rimuove il token per evitare replay
        delete ca.pendingTokens[serviceName];
        console.log(`✅ Autenticazione challenge–response riuscita per ${serviceName}`);
        return res.json({ authenticated: true });
    } else {
        console.error(`❌ Autenticazione challenge–response fallita per ${serviceName}`);
        return res.status(401).json({ error: "Firma non valida" });
    }
});

/**
 * Endpoint per richiedere la chiave privata di un target.
 * Il richiedente deve inviare: requesterServiceId, requesterPrivateKey e targetServiceId.
 * Se autenticato, viene restituita la chiave privata del target.
 */
app.post('/requestKey', async (req, res) => {
    const { requesterServiceId, requesterPrivateKey, targetServiceId } = req.body;
    if (!requesterServiceId || !requesterPrivateKey || !targetServiceId) {
        return res.status(400).json({ error: "Richiesta incompleta. Campi richiesti: requesterServiceId, requesterPrivateKey, targetServiceId" });
    }
    // Cerca il servizio richiedente tramite serviceId
    const requester = Object.values(ca.certificates).find(s => s.serviceId === requesterServiceId);
    if (!requester) {
        return res.status(404).json({ error: "Servizio richiedente non registrato" });
    }
    // Verifica la validità della chiave privata del richiedente (metodo legacy)
    if (requester.privateKey !== requesterPrivateKey) {
        return res.status(401).json({ error: "Autenticazione fallita per il richiedente" });
    }
    // Cerca il target tramite serviceId
    const target = Object.values(ca.certificates).find(s => s.serviceId === targetServiceId);
    if (!target) {
        return res.status(404).json({ error: "Target non registrato" });
    }
    console.log(`ℹ️ Richiesta di chiave privata per il target ${targetServiceId} da parte del richiedente ${requesterServiceId} autenticato.`);
    // **Attenzione:** Esporre chiavi private è estremamente rischioso in produzione
    return res.json({ privateKey: target.privateKey });
});

// Endpoint opzionali per ottenere le chiavi (solo per scopi interni, non in produzione)
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

app.listen(PORT, HOST, () => {
    console.log(`Certificate Authority in ascolto su http://${HOST}:${PORT}`);
});
