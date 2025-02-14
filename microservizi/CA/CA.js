// ca.js
const USE_LOCALHOST = false; // Imposta a false per ascoltare su tutte le interfacce
const HOST = USE_LOCALHOST ? 'localhost' : '0.0.0.0';
const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const NodeRSA = require('node-rsa');
const os = require('os');
const app = express();
const PORT = 3000;

// Middleware per il parsing del JSON
app.use(express.json());

// Percorsi dei file per le chiavi
const PRIVATE_KEYS_FILE = path.join(__dirname, 'private_keys.json');
const PUBLIC_KEYS_FILE = path.join(__dirname, 'public_keys.json');

// Classe per gestire certificati e informazioni dei servizi
class CertificateAuthority {
    constructor() {
        this.certificates = {}; // Chiave: serviceName, valore: { serviceId, owner, description, ipAddress, tailscaleIp, privateKey, publicKey }
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

    // Autentica un servizio confrontando la chiave privata
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
 * Se viene fornito un target nella richiesta verrà rifiutata (vedi endpoint /requestKey).
 */
app.post('/connectionRequest', async (req, res) => {
    const serviceInfo = req.body;
    if (!serviceInfo.serviceName || !serviceInfo.serviceId) {
        return res.status(400).json({ error: "Il nome e l'ID del servizio sono obbligatori" });
    }
    // Se nella richiesta è presente un target, indirizza l'uso all'endpoint dedicato
    if (serviceInfo.targetServiceId) {
        return res.status(400).json({ error: "Utilizzare l'endpoint /requestKey per richiedere la chiave privata di un target" });
    }

    // Se il servizio è già registrato
    if (ca.certificates[serviceInfo.serviceName]) {
        // Se non viene fornita la chiave privata, chiedi approvazione
        if (!serviceInfo.privateKey) {
            console.log(`ℹ️ Richiesta di nuova autenticazione per il servizio ${serviceInfo.serviceName} (nessuna chiave privata fornita).`);
            const approved = await askApproval(serviceInfo);
            if (approved) {
                const key = new NodeRSA({ b: 2048 });
                const privateKey = key.exportKey('private');
                const publicKey = key.exportKey('public');
                ca.registerService(serviceInfo, privateKey, publicKey);
                console.log(`✅ Servizio ${serviceInfo.serviceName} registrato con nuove chiavi.`);
                return res.json({ approved: true, keys: { privateKey, publicKey } });
            } else {
                console.log(`❌ Richiesta di connessione da ${serviceInfo.serviceName} rifiutata.`);
                return res.json({ approved: false });
            }
        } else {
            // Se viene fornita la chiave privata, verifica che corrisponda
            if (ca.certificates[serviceInfo.serviceName].privateKey !== serviceInfo.privateKey) {
                return res.status(401).json({ error: "Autenticazione fallita: chiave privata non valida. Richiedere una nuova autenticazione con un nuovo id." });
            }
            console.log(`ℹ️ Il servizio ${serviceInfo.serviceName} è già registrato ed è stato autenticato correttamente.`);
            const { privateKey, publicKey } = ca.certificates[serviceInfo.serviceName];
            return res.json({ approved: true, keys: { privateKey, publicKey } });
        }
    } else {
        // Se il servizio non è registrato, chiedi approvazione e registralo
        const approved = await askApproval(serviceInfo);
        if (approved) {
            const key = new NodeRSA({ b: 2048 });
            const privateKey = key.exportKey('private');
            const publicKey = key.exportKey('public');
            ca.registerService(serviceInfo, privateKey, publicKey);
            console.log(`✅ Servizio ${serviceInfo.serviceName} registrato con nuove chiavi.`);
            return res.json({ approved: true, keys: { privateKey, publicKey } });
        } else {
            console.log(`❌ Richiesta di connessione da ${serviceInfo.serviceName} rifiutata.`);
            return res.json({ approved: false });
        }
    }
});

/**
 * Endpoint per richiedere la chiave privata di un target.
 * Il richiedente deve inviare: requesterServiceId, requesterPrivateKey e targetServiceId.
 * Se il richiedente è autenticato, viene restituita la chiave privata del target.
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
    // Verifica la validità della chiave privata del richiedente
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
