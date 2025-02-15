// ca.js
const USE_TAILSCALE = false; // Imposta a true per usare l'IP Tailscale, false per usare tutte le interfacce
const os = require('os');
function getTailscaleIP() {
    const interfaces = os.networkInterfaces();
    for (const name in interfaces) {
        if (name.toLowerCase().includes('tailscale')) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
    }
    return '0.0.0.0';
}
const HOST = USE_TAILSCALE ? getTailscaleIP() : '0.0.0.0';

const PORT = 3000;
const express = require('express');
const fs = require('fs');
const path = require('path');
const NodeRSA = require('node-rsa');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const readline = require('readline');

const app = express();
app.use(express.json());

// FILES per le chiavi dei servizi
const PRIVATE_KEYS_FILE = path.join(__dirname, 'private_keys.json');
const PUBLIC_KEYS_FILE = path.join(__dirname, 'public_keys.json');
// File per le STORAGE KEYS usate per cifrare i dati nel DB (generiamo es. 3 chiavi)
const STORAGE_KEYS_FILE = path.join(__dirname, 'storage_keys.json');

/**
 * Classe CA: gestisce registrazione, autenticazione e memorizzazione delle chiavi.
 * Memorizza anche il flag "loadData" (se il servizio può inviare dati).
 */
class CertificateAuthority {
    constructor() {
        // struttura: { serviceName: { serviceId, owner, description, ipAddress, tailscaleIp, privateKey, publicKey, loadData } }
        this.certificates = {};
        this._loadCertificates();
    }

    _loadCertificates() {
        // Carica le chiavi private (con il flag loadData)
        if (fs.existsSync(PRIVATE_KEYS_FILE)) {
            try {
                const data = JSON.parse(fs.readFileSync(PRIVATE_KEYS_FILE, 'utf8'));
                for (const [serviceName, { serviceId, key, loadData }] of Object.entries(data)) {
                    this.certificates[serviceName] = { serviceId, privateKey: key, loadData };
                }
            } catch (e) {
                console.error("Errore nel caricare file private_keys.json:", e);
            }
        }
        // Carica le chiavi pubbliche
        if (fs.existsSync(PUBLIC_KEYS_FILE)) {
            try {
                const data = JSON.parse(fs.readFileSync(PUBLIC_KEYS_FILE, 'utf8'));
                for (const [serviceName, { serviceId, key }] of Object.entries(data)) {
                    if (this.certificates[serviceName]) {
                        this.certificates[serviceName].publicKey = key;
                    }
                }
            } catch (e) {
                console.error("Errore nel caricare file public_keys.json:", e);
            }
        }
    }

    // Registra o aggiorna un servizio (memorizza anche il flag loadData)
    registerService(serviceInfo, privateKey, publicKey) {
        this.certificates[serviceInfo.serviceName] = {
            serviceId: serviceInfo.serviceId,
            owner: serviceInfo.owner,
            description: serviceInfo.description,
            ipAddress: serviceInfo.ipAddress,
            tailscaleIp: serviceInfo.tailscaleIp,
            privateKey,
            publicKey,
            loadData: serviceInfo.loadData || false
        };
        this._updateKeyFile(PRIVATE_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, privateKey, serviceInfo.loadData);
        this._updateKeyFile(PUBLIC_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, publicKey);
    }

    // Aggiorna il file JSON specificato
    _updateKeyFile(filePath, serviceName, serviceId, key, loadData) {
        let data = {};
        if (fs.existsSync(filePath)) {
            try {
                data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            } catch (e) {
                console.error("Errore nel parsing di", filePath, e);
            }
        }
        if (filePath === PRIVATE_KEYS_FILE) {
            data[serviceName] = { serviceId, key, loadData };
        } else {
            data[serviceName] = { serviceId, key };
        }
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

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

    authenticateService(serviceName, providedPrivateKey) {
        return (
            this.certificates[serviceName] &&
            this.certificates[serviceName].privateKey === providedPrivateKey
        );
    }
}

const ca = new CertificateAuthority();

/**
 * Gestione delle STORAGE KEYS per il DB.
 * Se il file non esiste, generiamo (es. 3 chiavi AES a 256 bit).
 */
let storageKeys = [];
function loadOrGenerateStorageKeys() {
    if (fs.existsSync(STORAGE_KEYS_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(STORAGE_KEYS_FILE, 'utf8'));
            storageKeys = data; // Array di oggetti { id, key }
            console.log("✅ Storage keys loaded.");
        } catch (err) {
            console.error("Errore nel caricamento di storage_keys.json:", err);
        }
    } else {
        storageKeys = [];
        for (let i = 1; i <= 3; i++) {
            const keyBuffer = crypto.randomBytes(32);
            storageKeys.push({ id: i, key: keyBuffer.toString('hex') });
        }
        fs.writeFileSync(STORAGE_KEYS_FILE, JSON.stringify(storageKeys, null, 2));
        console.log("✅ Nuove storage keys generate e salvate.");
    }
}
loadOrGenerateStorageKeys();

// Utility: scegli una storage key a caso
function chooseStorageKey() {
    if (storageKeys.length === 0) throw new Error("Nessuna storage key disponibile.");
    const index = Math.floor(Math.random() * storageKeys.length);
    return storageKeys[index];
}

// Interfaccia readline per approvazioni manuali
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
        console.log(`- Carica dati sul DB: ${serviceInfo.loadData ? "SI" : "NO"}`);
        rl.question('👉 Vuoi approvare la connessione? (si/no): ', (answer) => {
            resolve(answer.toLowerCase().trim().charAt(0) === 's');
        });
    });
}

// Endpoint di registrazione/autenticazione
app.post('/connectionRequest', async (req, res) => {
    const serviceInfo = req.body;
    if (!serviceInfo.serviceName || !serviceInfo.serviceId) {
        return res.status(400).json({ error: "Il nome e l'ID del servizio sono obbligatori" });
    }
    if (serviceInfo.targetServiceId) {
        return res.status(400).json({ error: "Utilizzare l'endpoint /requestKey per richiedere dati di un target" });
    }
    if (!serviceInfo.privateKey) {
        const serviceIdAlreadyExists = Object.values(ca.certificates).some(s => s.serviceId === serviceInfo.serviceId);
        if (serviceIdAlreadyExists) {
            return res.status(400).json({ error: "Registrazione rifiutata: esiste già un servizio con questo serviceId. Usa un nuovo serviceId oppure autenticati." });
        }
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
            return res.status(400).json({ error: "Registrazione rifiutata dall'utente." });
        }
    } else {
        if (!ca.certificates[serviceInfo.serviceName]) {
            return res.status(404).json({ error: "Servizio non registrato" });
        }
        if (ca.certificates[serviceInfo.serviceName].privateKey !== serviceInfo.privateKey) {
            return res.status(401).json({ error: "Autenticazione fallita: chiave privata non valida." });
        }
        console.log(`ℹ️ Servizio ${serviceInfo.serviceName} autenticato correttamente.`);
        const { privateKey, publicKey } = ca.certificates[serviceInfo.serviceName];
        return res.json({ approved: true, keys: { privateKey, publicKey } });
    }
});

// Endpoint per la sottomissione dati (DataAcquisition)
app.post('/submitData', async (req, res) => {
    const { serviceId, privateKey, record } = req.body;
    if (!serviceId || !privateKey || !record || !record.collection || !record.encryptedData || !record.iv || !record.encryptedAESKey) {
        return res.status(400).json({ error: "Dati incompleti. Campi obbligatori: serviceId, privateKey, record { collection, encryptedData, iv, encryptedAESKey }" });
    }
    const service = Object.values(ca.certificates).find(s => s.serviceId === serviceId);
    if (!service) return res.status(404).json({ error: "Servizio non registrato" });
    if (service.privateKey !== privateKey) return res.status(401).json({ error: "Autenticazione fallita" });
    if (!service.loadData) {
        return res.status(403).json({ error: "Il servizio non è autorizzato a caricare dati sul DB" });
    }
    let aesKey;
    try {
        const rsa = new NodeRSA(service.privateKey);
        aesKey = rsa.decrypt(Buffer.from(record.encryptedAESKey, 'hex'));
    } catch (err) {
        return res.status(500).json({ error: "Errore nella decrittazione della chiave AES: " + err.message });
    }
    let plaintext;
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(record.iv, 'hex'));
        plaintext = decipher.update(Buffer.from(record.encryptedData, 'hex'), undefined, 'utf8');
        plaintext += decipher.final('utf8');
    } catch (err) {
        return res.status(500).json({ error: "Errore nella decrittazione dei dati: " + err.message });
    }
    let storageKeyObj = chooseStorageKey();
    let storageIV = crypto.randomBytes(16);
    let storageEncryptedData;
    try {
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(storageKeyObj.key, 'hex'), storageIV);
        storageEncryptedData = cipher.update(plaintext, 'utf8', 'hex');
        storageEncryptedData += cipher.final('hex');
    } catch (err) {
        return res.status(500).json({ error: "Errore nella cifratura per il DB: " + err.message });
    }
    try {
        const mongoUrl = 'mongodb://localhost:27017/';
        const dbName = 'sensor_data';
        const client = new MongoClient(mongoUrl);
        await client.connect();
        const db = client.db(dbName);
        const collection = db.collection(record.collection);
        await collection.insertOne({
            serviceId,
            encryptedData: storageEncryptedData,
            iv: storageIV.toString('hex'),
            dbKeyId: storageKeyObj.id,
            timestamp: new Date()
        });
        await client.close();
        console.log(`✅ Dati inseriti nella collezione ${record.collection} per il servizio ${serviceId}`);
        return res.json({ success: true, message: "Dati elaborati e memorizzati nel DB" });
    } catch (err) {
        return res.status(500).json({ error: "Errore durante l'inserimento nel DB: " + err.message });
    }
});

// Endpoint per la richiesta dati (DataDecryption)
app.post('/requestKey', async (req, res) => {
    const { requesterServiceId, requesterPrivateKey, targetServiceId } = req.body;
    if (!requesterServiceId || !requesterPrivateKey || !targetServiceId) {
        return res.status(400).json({ error: "Richiesta incompleta. Campi richiesti: requesterServiceId, requesterPrivateKey, targetServiceId" });
    }
    const requester = Object.values(ca.certificates).find(s => s.serviceId === requesterServiceId);
    if (!requester) return res.status(404).json({ error: "Servizio richiedente non registrato" });
    if (requester.privateKey !== requesterPrivateKey) return res.status(401).json({ error: "Autenticazione fallita per il richiedente" });
    const target = Object.values(ca.certificates).find(s => s.serviceId === targetServiceId);
    if (!target) return res.status(404).json({ error: "Target non registrato" });
    console.log(`ℹ️ Richiesta dati per il target ${targetServiceId} da ${requesterServiceId}`);

    try {
        const mongoUrl = 'mongodb://localhost:27017/';
        const dbName = 'sensor_data';
        const client = new MongoClient(mongoUrl);
        await client.connect();
        const db = client.db(dbName);
        const collectionsToCheck = ['co2_readings', 'temperature_readings'];
        let results = [];
        for (const collectionName of collectionsToCheck) {
            const collection = db.collection(collectionName);
            const records = await collection.find({ serviceId: target.serviceId }).toArray();
            for (const record of records) {
                try {
                    const storageKeyObj = storageKeys.find(k => k.id === record.dbKeyId);
                    if (!storageKeyObj) throw new Error("Storage key non trovata per dbKeyId " + record.dbKeyId);
                    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(storageKeyObj.key, 'hex'), Buffer.from(record.iv, 'hex'));
                    let decrypted = decipher.update(Buffer.from(record.encryptedData, 'hex'), undefined, 'utf8');
                    decrypted += decipher.final('utf8');
                    // Ri-encripta i dati con la chiave pubblica del richiedente:
                    const rsa = new NodeRSA(requester.publicKey);
                    const encryptedForRequester = rsa.encrypt(decrypted, 'base64');
                    results.push({
                        collection: collectionName,
                        recordId: record._id,
                        data: encryptedForRequester
                    });
                } catch (err) {
                    console.error("❌ Errore nell'elaborazione del record", record._id, err.message);
                }
            }
        }
        await client.close();
        if (results.length === 0) {
            return res.json({ message: "Nessun record da decriptare per il target specificato." });
        }
        return res.json({ data: results });
    } catch (err) {
        console.error("❌ Errore nell'elaborazione dati:", err.message);
        return res.status(500).json({ error: "Errore nell'elaborazione dati: " + err.message });
    }
});

// Endpoint per ottenere le chiavi (solo per test, non in produzione)
app.get('/publicKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    if (!ca.certificates[serviceName]) return res.status(404).send("Servizio non registrato");
    res.send(ca.certificates[serviceName].publicKey);
});
app.get('/privateKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    if (!ca.certificates[serviceName]) return res.status(404).send("Servizio non registrato");
    const key = ca.loadKey(serviceName, 'private');
    if (!key) return res.status(404).send("Chiave privata non trovata");
    res.send(key);
});

app.listen(PORT, HOST, () => {
    console.log(`Certificate Authority in ascolto su http://${HOST}:${PORT}`);
});
