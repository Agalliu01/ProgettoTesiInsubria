// dataDecryption.js
const axios = require('axios');
const fs = require('fs').promises;
const os = require('os');
const NodeRSA = require('node-rsa');
const path = require('path');

const USE_TAILSCALE = false; // Imposta a true per usare l'IP Tailscale
function getTailscaleIP(ipInfo) {
    for (const iface in ipInfo) {
        if (iface.toLowerCase().includes('tailscale')) {
            for (const addr of ipInfo[iface]) {
                if (addr.family === 'IPv4' && !addr.internal) {
                    return addr.address;
                }
            }
        }
    }
    return 'localhost';
}
async function getBaseURL() {
    const ipInfo = os.networkInterfaces();
    return USE_TAILSCALE ? `http://${getTailscaleIP(ipInfo)}:3000` : 'http://localhost:3000';
}

const KEYS_FILE = './my_keys_decryption.json'; // File locale per le chiavi di DataDecryption
const SERVICE_NAME = 'DataDecryption';
const SERVICE_ID = 'DataDecryption-001';

/**
 * Richiede la connessione (registrazione o autenticazione) al CA.
 */
async function requestConnection() {
    let localKeys = null;
    try {
        const data = await fs.readFile(KEYS_FILE, 'utf8');
        localKeys = JSON.parse(data);
        console.log("✅ Chiavi locali trovate:", localKeys);
    } catch (err) {
        console.log("⚠️ Nessun file di chiavi trovato, richiedo connessione al CA...");
    }

    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE ? `http://${getTailscaleIP(ipInfo)}:3000` : 'http://localhost:3000';
    const url = `${baseURL}/connectionRequest`;
    const requestBody = {
        serviceName: SERVICE_NAME,
        serviceId: SERVICE_ID,
        description: 'Servizio per lettura/decrittazione dati',
        owner: 'Company123',
        ipAddress: ipInfo,
        loadData: false
    };
    if (localKeys && localKeys.privateKey) {
        requestBody.privateKey = localKeys.privateKey;
    }

    try {
        console.log("🔗 Inviando richiesta di connessione al CA...");
        const response = await axios.post(url, requestBody, { timeout: 10000 });
        if (response.data.approved) {
            console.log("✅ Connessione approvata dal CA");
            if (response.data.keys) {
                localKeys = response.data.keys;
                await fs.writeFile(KEYS_FILE, JSON.stringify(localKeys, null, 2));
                console.log("🔑 Chiavi salvate in", KEYS_FILE);
            }
            return localKeys;
        } else {
            console.error("❌ Connessione rifiutata:", response.data.error);
            process.exit(1);
        }
    } catch (err) {
        console.error("❌ Errore nella richiesta di connessione:", err.message);
        process.exit(1);
    }
}

/**
 * Richiede i dati relativi a un target (ad es. DataAcquisition) tramite il CA.
 * Dopo che il CA ha decriptato i dati dal DB, li ri-encripta usando la chiave pubblica del richiedente,
 * così che solo il richiedente (che possiede la sua chiave privata) possa decriptarli.
 */
async function requestDecryptedData(targetServiceId) {
    const localKeys = await requestConnection();
    const baseURL = await getBaseURL();
    const url = `${baseURL}/requestKey`;
    const payload = {
        requesterServiceId: SERVICE_ID,
        requesterPrivateKey: localKeys.privateKey,
        targetServiceId // Es. "DataAcquisition-001"
    };
    try {
        const response = await axios.post(url, payload, { timeout: 15000 });
        if (response.data.data) {
            return response.data.data; // Array di record ri‑cifrati per il richiedente
        } else if(response.data.message) {
            console.log(response.data.message);
            return [];
        } else {
            console.error("❌ Nessun dato ricevuto:", response.data.error);
            return [];
        }
    } catch (err) {
        console.error("❌ Errore nella richiesta dei dati:", err.message);
        throw err;
    }
}

/**
 * Decripta una stringa cifrata con RSA, usando la chiave privata.
 */
function decryptRSAEncryptedData(encryptedData, privateKeyStr) {
    try {
        const rsa = new NodeRSA(privateKeyStr);
        return rsa.decrypt(encryptedData, 'utf8');
    } catch (err) {
        console.error("❌ Errore nella decriptazione RSA:", err.message);
        throw err;
    }
}

/**
 * Recupera e processa i dati ricevuti dal CA.
 * Se non vengono trovati record, stampa un messaggio appropriato.
 */
async function processDecryptedData() {
    const targetServiceId = 'DataAcquisition-001';
    try {
        const records = await requestDecryptedData(targetServiceId);
        if (records.length === 0) {
            console.log("✅ Nessun record da decriptare per il target specificato.");
            return;
        }
        console.log(`✅ Ricevuti ${records.length} record per il target ${targetServiceId}`);
        const localKeys = JSON.parse(await fs.readFile(KEYS_FILE, 'utf8'));
        records.forEach(record => {
            try {
                const decrypted = decryptRSAEncryptedData(record.data, localKeys.privateKey);
                console.log(`Record da ${record.collection} (ID: ${record.recordId}):`, decrypted);
            } catch (err) {
                console.error(`❌ Errore decriptando il record ${record.recordId}:`, err.message);
            }
        });
    } catch (err) {
        console.error("❌ Errore nel processo di decriptazione:", err.message);
    }
}

processDecryptedData();
