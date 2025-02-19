const USE_TAILSCALE = true; // true per usare IP Tailscale, false per localhost
const axios = require('axios');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const path = require('path');

const KEYS_FILE = './my_keys_decryption.json';
//const mongoUrl = 'mongodb://localhost:27017/';
const mongoUrl = 'mongodb://admin:password@100.116.74.57:27017/admin?tls=true&tlsCertificateKeyFile=C:\\Users\\capit\\Documents\\ProgettoTesiInsubria\\microservizi\\Decryption\\mongodb.pem&tlsCAFile=C:\\Users\\capit\\Documents\\ProgettoTesiInsubria\\microservizi\\Decryption\\mongodb.pem';
const dbName = 'sensor_data';
const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';
let localKeys = null;
let keyCache = {}; // Cache per le chiavi private dei target

// -------------------- MODIFICA AGGIUNTIVA --------------------
// Funzione per ottenere il certificato pubblico del server e creare un https.Agent
async function getHttpsAgent() {
    const certFile = path.join(__dirname, 'server.cert');
    let caCert;
    try {
        caCert = await fs.readFile(certFile, 'utf8');
    } catch (err) {
        const ipInfo = os.networkInterfaces();
        const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
            ? `https://${getTailscaleIP(ipInfo)}:3000`
            : 'https://localhost:3000';
        const url = `${baseURL}/serverCert`;
        const tempAgent = new (require('https').Agent)({ rejectUnauthorized: false });
        const response = await axios.get(url, { httpsAgent: tempAgent });
        caCert = response.data;
        await fs.writeFile(certFile, caCert);
    }
    return new (require('https').Agent)({ ca: caCert });
}
// -------------------- FINE MODIFICA --------------------

// Funzione per ottenere l'IP Tailscale o localhost
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
    return null;
}

/**
 * Funzione che decripta la chiave AES cifrata con ECIES.
 * @param {string} encryptedAESKey - JSON string contenente { ephemeralPublicKey, iv, ciphertext } (tutti in hex)
 * @param {string} recipientPrivateKey - chiave privata (raw hex) del destinatario
 * @returns {Buffer} - Buffer della chiave AES decriptata
 */
function decryptAESKeyWithECC(encryptedAESKey, recipientPrivateKey) {
    const payload = JSON.parse(encryptedAESKey);
    const { ephemeralPublicKey, iv, ciphertext } = payload;
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(recipientPrivateKey, 'hex');
    const sharedSecret = ecdh.computeSecret(ephemeralPublicKey, 'hex'); // Buffer
    const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest(); // 32 bytes
    const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(Buffer.from(ciphertext, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted; // Buffer contenente la chiave AES
}

/**
 * Funzione per autenticare il client tramite challenge–response usando HMAC.
 */
async function authenticateClient() {
    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
        ? `https://${getTailscaleIP(ipInfo)}:3000`
        : 'https://localhost:3000';

    try {
        const httpsAgent = await getHttpsAgent();
        const tokenResponse = await axios.post(`${baseURL}/generateToken`, {
            serviceName: 'DataDecryption'
        }, {
            timeout: 10000,
            httpsAgent
        });
        const token = tokenResponse.data.token;
        console.log(`🔑 Token ricevuto: ${token}`);

        const signature = crypto.createHmac('sha256', Buffer.from(localKeys.privateKey, 'hex'))
            .update(token)
            .digest('hex');
        console.log(`🖋 HMAC calcolato: ${signature}`);

        const authResponse = await axios.post(`${baseURL}/authenticate`, {
            serviceName: 'DataDecryption',
            signature
        }, {
            timeout: 10000,
            httpsAgent
        });

        if (authResponse.data.authenticated) {
            console.log("✅ Autenticazione completata con successo!");
            decryptData();
        } else {
            console.error("❌ Autenticazione non riuscita");
            process.exit(1);
        }
    } catch (err) {
        console.error("❌ Errore durante l'autenticazione:", err.message);
        process.exit(1);
    }
}

/**
 * Funzione per richiedere la chiave privata di un target.
 */
async function getTargetPrivateKey(targetServiceId) {
    if (keyCache[targetServiceId]) {
        return keyCache[targetServiceId];
    }
    try {
        console.log(`🔍 Richiesta chiave privata per il target ${targetServiceId} alla CA...`);
        const ipInfo = os.networkInterfaces();
        const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
            ? `https://${getTailscaleIP(ipInfo)}:3000`
            : 'https://localhost:3000';
        const url = `${baseURL}/requestKey`;
        const httpsAgent = await getHttpsAgent();
        const response = await axios.post(url, {
            requesterServiceId: 'DataDecryption-001',
            requesterPrivateKey: localKeys.privateKey,
            targetServiceId
        }, {
            timeout: 10000,
            httpsAgent
        });
        if (response.data && response.data.privateKey) {
            console.log(`✅ Chiave privata ricevuta per il target ${targetServiceId}.`);
            keyCache[targetServiceId] = response.data.privateKey;
            return response.data.privateKey;
        } else {
            throw new Error(`Chiave privata non ricevuta per ${targetServiceId}.`);
        }
    } catch (err) {
        console.error(`❌ Errore nel recupero della chiave per ${targetServiceId}:`, err.message);
        throw err;
    }
}

/**
 * Decripta i dati cifrati in MongoDB utilizzando la chiave AES decriptata.
 */
async function decryptData() {
    console.log("🔐 Avvio processo di decrittazione...");
    const { MongoClient } = require('mongodb');
    try {
        const client = new MongoClient(mongoUrl);
        await client.connect();
        console.log("✅ Connessione a MongoDB stabilita.");
        const db = client.db(dbName);
        const collectionC02 = db.collection(collectionNameCO2);
        const collectionTemp = db.collection(collectionNameTemperature);
        const recordsCO2 = await collectionC02.find().toArray();
        const recordTemp = await collectionTemp.find().toArray();

        if (!recordsCO2.length) {
            console.log("⚠️ Nessun dato trovato.");
            await client.close();
            return;
        }

        if (!recordTemp.length) {
            console.log("⚠️ Nessun dato trovato.");
            await client.close();
            return;
        }

        // Ciclo per recordsCO2
        for (const record of recordsCO2) {
            await decryptRecord(record);
        }

        // Ciclo per recordTemp
        for (const record of recordTemp) {
            await decryptRecord(record);
        }

        async function decryptRecord(record) {
            try {
                const targetServiceId = record.serviceId;
                const targetPrivateKey = await getTargetPrivateKey(targetServiceId);
                const aesKey = decryptAESKeyWithECC(record.encryptedAESKey, targetPrivateKey);
                const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(record.iv, 'hex'));
                let decrypted = decipher.update(Buffer.from(record.encryptedData, 'hex'), undefined, 'utf8');
                decrypted += decipher.final('utf8');
                console.log(`✅ Dati decriptati per ${targetServiceId}:`, decrypted);
            } catch (err) {
                console.error("❌ Errore nella decrittazione del record:", err.message);
            }
        }

        await client.close();
        console.log("✅ Connessione a MongoDB chiusa.");
    } catch (err) {
        console.error("❌ Errore nel processo di decrittazione:", err.message);
    }
}

/**
 * Funzione principale: richiede la connessione e poi si autentica.
 */
async function main() {
    try {
        const data = await fs.readFile(KEYS_FILE, 'utf8');
        localKeys = JSON.parse(data);
        console.log("✅ Chiavi locali trovate.", localKeys);
    } catch (err) {
        console.log("⚠️ Nessun file di chiavi trovato, attendo che la CA mi fornisca le chiavi...");
    }
    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
        ? `https://${getTailscaleIP(ipInfo)}:3000`
        : 'https://localhost:3000';
    const url = `${baseURL}/connectionRequest`;
    const requestBody = {
        serviceName: 'DataDecryption',
        serviceId: 'DataDecryption-001',
        description: 'Servizio per decrittazione dei dati',
        owner: 'Company123',
        ipAddress: ipInfo
    };

    try {
        console.log("🔗 Inviando richiesta di connessione alla CA...");
        const httpsAgent = await getHttpsAgent();
        const response = await axios.post(url, requestBody, {
            timeout: 10000,
            httpsAgent
        });
        console.log("✅ Risposta della CA ricevuta.");
        if (response.data.approved && response.data.keys) {
            let receivedKeys = response.data.keys;
            // Se la risposta non contiene la chiave privata, manteniamola da file (se già presente)
            if (!receivedKeys.privateKey && localKeys && localKeys.privateKey) {
                receivedKeys.privateKey = localKeys.privateKey;
            }
            localKeys = receivedKeys;
            await fs.writeFile(KEYS_FILE, JSON.stringify(localKeys, null, 2));
            console.log("🔑 Chiavi ricevute dalla CA e salvate in", KEYS_FILE);
            await authenticateClient();
        } else {
            console.error("❌ Registrazione rifiutata dalla CA:", response.data.error || "Registrazione non approvata.");
            process.exit(1);
        }
    } catch (error) {
        let errorMsg = error.message;
        if (error.response && error.response.data && error.response.data.error) {
            errorMsg = error.response.data.error;
        }
        console.error("❌ Errore nella richiesta di connessione:", errorMsg);
        process.exit(1);
    }
}

main();
