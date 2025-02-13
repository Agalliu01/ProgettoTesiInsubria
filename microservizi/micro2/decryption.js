const axios = require('axios');
const os = require('os');
const fs = require('fs').promises;
const { MongoClient } = require('mongodb');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');

// Configurazioni
const caIP = '100.86.173.100';
const KEYS_FILE = './my_keys_decryption.json';
const mongoUrl = 'mongodb://localhost:27017/';
const dbName = 'sensor_data';
const collectionNameCO2 = 'co2_readings';

// Variabili globali
let localKeys = null;
let keyCache = {}; // Cache per le chiavi private dei servizi target

async function requestConnection() {
    try {
        try {
            const data = await fs.readFile(KEYS_FILE, 'utf8');
            localKeys = JSON.parse(data);
            console.log("✅ Chiavi locali trovate.");
        } catch (err) {
            console.log("⚠️ Nessun file di chiavi trovato. Richiesta connessione alla CA...");
        }

        if (!localKeys) {
            const url = `http://${caIP}:3000/connectionRequest`;
            const requestBody = {
                serviceName: 'DataDecryption',
                serviceId: 'DataDecryption-001',
                description: 'Servizio per decrittazione dei dati',
                owner: 'Company123',
                ipAddress: os.networkInterfaces()
            };

            console.log("🔗 Inviando richiesta di connessione alla CA...");
            const response = await axios.post(url, requestBody);
            console.log("✅ Risposta della CA ricevuta.");

            if (response.data.approved && response.data.keys) {
                localKeys = response.data.keys;
                await fs.writeFile(KEYS_FILE, JSON.stringify(localKeys, null, 2));
                console.log("🔑 Chiavi ricevute e salvate in", KEYS_FILE);
            } else {
                console.error("❌ Errore: La CA non ha fornito le chiavi. Uscita.");
                process.exit(1);
            }
        } else {
            console.log("✅ Utilizzo chiavi locali già esistenti.");
        }
    } catch (err) {
        console.error("❌ Errore nella richiesta di connessione alla CA:", err.message);
        process.exit(1);
    }
}

async function getTargetPrivateKey(targetServiceId) {
    if (keyCache[targetServiceId]) {
        return keyCache[targetServiceId];
    }

    try {
        console.log(`🔍 Richiesta chiave privata per il target ${targetServiceId} alla CA...`);
        const url = `http://${caIP}:3000/requestKey`;
        const response = await axios.post(url, {
            requesterServiceId: 'DataDecryption-001',
            requesterPrivateKey: localKeys.privateKey,
            targetServiceId
        });

        if (response.data && response.data.privateKey) {
            console.log(`✅ Chiave privata ricevuta per il target ${targetServiceId}.`);
            keyCache[targetServiceId] = response.data.privateKey;
            return response.data.privateKey;
        } else {
            throw new Error(`❌ Chiave privata non ricevuta per ${targetServiceId}.`);
        }
    } catch (err) {
        console.error(`❌ Errore nel recupero della chiave per ${targetServiceId}:`, err.message);
        throw err;
    }
}

function decryptAESKeyWithRSA(encryptedAESKey, privateKey) {
    try {
        const key = new NodeRSA(privateKey);
        if (!key.isPrivate()) throw new Error('Chiave privata non valida.');

        return key.decrypt(Buffer.from(encryptedAESKey, 'hex'));
    } catch (err) {
        console.error("❌ Errore nella decrittazione della chiave AES:", err.message);
        throw err;
    }
}

function decryptWithAES(encryptedData, aesKey, iv) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(iv, 'hex'));
        let decrypted = decipher.update(Buffer.from(encryptedData, 'hex'), 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error("❌ Errore nella decrittazione dei dati:", err.message);
        throw err;
    }
}

async function decryptData() {
    console.log("🔐 Avvio processo di decrittazione...");
    try {
        const client = new MongoClient(mongoUrl);
        await client.connect();
        console.log("✅ Connessione a MongoDB stabilita.");
        const db = client.db(dbName);
        const collection = db.collection(collectionNameCO2);
        const records = await collection.find().toArray();

        if (!records.length) {
            console.log("⚠️ Nessun dato trovato.");
            await client.close();
            return;
        }

        for (const record of records) {
            try {
                const targetServiceId = record.serviceId;
                const targetPrivateKey = await getTargetPrivateKey(targetServiceId);
                const aesKey = decryptAESKeyWithRSA(record.encryptedAESKey, targetPrivateKey);
                const decryptedData = decryptWithAES(record.encryptedData, aesKey, record.iv);
                console.log(`✅ Dati decriptati per ${targetServiceId}:`, decryptedData);
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

async function main() {
    await requestConnection();
    await decryptData();
}

main();
