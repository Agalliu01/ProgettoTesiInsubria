// dataDecryption.js
const USE_TAILSCALE = false; // Imposta a true per usare l'IP Tailscale, false per usare localhost
const axios = require('axios');
const os = require('os');
const fs = require('fs').promises;
const { MongoClient } = require('mongodb');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const path = require('path');

const KEYS_FILE = './my_keys_decryption.json';
const mongoUrl = 'mongodb://localhost:27017/';
const dbName = 'sensor_data';
const collectionNameCO2 = 'co2_readings';

let localKeys = null;
let keyCache = {}; // Cache per le chiavi private dei target

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

async function requestConnection() {
    try {
        const data = await fs.readFile(KEYS_FILE, 'utf8');
        localKeys = JSON.parse(data);
        console.log("✅ Chiavi locali trovate.");
    } catch (err) {
        console.log("⚠️ Nessun file di chiavi trovato.");
    }

    let attempts = 0;
    const maxAttempts = 3;
    let success = false;
    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE
        ? `http://${getTailscaleIP(ipInfo)}:3000`
        : 'http://localhost:3000';
    const url = `${baseURL}/connectionRequest`;
    const requestBody = {
        serviceName: 'DataDecryption',
        serviceId: 'DataDecryption-001',
        description: 'Servizio per decrittazione dei dati',
        owner: 'Company123',
        ipAddress: ipInfo
    };
    if (localKeys && localKeys.privateKey) {
        requestBody.privateKey = localKeys.privateKey;
    }
    while (attempts < maxAttempts && !success) {
        try {
            attempts++;
            console.log(`🔗 Inviando richiesta di connessione alla CA... Tentativo ${attempts}`);
            const response = await axios.post(url, requestBody);
            console.log("✅ Risposta della CA ricevuta.");
            if (response.data.approved && response.data.keys) {
                localKeys = response.data.keys;
                await fs.writeFile(KEYS_FILE, JSON.stringify(localKeys, null, 2));
                console.log("🔑 Chiavi ricevute e salvate in", KEYS_FILE);
                success = true;
            } else {
                throw new Error("La CA non ha fornito le chiavi.");
            }
        } catch (error) {
            console.error(`❌ Tentativo ${attempts} fallito: ${error.message}`);
            if (attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 2000));
            } else {
                console.error("❌ Numero massimo di tentativi raggiunto. Uscita.");
                process.exit(1);
            }
        }
    }
}

async function getTargetPrivateKey(targetServiceId) {
    if (keyCache[targetServiceId]) {
        return keyCache[targetServiceId];
    }
    try {
        console.log(`🔍 Richiesta chiave privata per il target ${targetServiceId} alla CA...`);
        const ipInfo = os.networkInterfaces();
        const baseURL = USE_TAILSCALE
            ? `http://${getTailscaleIP(ipInfo)}:3000`
            : 'http://localhost:3000';
        const url = `${baseURL}/requestKey`;
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
            throw new Error(`Chiave privata non ricevuta per ${targetServiceId}.`);
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
