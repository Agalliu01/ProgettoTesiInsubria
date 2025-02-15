// dataAcquisition.js
const axios = require('axios');
const fs = require('fs').promises;
const os = require('os');
const crypto = require('crypto');
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

const KEYS_FILE = './my_keys.json'; // File locale per le chiavi di DataAcquisition
const SERVICE_NAME = 'DataAcquisition';
const SERVICE_ID = 'DataAcquisition-001';

// Percorsi dei file (modifica in base alla tua struttura)
const filePathCO2 = path.join(__dirname, 'DataCO2_Adeunis');
const filePathTemperature = path.join(__dirname, 'DataTemperature_Adeunis');

// Nomi delle collezioni per il DB
const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';

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
        description: 'Servizio di acquisizione dati dai sensori',
        owner: 'Company123',
        ipAddress: ipInfo,
        loadData: true
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
 * Genera una chiave AES a 256 bit.
 */
function generateAESKey() {
    return crypto.randomBytes(32);
}

/**
 * Cifra il plaintext con AES-256-CBC.
 */
function encryptWithAES(plaintext, aesKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encryptedData: encrypted, iv: iv.toString('hex') };
}

/**
 * Processa i file dei sensori e invia man mano i record al CA.
 * Al termine stampa un riepilogo con il numero di record inviati correttamente ed errori.
 */
async function processFiles() {
    const localKeys = await requestConnection();

    const [co2Data, tempData] = await Promise.all([
        fs.readFile(filePathCO2, 'utf8'),
        fs.readFile(filePathTemperature, 'utf8')
    ]);

    const co2Lines = co2Data.split('\n').filter(line => line.trim() !== '');
    const tempLines = tempData.split('\n').filter(line => line.trim() !== '');
    console.log(`Trovate ${co2Lines.length} righe CO₂ e ${tempLines.length} righe Temperatura.`);

    let indexCO2 = 0, indexTemp = 0;
    let successCount = 0;
    let errorCount = 0;
    const delay = 10;

    const intervalId = setInterval(async () => {
        if (indexCO2 < co2Lines.length) {
            const values = co2Lines[indexCO2].split('\t').map(v => v.trim());
            const dataObj = {
                timestamp: values[0],
                date: values[1],
                zone2_window1: values[2],
                zone2_window2: values[3],
                meeting2: values[4],
                zone3_window: values[5],
                meeting1: values[6],
                meeting3: values[7],
                meeting4: values[8],
                zone3_back: values[9],
                break_room: values[10],
                zone2_back: values[11]
            };

            const aesKey = generateAESKey();
            const { encryptedData, iv } = encryptWithAES(JSON.stringify(dataObj), aesKey);

            const rsa = new NodeRSA(localKeys.publicKey);
            const encryptedAESKeyBuffer = rsa.encrypt(aesKey);
            const encryptedAESKey = encryptedAESKeyBuffer.toString('hex');

            const record = {
                collection: collectionNameCO2,
                encryptedData,
                iv,
                encryptedAESKey
            };

            const payload = {
                serviceId: SERVICE_ID,
                privateKey: localKeys.privateKey,
                record
            };

            try {
                const baseURL = await getBaseURL();
                const response = await axios.post(`${baseURL}/submitData`, payload, { timeout: 10000 });
                console.log(`CO₂ record ${indexCO2}:`, response.data.message);
                successCount++;
            } catch (err) {
                console.error("Errore invio record CO₂:", err.message);
                errorCount++;
            }
            indexCO2++;
        }

        if (indexTemp < tempLines.length) {
            const values = tempLines[indexTemp].split('\t').map(v => v.trim());
            const dataObj = {
                timestamp: values[0],
                date: values[1],
                zone2_window1: values[2],
                zone2_window2: values[3],
                meeting2: values[4],
                zone3_window: values[5],
                meeting1: values[6],
                meeting3: values[7],
                meeting4: values[8],
                zone3_back: values[9],
                hall2: values[10],
                hall1: values[11],
                upstair: values[12],
                intrance: values[13],
                downstair: values[14],
                tech_back: values[15],
                break_room: values[16],
                zone2_back: values[17]
            };

            const aesKey = generateAESKey();
            const { encryptedData, iv } = encryptWithAES(JSON.stringify(dataObj), aesKey);

            const rsa = new NodeRSA(localKeys.publicKey);
            const encryptedAESKeyBuffer = rsa.encrypt(aesKey);
            const encryptedAESKey = encryptedAESKeyBuffer.toString('hex');

            const record = {
                collection: collectionNameTemperature,
                encryptedData,
                iv,
                encryptedAESKey
            };

            const payload = {
                serviceId: SERVICE_ID,
                privateKey: localKeys.privateKey,
                record
            };

            try {
                const baseURL = await getBaseURL();
                const response = await axios.post(`${baseURL}/submitData`, payload, { timeout: 10000 });
                console.log(`Temperatura record ${indexTemp}:`, response.data.message);
                successCount++;
            } catch (err) {
                console.error("Errore invio record Temperatura:", err.message);
                errorCount++;
            }
            indexTemp++;
        }

        if (indexCO2 >= co2Lines.length && indexTemp >= tempLines.length) {
            clearInterval(intervalId);
            console.log("Elaborazione completata: tutti i record inviati.");
            console.log(`Record inviati correttamente: ${successCount}`);
            console.log(`Record con errori: ${errorCount}`);
        }
    }, delay);
}

processFiles();
