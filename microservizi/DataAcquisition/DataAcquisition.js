// dataAcquisition.js
const USE_TAILSCALE = false; // Imposta a true per usare l'IP Tailscale, false per usare localhost
const axios = require('axios');
const os = require('os');
const fs = require('fs').promises;
const { MongoClient } = require('mongodb');
const path = require('path');
const NodeRSA = require('node-rsa');
const {
    generateAESKey,
    encryptWithAES,
    encryptAESKeyWithRSA,
    getPublicKey
} = require('./encryption');

const KEYS_FILE = './my_keys.json';
const mongoUrl = 'mongodb://localhost:27017/';
const dbName = 'sensor_data';

const filePathCO2 = '../DataCO2_Adeunis';
const filePathTemperature = '../DataTemperature_Adeunis';

const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';

let serviceId = 'DataAcquisition-001';

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

async function processFiles() {
    const client = new MongoClient(mongoUrl);
    try {
        await client.connect();
        console.log("✅ Connessione a MongoDB aperta.");
        const db = client.db(dbName);
        const co2Collection = db.collection(collectionNameCO2);
        const tempCollection = db.collection(collectionNameTemperature);

        const [co2Data, tempData] = await Promise.all([
            fs.readFile(filePathCO2, 'utf8'),
            fs.readFile(filePathTemperature, 'utf8')
        ]);

        const co2Lines = co2Data.split('\n').filter(line => line.trim() !== '');
        const tempLines = tempData.split('\n').filter(line => line.trim() !== '');
        console.log(`Simulazione rilevazione: ${co2Lines.length} righe CO₂ e ${tempLines.length} righe Temperatura.`);

        // Ottieni la chiave pubblica per cifrare la chiave AES
        const publicKey = await getPublicKey('DataAcquisition');

        let indexCO2 = 0, indexTemp = 0;
        const timeout = 0; // nessun delay tra le elaborazioni

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
                const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

                try {
                    await co2Collection.insertOne({
                        serviceId, // Salva il serviceId in chiaro
                        encryptedData,
                        iv,
                        encryptedAESKey: encryptedAESKey.toString('hex')
                    });
                } catch (e) {
                    console.error("Errore inserimento CO₂:", e);
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
                const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

                try {
                    await tempCollection.insertOne({
                        serviceId, // Salva il serviceId in chiaro
                        encryptedData,
                        iv,
                        encryptedAESKey: encryptedAESKey.toString('hex')
                    });
                } catch (e) {
                    console.error("Errore inserimento Temperatura:", e);
                }
                indexTemp++;
            }

            if (indexCO2 >= co2Lines.length && indexTemp >= tempLines.length) {
                clearInterval(intervalId);
                console.log("Elaborazione completata.");
                await client.close();
            }
        }, timeout);

    } catch (err) {
        console.error("Errore:", err);
        await client.close();
    }
}

async function requestConnection() {
    let localKeys = null;
    try {
        const keysData = await fs.readFile(KEYS_FILE, 'utf8');
        localKeys = JSON.parse(keysData);
        console.log("✅ Chiavi locali trovate:", localKeys);
    } catch (err) {
        console.log("⚠️ Nessun file di chiavi trovato, attendo che la CA mi fornisca le chiavi...");
    }

    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE
        ? `http://${getTailscaleIP(ipInfo)}:3000`
        : 'http://localhost:3000';
    const url = `${baseURL}/connectionRequest`;

    const requestBody = {
        serviceName: 'DataAcquisition',
        serviceId: serviceId,
        description: 'Servizio per l’elaborazione dei dati dei sensori',
        owner: 'Company123',
        ipAddress: ipInfo
    };

    if (localKeys && localKeys.privateKey) {
        requestBody.privateKey = localKeys.privateKey;
    }

    try {
        console.log("🔗 Inviando richiesta di connessione alla CA...");
        // Timeout impostato a 10 secondi
        const response = await axios.post(url, requestBody, { timeout: 10000 });
        if (response.data.approved) {
            console.log("✅ Connessione approvata/verificata dalla CA");
            if (response.data.keys) {
                await fs.writeFile(KEYS_FILE, JSON.stringify(response.data.keys, null, 2));
                console.log("🔑 Chiavi ricevute dalla CA e salvate in", KEYS_FILE);
                serviceId = response.data.keys.serviceId || serviceId;
                processFiles();
            } else {
                console.error("❌ La CA non ha fornito le chiavi. Non posso procedere.");
                process.exit(1);
            }
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

requestConnection();
