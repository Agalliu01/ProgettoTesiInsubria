const USE_TAILSCALE = false; // Imposta a true per usare l'IP Tailscale, false per usare localhost

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

const axios = require('axios');
const os = require('os');
const timeout = 0; // tempo (ms) tra il processamento di ogni riga
const fs = require('fs').promises;
const { MongoClient } = require('mongodb');
const path = require('path');

const {
    generateAESKey,
    encryptWithAES,
    encryptAESKeyWithRSA,
    getPublicKey
} = require('./encryption');

const mongoUrl = 'mongodb://localhost:27017/';
const dbName = 'sensor_data';

const filePathCO2 = '../DataCO2_Adeunis';
const filePathTemperature = '../DataTemperature_Adeunis';

const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';

const serviceId = 'DataAcquisition-001'; // ID del servizio

// File locale in cui salvare le chiavi ottenute dalla CA
const KEYS_FILE = './my_keys.json';

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

        // Otteniamo la chiave pubblica di destinazione per cifrare la chiave AES.
        // (La logica di ottenimento della chiave pubblica è separata e gestita in getPublicKey.)
        const publicKey = await getPublicKey('DataAcquisition');

        let indexCO2 = 0, indexTemp = 0;

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
    try {
        let localKeys = null;
        // Provo a leggere il file delle chiavi se esiste
        try {
            const keysData = await fs.readFile(KEYS_FILE, 'utf8');
            localKeys = JSON.parse(keysData);
            console.log("Chiavi locali trovate:", localKeys);
        } catch (err) {
            console.log("Nessun file di chiavi trovato, attendo che la CA mi fornisca le chiavi...");
        }

        // Recupera informazioni sull'IP (adattare se necessario)
        const ipInfo = os.networkInterfaces();
        const baseURL = USE_TAILSCALE ? `http://${getTailscaleIP(ipInfo)}:3000` : 'http://localhost:3000';
        const url = `${baseURL}/connectionRequest`;
        const requestBody = {
            serviceName: 'DataAcquisition',
            serviceId,
            description: 'Servizio per l’elaborazione dei dati dei sensori',
            owner: 'Company123',
            ipAddress: ipInfo
        };

        // Se ho già una chiave locale, la invio per autenticare il servizio registrato
        if (localKeys && localKeys.privateKey) {
            requestBody.privateKey = localKeys.privateKey;
        }

        let attempts = 0;
        const maxAttempts = 3;
        let connectionResponse = null;
        let success = false;
        while (attempts < maxAttempts && !success) {
            try {
                attempts++;
                console.log(`🔗 Inviando richiesta di connessione alla CA... Tentativo ${attempts}`);
                connectionResponse = await axios.post(url, requestBody);
                if (connectionResponse.data.approved) {
                    success = true;
                } else {
                    throw new Error("Connessione rifiutata dalla CA");
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

        if (connectionResponse.data.approved) {
            console.log("✅ Connessione approvata/verificata dalla CA");
            if (connectionResponse.data.keys) {
                await fs.writeFile(KEYS_FILE, JSON.stringify(connectionResponse.data.keys, null, 2));
                console.log("Chiavi ricevute dalla CA e salvate in", KEYS_FILE);
                processFiles();
            } else {
                console.error("❌ La CA non ha fornito le chiavi. Non posso procedere.");
                process.exit(1);
            }
        } else {
            console.error("❌ Connessione rifiutata dalla CA");
            process.exit(1);
        }
    } catch (error) {
        console.error("Errore durante la richiesta di connessione a CA:", error.message);
        process.exit(1);
    }
}
//saa
requestConnection();
