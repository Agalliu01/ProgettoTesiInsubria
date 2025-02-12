const timeout = 0; // tempo (ms) tra il processamento di ogni riga

const fs = require('fs').promises;
const { MongoClient } = require('mongodb');

const {
    generateAESKey,
    encryptWithAES,
    encryptAESKeyWithRSA,
    getPublicKey
} = require('./encryption');

const mongoUrl = 'mongodb://localhost:27017/';
//const mongoUrl = 'mongodb://admin:password@100.111.12.33:27017';

const dbName = 'sensor_data';

const filePathCO2 = '../DataCO2_Adeunis';
const filePathTemperature = '../DataTemperature_Adeunis';

const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';

// Genera una barra di avanzamento con 5 segmenti (20% ciascuno)
const renderProgressBar = (progress) => {
    const totalBars = 5;
    const prog = Math.min(progress, 1);
    const filled = Math.floor(prog * totalBars);
    return `[${'#'.repeat(filled)}${'-'.repeat(totalBars - filled)}] ${Math.floor(prog * 100)}%`;
};

async function processFiles() {
    const client = new MongoClient(mongoUrl);
    try {
        await client.connect();
        console.log("✅ Connessione a MongoDB aperta.");
        const db = client.db(dbName);
        const co2Collection = db.collection(collectionNameCO2);
        const tempCollection = db.collection(collectionNameTemperature);

        // Lettura in parallelo dei due file
        const [co2Data, tempData] = await Promise.all([
            fs.readFile(filePathCO2, 'utf8'),
            fs.readFile(filePathTemperature, 'utf8')
        ]);

        const co2Lines = co2Data.split('\n').filter(line => line.trim() !== '');
        const tempLines = tempData.split('\n').filter(line => line.trim() !== '');
        console.log(`Simulazione rilevazione: ${co2Lines.length} righe CO₂ e ${tempLines.length} righe Temperatura.`);

        // Avvio del timer
        const startTime = Date.now();

        let indexCO2 = 0, indexTemp = 0;
        let thresholdCO2 = 0.2, thresholdTemp = 0.2;

        const publicKey = await getPublicKey('DataAcquisition'); // Carica la chiave pubblica RSA (con await)

        const intervalId = setInterval(async () => {
            // Elaborazione del file CO₂ (se ancora disponibile)
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
                        encryptedData,
                        iv,
                        encryptedAESKey: encryptedAESKey.toString('hex')
                    });
                } catch (e) {
                    console.error("Errore inserimento CO₂:", e);
                }
                indexCO2++;
                const progress = indexCO2 / co2Lines.length;
                if (progress >= thresholdCO2 || indexCO2 === co2Lines.length) {
                    console.log("CO₂ progress: " + renderProgressBar(progress));
                    thresholdCO2 += 0.2;
                }
            }

            // Elaborazione del file Temperatura (se ancora disponibile)
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
                        encryptedData,
                        iv,
                        encryptedAESKey: encryptedAESKey.toString('hex')
                    });
                } catch (e) {
                    console.error("Errore inserimento Temperatura:", e);
                }
                indexTemp++;
                const progress = indexTemp / tempLines.length;
                if (progress >= thresholdTemp || indexTemp === tempLines.length) {
                    console.log("Temperatura progress: " + renderProgressBar(progress));
                    thresholdTemp += 0.2;
                }
            }

            // Se entrambi i file sono stati completamente processati
            if (indexCO2 >= co2Lines.length && indexTemp >= tempLines.length) {
                clearInterval(intervalId);
                const elapsedTime = Date.now() - startTime;
                console.log("Elaborazione completata.");
                console.log(`Tempo totale: ${elapsedTime / 1000}s.`);
                console.log(`Totale righe processate: [CO₂ -> ${indexCO2}], [Temperatura -> ${indexTemp}]`);
                console.log("Chiusura connessione MongoDB.");
                await client.close();
            }
        }, timeout);

    } catch (err) {
        console.error("Errore:", err);
        await client.close();
    }
}

processFiles();
