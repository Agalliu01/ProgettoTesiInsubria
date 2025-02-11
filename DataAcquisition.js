
const timeout=0;  //cambieremo poi come vorremmo per il testing


const fs = require('fs').promises;
const { MongoClient } = require('mongodb');

// Parametri di connessione e database
const mongoUrl = 'mongodb://localhost:27017/'; // Modifica se necessario
//*********Attiva l'url sotto per te leti se devi provare il codice
//const mongoUrl = 'mongodb://admin:password@100.111.12.33:27017'; // se non ti trova l url, verifica il servizio su docker oppure se te l ho messo giusto

const dbName = 'sensor_data';

// Percorsi dei file CSV
const filePathCO2 = 'DataCO2_Adeunis';                // File CO₂ (originale)
const filePathTemperature = 'DataTemperature_Adeunis'; // File Temperatura

// Nomi delle collezioni (se vuoi in futuro inserire i dati su MongoDB)
const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';

// (Opzionale) Funzione di connessione a MongoDB per eventuale inserimento
async function connectToMongo(collectionName, data) {
    const client = new MongoClient(mongoUrl);
    try {
        await client.connect();
        console.log("✅ Connesso a MongoDB!");
        const db = client.db(dbName);
        const collection = db.collection(collectionName);
        console.log(`📂 Database e collezione (${collectionName}) selezionati con successo!`);
        // Se vuoi inserire i dati, decommenta le righe seguenti:
         const result = await collection.insertOne(data);
         console.log("📥 Dati inseriti con successo:", result.insertedId);
    } catch (err) {
        console.error("❌ Errore nella connessione a MongoDB:", err);
    } finally {
        await client.close();
        console.log("🔌 Connessione chiusa.");
    }
}

// Funzione che legge entrambi i file e, ogni 1 secondo, preleva una riga da ciascuno e la stampa
async function processFiles() {
    try {
        // Leggiamo i due file in parallelo
        const [co2Data, temperatureData] = await Promise.all([
            fs.readFile(filePathCO2, 'utf8'),
            fs.readFile(filePathTemperature, 'utf8')
        ]);

        // Suddividiamo i file in array di righe e filtriamo eventuali righe vuote
        const co2Lines = co2Data.split('\n').filter(line => line.trim() !== '');
        const temperatureLines = temperatureData.split('\n').filter(line => line.trim() !== '');

        // Se i file hanno numeri di righe differenti, usiamo il minimo fra i due
        let index = 0;
        const maxIndex = Math.min(co2Lines.length, temperatureLines.length);

        console.log(`Inizio elaborazione: verranno processate ${maxIndex} righe per ciascun file (ogni ${timeout/1000} secondi).`);

        const intervalId = setInterval(() => {
            if (index >= maxIndex) {
                clearInterval(intervalId);
                console.log("Fine dei dati.");
                return;
            }

            // Elaborazione della riga del file CO₂, rimuovendo i caratteri \r
            const co2Values = co2Lines[index]
                .split('\t')
                .map(item => item.replace(/\r/g, '').trim());

            const co2SensorData = {
                timestamp:     co2Values[0],
                date:          co2Values[1],
                zone2_window1: co2Values[2],
                zone2_window2: co2Values[3],
                meeting2:      co2Values[4],
                zone3_window:  co2Values[5],
                meeting1:      co2Values[6],
                meeting3:      co2Values[7],
                meeting4:      co2Values[8],
                zone3_back:    co2Values[9],
                break_room:    co2Values[10],
                zone2_back:    co2Values[11]
            };

            // Elaborazione della riga del file Temperatura, rimuovendo i caratteri \r
            const temperatureValues = temperatureLines[index]
                .split('\t')
                .map(item => item.replace(/\r/g, '').trim());

            const temperatureSensorData = {
                timestamp:     temperatureValues[0],
                date:          temperatureValues[1],
                zone2_window1: temperatureValues[2],
                zone2_window2: temperatureValues[3],
                meeting2:      temperatureValues[4],
                zone3_window:  temperatureValues[5],
                meeting1:      temperatureValues[6],
                meeting3:      temperatureValues[7],
                meeting4:      temperatureValues[8],
                zone3_back:    temperatureValues[9],
                hall2:         temperatureValues[10],
                hall1:         temperatureValues[11],
                upstair:       temperatureValues[12],
                intrance:      temperatureValues[13],
                downstair:     temperatureValues[14],
                tech_back:     temperatureValues[15],
                break_room:    temperatureValues[16],
                zone2_back:    temperatureValues[17]
            };

            console.log(`\n--- Riga ${index + 1} ---`);
            console.log("CO₂:", co2SensorData);
            console.log("Temperatura:", temperatureSensorData);

            // Se in futuro vuoi inserire i dati in MongoDB, puoi chiamare le funzioni:
             connectToMongo(collectionNameCO2, co2SensorData);
             connectToMongo(collectionNameTemperature, temperatureSensorData);

            index++;
        }, timeout);

    } catch (err) {
        console.error("❌ Errore nel leggere i file:", err);
    }
}

processFiles();
