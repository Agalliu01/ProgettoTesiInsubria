const fs = require('fs');
const { MongoClient } = require('mongodb');

const filePath = 'DataCO2_Adeunis';
const mongoUrl = 'mongodb://localhost:27017/'; // Modifica con i tuoi parametri

//const mongoUrl='mongodb://admin:password@100.111.12.33:27017';
const dbName = 'sensor_data'; // Nome del database
const collectionName = 'co2_readings'; // Nome della collezione

async function connectToMongo() {
    const client = new MongoClient(mongoUrl);

    try {
        await client.connect();
        console.log("✅ Connesso a MongoDB!");

        const db = client.db(dbName);
        const collection = db.collection(collectionName);

        console.log("📂 Database e collezione selezionati con successo!");

        // ❌ Inserimento commentato
        // const result = await collection.insertOne(data);
        // console.log("📥 Dati inseriti con successo:", result.insertedId);

    } catch (err) {
        console.error("❌ Errore nella connessione a MongoDB:", err);
    } finally {
        await client.close();
        console.log("🔌 Connessione chiusa.");
    }
}

function processFirstLine(filePath) {
    console.log("📂 Lettura del file:", filePath);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error("❌ Errore nel leggere il file:", err);
            return;
        }

        const lines = data.split('\n');
        const firstLine = lines[0].trim();

        if (!firstLine) {
            console.error("❌ Prima riga vuota o non valida!");
            return;
        }

        const values = firstLine.split('\t');

        const sensorData = {
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

        console.log("📊 Dati della prima riga:", sensorData);

        // Connessione a MongoDB (senza inserire dati)
        connectToMongo();
    });
}

processFirstLine(filePath);
