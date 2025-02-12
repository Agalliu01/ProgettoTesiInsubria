const express = require('express');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const axios = require('axios');
const app = express();
const PORT = 3000;

// Configurazione MongoDB
const mongoUrl = 'mongodb://localhost:27017/';
//const mongoUrl = 'mongodb://admin:password@100.111.12.33:27017';
const dbName = 'sensor_data';
const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';

// Funzione per decifrare la chiave AES con la chiave privata RSA
function decryptAESKeyWithRSA(encryptedAESKey, privateKey) {
    try {
        const key = new NodeRSA(privateKey);

        // Verifica che la chiave sia valida
        if (!key.isPrivate()) {
            throw new Error('La chiave non è una chiave privata valida.');
        }

        // Converte l'`encryptedAESKey` in un buffer se è una stringa esadecimale
        const encryptedAESKeyBuffer = Buffer.isBuffer(encryptedAESKey)
            ? encryptedAESKey
            : Buffer.from(encryptedAESKey, 'hex');

        // Decifra la chiave AES
        const decryptedKey = key.decrypt(encryptedAESKeyBuffer, 'buffer');
        console.log("Chiave AES decriptata (hex):", decryptedKey.toString('hex'));
        return decryptedKey; // Restituisce la chiave AES come buffer
    } catch (err) {
        console.error('Errore nella decrittazione della chiave AES:', err);
        throw err;
    }
}



/// Funzione per decifrare i dati con AES
function decryptWithAES(encryptedData, aesKey, iv) {
    const ivBuffer = Buffer.from(iv, 'hex');  // Assicurati che l'IV sia un buffer
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, ivBuffer);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}


// Funzione per ottenere la chiave privata dalla CA
async function getPrivateKeyFromCA(serviceName) {
    try {
        // Chiamata HTTP per ottenere la chiave privata dalla CA
        const response = await axios.get(`http://localhost:3000/privateKey/${serviceName}`);
        return response.data; // Restituisce la chiave privata
    } catch (err) {
        console.error("Errore nel recupero della chiave privata dalla CA:", err);
        throw err;
    }
}





async function decrypt() {

    console.log("Richiesta di decrittazione ricevuta");  // Aggiungi questo log
    try {
        const serviceName = 'DataAcquisition'; // Nome del servizio per il quale vogliamo la chiave privata
        console.log("Recuperando la chiave privata dalla CA...");

        const privateKey = await getPrivateKeyFromCA(serviceName);
        console.log("Chiave privata ricevuta:", privateKey); // Aggiungi questo log

        // Connessione a MongoDB
        const client = new MongoClient(mongoUrl);
        await client.connect();
        console.log('✅ Connessione a MongoDB aperta.');

        const db = client.db(dbName);
        const co2Collection = db.collection(collectionNameCO2);
        const tempCollection = db.collection(collectionNameTemperature);

       const co2Data = await co2Collection.find().limit(1).toArray();
    //    const tempData = await tempCollection.find().toArray();



      //  const decryptedCO2Data = await Promise.all(co2Data.map(async (entry) => {

            if (co2Data.length > 0) {
                const entry = co2Data[0];



                console.log("Decifrando entry CO2:", entry);
                const aesKey= decryptAESKeyWithRSA(entry.encryptedAESKey, privateKey); // Decifra la chiave AES
                console.log("Chiave AES decriptata (buffer):", aesKey);

                const decryptedData = decryptWithAES(entry.encryptedData, aesKey, entry.iv); // Decifra i dati
                console.log("Dati decifrati CO2:", decryptedData);
                return JSON.parse(decryptedData); // Restituisce i dati decifrati come oggetto
            }
       // }));
/*
        const decryptedTempData = await Promise.all(tempData.map(async (entry) => {
            console.log("Decifrando entry Temperatura:", entry);
            const aesKey = decryptAESKeyWithRSA(entry.encryptedAESKey, privateKey); // Decifra la chiave AES
            console.log("Chiave AES decifrata:", aesKey.toString('hex'));
            const decryptedData = decryptWithAES(entry.encryptedData, aesKey, entry.iv); // Decifra i dati
            console.log("Dati decifrati Temperatura:", decryptedData);
            return JSON.parse(decryptedData); // Restituisce i dati decifrati come oggetto
        }));
*/
        await client.close();
        console.log("Chiusura connessione MongoDB.");

        // Restituisce i dati decifrati
        console.log("CO2 Data Decifrato:", decryptedCO2Data);
        console.log("Temperature Data Decifrato:", decryptedTempData);


        console.log("Chiave privata ricevuta e decrittazione dati bloccata.");

    } catch (err) {
        console.error('Errore:', err);
        console.error('Errore durante la decifrazione dei dati.');
    }
}

decrypt();
