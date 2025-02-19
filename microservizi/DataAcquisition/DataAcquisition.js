const USE_TAILSCALE = true; // true per usare IP Tailscale, false per localhost
const axios = require('axios');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const path = require('path');

const KEYS_FILE = './my_keys.json';
//const mongoUrl = 'mongodb://localhost:27017/';
const mongoUrl = 'mongodb://admin:password@100.116.74.57:27017/admin?tls=true&tlsCertificateKeyFile=C:\\Users\\capit\\Documents\\ProgettoTesiInsubria\\microservizi\\DataAcquisition\\mongodb.pem&tlsCAFile=C:\\Users\\capit\\Documents\\ProgettoTesiInsubria\\microservizi\\DataAcquisition\\mongodb.pem';

const dbName = 'sensor_data';
const filePathCO2 = '../DataCO2_Adeunis';
const filePathTemperature = '../DataTemperature_Adeunis';
const collectionNameCO2 = 'co2_readings';
const collectionNameTemperature = 'temperature_readings';
let serviceId = 'DataAcquisition-001';

let localKeys = {};  // conterrà { privateKey, publicKey } in formato hex

// -------------------- MODIFICA AGGIUNTIVA --------------------
// Funzione per ottenere il certificato pubblico del server e creare un https.Agent
async function getHttpsAgent() {
    const certFile = path.join(__dirname, 'mongodb.pem');
    let caCert;
    try {
        caCert = await fs.readFile(certFile, 'utf8');
    } catch (err) {
        const ipInfo = os.networkInterfaces();
        const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
            ? `https://${getTailscaleIP(ipInfo)}:3000`
            : 'https://localhost:3000';
        const url = `${baseURL}/serverCert`;
        // Inizialmente usiamo rejectUnauthorized false per scaricare il certificato
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
 * Funzione che cifra la chiave AES usando ECIES (ECDH + AES-256-CBC)
 * @param {Buffer} aesKey - Buffer della chiave AES (32 bytes)
 * @param {string} recipientPublicKey - chiave pubblica del destinatario (hex)
 * @returns {string} - JSON string contenente: ephemeralPublicKey, iv, ciphertext (tutti in hex)
 */
function encryptAESKeyWithECC(aesKey, recipientPublicKey) {
    const ephemeral = crypto.createECDH('prime256v1');
    ephemeral.generateKeys();
    const sharedSecret = ephemeral.computeSecret(recipientPublicKey, 'hex'); // Buffer
    const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest(); // 32 bytes
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
    let encrypted = cipher.update(aesKey);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return JSON.stringify({
        ephemeralPublicKey: ephemeral.getPublicKey('hex'),
        iv: iv.toString('hex'),
        ciphertext: encrypted.toString('hex')
    });
}

/**
 * Funzione per richiedere la connessione al CA tramite HTTPS.
 * Se sono già presenti le chiavi, viene usato il metodo legacy.
 */
async function requestConnection() {
    let localKeysFromFile = null;
    try {
        const keysData = await fs.readFile(KEYS_FILE, 'utf8');
        localKeysFromFile = JSON.parse(keysData);
        console.log("✅ Chiavi locali trovate:", localKeysFromFile);
    } catch (err) {
        console.log("⚠️ Nessun file di chiavi trovato, attendo che la CA mi fornisca le chiavi...");
    }

    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
        ? `https://${getTailscaleIP(ipInfo)}:3000`
        : 'https://localhost:3000';
    const url = `${baseURL}/connectionRequest`;

    const requestBody = {
        serviceName: 'DataAcquisition',
        serviceId: serviceId,
        description: 'Servizio per l’elaborazione dei dati dei sensori',
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
        if (response.data.approved) {
            console.log("✅ Connessione approvata/verificata dalla CA");
            if (response.data.keys) {
                let receivedKeys = response.data.keys;
                // Se la risposta non contiene la chiave privata, manteniamola da file (caso già registrato)
                if (!receivedKeys.privateKey && localKeysFromFile && localKeysFromFile.privateKey) {
                    receivedKeys.privateKey = localKeysFromFile.privateKey;
                }
                await fs.writeFile(KEYS_FILE, JSON.stringify(receivedKeys, null, 2));
                console.log("🔑 Chiavi ricevute dalla CA e salvate in", KEYS_FILE);
                serviceId = receivedKeys.serviceId || serviceId;
                localKeys = receivedKeys;
                // Avvia il challenge–response per autenticarsi
                authenticateClient(localKeys);
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

/**
 * Funzione per autenticare il client tramite challenge–response usando HMAC.
 */
async function authenticateClient(localKeys) {
    const ipInfo = os.networkInterfaces();
    const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
        ? `https://${getTailscaleIP(ipInfo)}:3000`
        : 'https://localhost:3000';

    try {
        const httpsAgent = await getHttpsAgent();
        const tokenResponse = await axios.post(`${baseURL}/generateToken`, {
            serviceName: 'DataAcquisition'
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
            serviceName: 'DataAcquisition',
            signature
        }, {
            timeout: 10000,
            httpsAgent
        });

        if (authResponse.data.authenticated) {
            console.log("✅ Autenticazione completata con successo!");
            processFiles();
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
 * Funzione per processare i file e inviare i dati cifrati a MongoDB.
 * La chiave AES viene cifrata con la chiave pubblica del target, ottenuta tramite un endpoint.
 */
async function processFiles() {
    const { MongoClient } = require('mongodb');
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

        // Recupera la chiave pubblica del target (qui "DataAcquisition")
        const ipInfo = os.networkInterfaces();
        const baseURL = USE_TAILSCALE && getTailscaleIP(ipInfo)
            ? `https://${getTailscaleIP(ipInfo)}:3000`
            : 'https://localhost:3000';
        const httpsAgent = await getHttpsAgent();
        const publicKeyResponse = await axios.get(`${baseURL}/publicKey/DataAcquisition`, { httpsAgent });
        const recipientPublicKey = publicKeyResponse.data; // hex string

        let indexCO2 = 0, indexTemp = 0;
        const timeout = 0; // nessun delay

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

                const aesKey = crypto.randomBytes(32); // chiave AES a 256 bit
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
                let encryptedData = cipher.update(JSON.stringify(dataObj), 'utf8', 'hex');
                encryptedData += cipher.final('hex');
                // Cifra la chiave AES con ECC usando la chiave pubblica del target
                const encryptedAESKey = encryptAESKeyWithECC(aesKey, recipientPublicKey);

                try {
                    await co2Collection.insertOne({
                        serviceId, // in chiaro
                        encryptedData,
                        iv: iv.toString('hex'),
                        encryptedAESKey
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

                const aesKey = crypto.randomBytes(32);
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
                let encryptedData = cipher.update(JSON.stringify(dataObj), 'utf8', 'hex');
                encryptedData += cipher.final('hex');
                const encryptedAESKey = encryptAESKeyWithECC(aesKey, recipientPublicKey);

                try {
                    await tempCollection.insertOne({
                        serviceId,
                        encryptedData,
                        iv: iv.toString('hex'),
                        encryptedAESKey
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

requestConnection();
