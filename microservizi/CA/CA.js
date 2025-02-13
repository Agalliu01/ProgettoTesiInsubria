const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const NodeRSA = require('node-rsa');
const os = require('os');
const app = express();
const PORT = 3000;

// Middleware per il parsing di JSON
app.use(express.json());

// Percorsi fissi per i file di chiavi
const PRIVATE_KEYS_FILE = path.join(__dirname, 'private_keys.json');
const PUBLIC_KEYS_FILE  = path.join(__dirname, 'public_keys.json');

// Classe per gestire certificati e informazioni dei servizi
class CertificateAuthority {
    constructor() {
        this.certificates = {};  // Mappa il nome del servizio a un oggetto contenente informazioni e chiavi
        this.authenticatedClients = new Set();  // Set di client autenticati (non utilizzato in questo esempio, ma riservato per ulteriori controlli)
    }

    // Registra un servizio con le sue chiavi pubbliche e private
    registerService(serviceInfo, privateKey, publicKey) {
        this.certificates[serviceInfo.serviceName] = {
            serviceId: serviceInfo.serviceId,
            owner: serviceInfo.owner,
            description: serviceInfo.description,
            ipAddress: serviceInfo.ipAddress,
            tailscaleIp: serviceInfo.tailscaleIp, // campo aggiuntivo
            privateKey,
            publicKey
        };
        // Aggiorna i file globali delle chiavi, salvando anche il serviceId
        this._updateKeyFile(PRIVATE_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, privateKey);
        this._updateKeyFile(PUBLIC_KEYS_FILE, serviceInfo.serviceName, serviceInfo.serviceId, publicKey);
    }

    // Ritorna la chiave pubblica di un servizio cercando per serviceId
    getPublicKey(serviceId) {
        const service = Object.values(this.certificates).find(s => s.serviceId === serviceId);
        return service ? service.publicKey : null;
    }

    // Salva la chiave nel file JSON corrispondente, associando anche il serviceId
    _updateKeyFile(filePath, serviceName, serviceId, key) {
        let data = {};
        if (fs.existsSync(filePath)) {
            try {
                data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            } catch (e) {
                console.error("Errore nel parsing di", filePath, e);
            }
        }
        data[serviceName] = { serviceId, key };
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

    // Carica la chiave dal file JSON corrispondente e restituisce solo il valore della chiave
    loadKey(serviceName, type) {
        const filePath = (type === 'private') ? PRIVATE_KEYS_FILE : PUBLIC_KEYS_FILE;
        if (fs.existsSync(filePath)) {
            try {
                const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                return data[serviceName] ? data[serviceName].key : null;
            } catch (e) {
                console.error("Errore nel parsing di", filePath, e);
                return null;
            }
        }
        return null;
    }

    // Autenticazione di un client (non utilizzata in questo esempio)
    authenticateClient(serviceId) {
        this.authenticatedClients.add(serviceId);
    }

    // Verifica se il client è autenticato (non utilizzata in questo esempio)
    isAuthenticated(serviceId) {
        return this.authenticatedClients.has(serviceId);
    }
}

const ca = new CertificateAuthority();

// Creazione dell'interfaccia readline per il prompt in console
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Funzione che chiede l'approvazione della connessione, mostrando tutte le info ricevute
function askApproval(serviceInfo) {
    return new Promise((resolve) => {
        console.log('\nRichiesta di connessione ricevuta:');
        console.log(`- Nome servizio: ${serviceInfo.serviceName}`);
        console.log(`- ID servizio: ${serviceInfo.serviceId}`);
        console.log(`- Descrizione: ${serviceInfo.description}`);
        console.log(`- Proprietario: ${serviceInfo.owner}`);
        console.log(`- IP locale: ${serviceInfo.ipAddress}`);
        console.log(`- IP Tailscale: ${serviceInfo.tailscaleIp || 'non specificato'}`);
        rl.question('👉 Vuoi approvare la connessione? (si/no): ', (answer) => {
            resolve(answer.toLowerCase().trim().charAt(0) === 's');
        });
    });
}

// Endpoint per gestire la richiesta di connessione
app.post('/connectionRequest', async (req, res) => {
    const serviceInfo = req.body;
    if (!serviceInfo.serviceName || !serviceInfo.serviceId) {
        return res.status(400).json({ error: "Il nome e l'ID del servizio sono obbligatori" });
    }

    // Se il servizio è già registrato, restituisco le chiavi già presenti
    if (ca.certificates[serviceInfo.serviceName]) {
        console.log(`ℹ️ Il servizio ${serviceInfo.serviceName} è già registrato, connessione automatica.`);
        const { privateKey, publicKey } = ca.certificates[serviceInfo.serviceName];
        return res.json({ approved: true, keys: { privateKey, publicKey } });
    }

    const approved = await askApproval(serviceInfo);
    if (approved) {
        const key = new NodeRSA({ b: 2048 });
        const privateKey = key.exportKey('private');
        const publicKey = key.exportKey('public');
        ca.registerService(serviceInfo, privateKey, publicKey);
        console.log(`✅ Servizio ${serviceInfo.serviceName} registrato con nuove chiavi.`);
        return res.json({ approved: true, keys: { privateKey, publicKey } });
    } else {
        console.log(`❌ Richiesta di connessione da ${serviceInfo.serviceName} rifiutata.`);
        return res.json({ approved: false });
    }
});

/*
  Endpoint per richiedere la chiave pubblica di un altro servizio.
  Il richiedente deve fornire:
  - requesterServiceId: il proprio serviceId
  - requesterPrivateKey: la propria chiave privata (per autenticarsi)
  - targetServiceId: il serviceId del servizio di cui vuole ottenere la chiave pubblica
*/
app.post('/requestKey', (req, res) => {
    const { requesterServiceId, requesterPrivateKey, targetServiceId } = req.body;
    if (!requesterServiceId || !requesterPrivateKey || !targetServiceId) {
        return res.status(400).json({ error: "Parametri mancanti: requesterServiceId, requesterPrivateKey, targetServiceId sono obbligatori." });
    }

    // Verifica dell'identità del richiedente: cerca il certificato in base al serviceId
    const requesterCert = Object.values(ca.certificates).find(cert => cert.serviceId === requesterServiceId);
    if (!requesterCert) {
        return res.status(404).json({ error: "Servizio richiedente non registrato" });
    }
    if (requesterCert.privateKey !== requesterPrivateKey) {
        return res.status(401).json({ error: "Autenticazione fallita: chiave privata non corretta" });
    }

    // Ricerca del servizio target in base al serviceId
    const targetCert = Object.values(ca.certificates).find(cert => cert.serviceId === targetServiceId);
    if (!targetCert) {
        return res.status(404).json({ error: "Servizio richiesto non registrato" });
    }

    // Restituisco la chiave privata del target (previa autenticazione)
    return res.json({ privateKey: targetCert.privateKey });
});

/*
  (Opzionale) Endpoint per ottenere la chiave pubblica di un servizio tramite GET.
  Attenzione: questo endpoint non richiede autenticazione e potrebbe essere usato solo per scopi interni.
*/
app.get('/publicKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    if (!ca.certificates[serviceName]) {
        return res.status(404).send('Servizio non registrato');
    }
    res.send(ca.certificates[serviceName].publicKey);
});

/*
  (Opzionale) Endpoint per ottenere la chiave privata di un servizio (solo per scopi interni).
  Non usare in produzione!
*/
app.get('/privateKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    if (!ca.certificates[serviceName]) {
        return res.status(404).send('Servizio non registrato');
    }
    const privateKey = ca.loadKey(serviceName, 'private');
    if (!privateKey) {
        return res.status(404).send('Chiave privata non trovata');
    }
    res.send(privateKey);
});

// Funzione per ottenere l'IP locale
function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const iface of Object.values(interfaces)) {
        for (const entry of iface) {
            if (entry.family === 'IPv4' && !entry.internal) {
                return entry.address;
            }
        }
    }
    return 'localhost';
}
//sa
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Certificate Authority in ascolto su http://${getLocalIP()}:${PORT}`);
});
