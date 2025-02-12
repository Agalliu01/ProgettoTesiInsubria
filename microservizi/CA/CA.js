// /CA/CA.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

class CertificateAuthority {
    constructor() {
        this.certificates = {};
    }

    registerService(serviceName, privateKey, publicKey) {
        this.certificates[serviceName] = { privateKey, publicKey };
    }




    getPublicKey(serviceName) {
        return this.certificates[serviceName]?.publicKey;
    }


    saveKey(serviceName, type, key) {
        const filePath = path.join(__dirname, `${serviceName}_${type}.pem`);
        fs.writeFileSync(filePath, key);
    }

    loadKey(serviceName, type) {
        const filePath = path.join(__dirname, `${serviceName}_${type}.pem`);
        return fs.readFileSync(filePath, 'utf8');
    }
}

const ca = new CertificateAuthority();
const NodeRSA = require('node-rsa');
const key = new NodeRSA({ b: 2048 });
const privateKey = key.exportKey('private');
const publicKey = key.exportKey('public');

// Registra e salva le chiavi
ca.registerService('DataAcquisition', privateKey, publicKey);
ca.saveKey('DataAcquisition', 'private', privateKey);
ca.saveKey('DataAcquisition', 'public', publicKey);

// Endpoint per ottenere la chiave pubblica di un servizio
app.get('/publicKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    const publicKey = ca.getPublicKey(serviceName);
    if (publicKey) {
        res.send(publicKey);
    } else {
        res.status(404).send('Service not registered');
    }
});

// Endpoint per ottenere la chiave privata di un servizio
app.get('/privateKey/:serviceName', (req, res) => {
    const serviceName = req.params.serviceName;
    const privateKey = ca.loadKey(serviceName, 'private');  // Carica la chiave privata dal file
    if (privateKey) {
        res.send(privateKey);  // Restituisce la chiave privata
    } else {
        res.status(404).send('Service not registered or private key not found');
    }
});


app.listen(PORT, '0.0.0.0', () => {
    console.log(`Certificate Authority in ascolto su http://localhost:${PORT}`);
});
