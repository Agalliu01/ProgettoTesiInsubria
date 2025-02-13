const crypto = require('crypto');
const axios = require('axios');


// Funzione per generare una chiave AES casuale
function generateAESKey() {
    return crypto.randomBytes(32); // AES-256
}

// Funzione per cifrare i dati con AES
function encryptWithAES(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encryptedData: encrypted, iv: iv.toString('hex') };
}

// Funzione per cifrare una chiave AES con la chiave pubblica RSA
function encryptAESKeyWithRSA(aesKey, publicKey) {
    return crypto.publicEncrypt(publicKey, aesKey);
}

// Funzione per ottenere la chiave pubblica dalla CA
async function getPublicKey(serviceName) {
    try {
        const response = await axios.get(`http://localhost:3000/publicKey/${serviceName}`);
        return response.data; // La chiave pubblica sarà nel corpo della risposta
    } catch (err) {
        console.error("Errore nella lettura della chiave pubblica dalla CA:", err);
        throw err;
    }
}

module.exports = {
    generateAESKey,
    encryptWithAES,
    encryptAESKeyWithRSA,
    getPublicKey
};
//sa