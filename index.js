const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors'); // Agregar CORS
const CryptoJS = require('crypto-js');

// Importar correctamente el módulo EC de elliptic
const EC = require('elliptic').ec;
const ec = new EC('secp256k1'); // Instancia correcta de EC

const app = express();

// Habilitar CORS para todas las solicitudes
app.use(cors()); // Esto permite peticiones desde cualquier origen

app.use(bodyParser.json());

// --- Funciones de Hash ---
const hashSHA224 = (value) => {
    return crypto.createHash('sha224').update(value).digest('hex');
};

const hashSHA256 = (value) => {
    return crypto.createHash('sha256').update(value).digest('hex');
};

const hashSHA384 = (value) => {
    return crypto.createHash('sha384').update(value).digest('hex');
};

const hashSHA512 = (value) => {
    return crypto.createHash('sha512').update(value).digest('hex');
};

// --- Función para cifrar con AES-256-CBC (Usado por ECC) ---
const encryptAES = (text, key) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
};

// --- Función para descifrar con AES-256-CBC ---
const decryptAES = (encryptedText, key) => {
    const iv = Buffer.from(encryptedText.slice(0, 32), 'hex'); // los primeros 32 caracteres (16 bytes) son el IV
    const content = encryptedText.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// --- Funciones para cifrado simétrico 3DES ---
const encrypt3DES = (text, key) => {
    const cipher = crypto.createCipheriv('des-ede3', Buffer.from(key), null);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
};

const decrypt3DES = (encryptedText, key) => {
    const decipher = crypto.createDecipheriv('des-ede3', Buffer.from(key), null);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// --- Clase para ECC (Asimétrico) ---
class ECC {
    constructor() {
        this.keyPair = ec.genKeyPair();
        this.publicKey = this.keyPair.getPublic('hex');
        this.privateKey = this.keyPair.getPrivate('hex');
    }

    deriveSharedSecret(clientPublicKey) {
        const clientKey = ec.keyFromPublic(clientPublicKey, 'hex');
        const sharedSecret = this.keyPair.derive(clientKey.getPublic());
        return sharedSecret.toString(16);
    }

    encryptMessage(sharedSecret, text) {
        const key = crypto.createHash('sha256').update(sharedSecret).digest();
        const encryptedText = encryptAES(text, key);
        return encryptedText;
    }

    decryptMessage(sharedSecret, encryptedText) {
        const key = crypto.createHash('sha256').update(sharedSecret).digest();
        const decryptedText = decryptAES(encryptedText, key);
        return decryptedText;
    }
}

// Instanciar ECC
const eccInstance = new ECC();

// --- Endpoint para cifrar los datos ---
app.post('/api/encrypt-data', (req, res) => {
    const { username, password, email, phone, address, clientPublicKey, encryption } = req.body;

    let encryptedData;

    if (encryption === 'asimetric') {
        // Derivar secreto compartido usando ECC
        const sharedSecret = eccInstance.deriveSharedSecret(eccInstance.privateKey, clientPublicKey);

        // Cifrar cada campo con ECC y AES
        encryptedData = {
            username: eccInstance.encryptMessage(sharedSecret, username),
            email: eccInstance.encryptMessage(sharedSecret, email),
            password: eccInstance.encryptMessage(sharedSecret, password),
            phone: eccInstance.encryptMessage(sharedSecret, phone),
            address: eccInstance.encryptMessage(sharedSecret, address)
        };
    } else if (encryption === 'simetric') {
        if (clientPublicKey.length !== 24) {
            return res.status(400).send('La clave para 3DES debe tener 24 caracteres.');
        }
        // Cifrar cada campo con 3DES
        encryptedData = {
            username: encrypt3DES(username, clientPublicKey),
            email: encrypt3DES(email, clientPublicKey),
            password: encrypt3DES(password, clientPublicKey),
            phone: encrypt3DES(phone, clientPublicKey),
            address: encrypt3DES(address, clientPublicKey)
        };
    } else if (encryption === 'hash224') {
        // Hashear cada campo con SHA-224
        encryptedData = {
            username: hashSHA224(username),
            email: hashSHA224(email),
            password: hashSHA224(password),
            phone: hashSHA224(phone),
            address: hashSHA224(address)
        };
    } else if (encryption === 'hash256') {
        // Hashear cada campo con SHA-256
        encryptedData = {
            username: hashSHA256(username),
            email: hashSHA256(email),
            password: hashSHA256(password),
            phone: hashSHA256(phone),
            address: hashSHA256(address)
        };
    } else if (encryption === 'hash384') {
        // Hashear cada campo con SHA-384
        encryptedData = {
            username: hashSHA384(username),
            email: hashSHA384(email),
            password: hashSHA384(password),
            phone: hashSHA384(phone),
            address: hashSHA384(address)
        };
    } else if (encryption === 'hash512') {
        // Hashear cada campo con SHA-512
        encryptedData = {
            username: hashSHA512(username),
            email: hashSHA512(email),
            password: hashSHA512(password),
            phone: hashSHA512(phone),
            address: hashSHA512(address)
        };
    } else {
        return res.status(400).send('Método de cifrado no soportado.');
    }

    res.json({
        encryption: encryption,
        encryptedData: encryptedData
    });
});

// --- Endpoint para descifrar los datos ---
app.post('/api/decrypt-data', (req, res) => {
    const { encryptedData, clientPublicKey, symmetricKey, encryption } = req.body;

    let decryptedData;

    if (encryption === 'ECC') {
        // Derivar secreto compartido usando ECC
        const sharedSecret = eccInstance.deriveSharedSecret(eccInstance.privateKey, clientPublicKey);

        // Descifrar cada campo con ECC y AES
        decryptedData = {
            username: eccInstance.decryptMessage(sharedSecret, encryptedData.username),
            email: eccInstance.decryptMessage(sharedSecret, encryptedData.email),
            password: eccInstance.decryptMessage(sharedSecret, encryptedData.password),
            phone: eccInstance.decryptMessage(sharedSecret, encryptedData.phone),
            address: eccInstance.decryptMessage(sharedSecret, encryptedData.address)
        };
    } else if (encryption === '3DES') {
        if (symmetricKey.length !== 24) {
            return res.status(400).send('La clave para 3DES debe tener 24 caracteres.');
        }
        // Descifrar cada campo con 3DES
        decryptedData = {
            username: decrypt3DES(encryptedData.username, symmetricKey),
            email: decrypt3DES(encryptedData.email, symmetricKey),
            password: decrypt3DES(encryptedData.password, symmetricKey),
            phone: decrypt3DES(encryptedData.phone, symmetricKey),
            address: decrypt3DES(encryptedData.address, symmetricKey)
        };
    } else {
        return res.status(400).send('Método de descifrado no soportado.');
    }

    res.json({
        decryptedData: decryptedData
    });
});

// Puerto de la aplicación
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {});
