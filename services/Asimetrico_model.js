const crypto = require('crypto');

// Función para generar un par de claves ECC
const generateKeyPair = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'sect239k1', // Puedes cambiar por otra curva como 'secp256k1'
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    return { publicKey, privateKey };
};

// Función para cifrar un mensaje utilizando la clave pública
const encryptMessage = (message, publicKey) => {
    // Simulamos un cifrado básico usando la clave pública
    const encryptedMessage = Buffer.from(message).toString('base64');
    return encryptedMessage;
};

// Función para descifrar un mensaje utilizando la clave privada
const decryptMessage = (encryptedMessage, privateKey) => {
    // Simulamos un descifrado básico usando la clave privada
    const decryptedMessage = Buffer.from(encryptedMessage, 'base64').toString('utf8');
    return decryptedMessage;
};

module.exports = {
    generateKeyPair,
    encryptMessage,
    decryptMessage
};

