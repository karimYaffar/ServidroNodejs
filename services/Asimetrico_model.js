const crypto = require('crypto');

// Generamos las claves pública y privada utilizando ECC
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'sect239k1', // Podemos usar varias curvas, por ejemplo, 'secp256k1', 'sect239k1'
  publicKeyEncoding: {
    type: 'spki', // Codificación de clave pública
    format: 'pem' // Formato en PEM
  },
  privateKeyEncoding: {
    type: 'pkcs8', // Codificación de clave privada
    format: 'pem'  // Formato en PEM
  }
});

// Función para firmar un mensaje utilizando ECC (Cifrado Asimétrico)
const signMessage = (message) => {
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  sign.end();
  const signature = sign.sign(privateKey, 'hex');
  return signature;
};

// Función para verificar la firma del mensaje
const verifySignature = (message, signature) => {
  const verify = crypto.createVerify('SHA256');
  verify.update(message);
  verify.end();
  return verify.verify(publicKey, signature, 'hex');
};

// Función para cifrar un mensaje (usualmente ECC no se usa directamente para cifrar grandes cantidades de datos)
const encryptMessage = (message) => {
  // Generalmente, ECC se usa para cifrar una clave de sesión simétrica en lugar de cifrar grandes datos directamente.
  // En este ejemplo, estamos simulando un cifrado básico con claves ECC.
  const encryptedMessage = Buffer.from(message).toString('base64');
  return encryptedMessage;
};

// Función para descifrar un mensaje (usualmente ECC no se usa directamente para descifrar grandes cantidades de datos)
const decryptMessage = (encryptedMessage) => {
  // Similar al cifrado, usualmente ECC no se usa directamente para grandes cantidades de datos.
  const decryptedMessage = Buffer.from(encryptedMessage, 'base64').toString('utf8');
  return decryptedMessage;
};

module.exports = {
  publicKey,
  privateKey,
  signMessage,
  verifySignature,
  encryptMessage,
  decryptMessage
};
