const crypto = require('crypto');

// Función genérica para generar el hash utilizando SHA-2
const hash = (text, algorithm) => {
  return crypto.createHash(algorithm).update(text).digest('hex');
};

// Exportamos las funciones para SHA-224, SHA-256, SHA-384, y SHA-512
module.exports = {
  hash
};
