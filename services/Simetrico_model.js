const crypto = require('crypto');

// Función para cifrar utilizando AES-128-CBC con la clave proporcionada por el usuario
const encrypt = (text, userKey) => {
  const key = Buffer.from(userKey, 'utf8'); // Convertimos la clave del usuario a un buffer
  const iv = crypto.randomBytes(16); // Generamos un IV aleatorio de 16 bytes

  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    iv: iv.toString('hex'),  // Guardamos el IV junto con el cifrado
    content: encrypted
  };
};

// Función para descifrar utilizando AES-128-CBC con la clave proporcionada por el usuario
const decrypt = (hash, userKey) => {
  const key = Buffer.from(userKey, 'utf8'); // Convertimos la clave del usuario a un buffer
  const iv = Buffer.from(hash.iv, 'hex'); // Recuperamos el IV en formato buffer

  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let decrypted = decipher.update(hash.content, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};

module.exports = {
  encrypt,
  decrypt
};
