const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const database = {};  // Simulación de base de datos en memoria


// Importar los servicios de cifrado
const simetricoService = require('./services/Simetrico_model');
const hashService = require('./services/hash_model');
const asimetricoService = require('./services/Asimetrico_model');

// Configuración para manejar JSON y formularios
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Ruta principal para recibir los datos y decidir el tipo de cifrado
app.post('/procesar', (req, res) => {
  const { usuario,password , correo, numero , direccion, option,userKey  } = req.body;

  const userId = userKey
  let resultado;

  switch (option) {
    case 'simetric': // Cifrado Simétrico - 3DES o AES
      // Verificamos que la clave tenga 16 caracteres
      if (userKey.length !== 16) {
        return res.status(400).json({ error: 'La clave debe tener 16 caracteres.' });
      }

      // Cifrar los datos utilizando la clave proporcionada por el usuario
      resultado = {
        usuario: simetricoService.encrypt(usuario, userKey),
        correo: simetricoService.encrypt(correo, userKey),
        password: simetricoService.encrypt(password, userKey),
        numero: simetricoService.encrypt(numero, userKey),
        direccion: simetricoService.encrypt(direccion, userKey)
      };

      res.json({
        mensaje: 'Datos encriptados con éxito usando cifrado simétrico',
        resultado
      });
      break;

    case 'asimetric': // Cifrado Asimétrico - ECC
      // Verificar si el userId está presente y buscar la clave pública
      const userData = database[userId];
      if (!userData) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const { publicKey } = userData;

      // Cifrar los datos utilizando la clave pública
      resultado = {
        usuario: asimetricoService.encryptMessage(usuario, publicKey),
        correo: asimetricoService.encryptMessage(correo, publicKey),
        password: asimetricoService.encryptMessage(password, publicKey),
        numero: asimetricoService.encryptMessage(numero, publicKey),
        direccion: asimetricoService.encryptMessage(direccion, publicKey)
      };

      res.json({
        mensaje: 'Datos encriptados con éxito usando cifrado asimétrico (ECC)',
        resultado
      });
      break;

    case 'sha224': // Cifrado Hash - SHA-224
    case 'sha256': // Cifrado Hash - SHA-256
    case 'sha384': // Cifrado Hash - SHA-384
    case 'sha512': // Cifrado Hash - SHA-512
      // Aplicamos el hash al conjunto completo de datos
      resultado = {
        usuario: hashService.hash(usuario, option),
        correo: hashService.hash(correo, option),
        password: hashService.hash(password, option),
        numero: hashService.hash(numero, option),
        direccion: hashService.hash(direccion, option)
      };

      res.json({
        mensaje: `Hash generado con éxito usando ${option.toUpperCase()}`,
        resultado
      });
      break;

    default:
      res.status(400).json({ error: 'Tipo de cifrado no soportado' });
  }
});

module.exports = app;

