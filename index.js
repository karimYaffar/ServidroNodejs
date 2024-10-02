const express = require('express');
const cors = require('cors');  // Importar el middleware de CORS
const app = express();
const bodyParser = require('body-parser');
const database = {};  // Simulación de base de datos en memoria

// Importar los servicios de cifrado
const simetricoService = require('./services/Simetrico_model');
const hashService = require('./services/hash_model');
const asimetricoService = require('./services/Asimetrico_model');

// Habilitar CORS para todas las rutas
app.use(cors());

// Configuración para manejar JSON y formularios
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Ruta principal para recibir los datos y decidir el tipo de cifrado
app.post('/procesar', (req, res) => {
  const { usuario, password, correo, numero, direccion, option, userKey } = req.body;

  const userId = userKey;
  let resultado;

  switch (option) {
    case 'simetric':
      if (userKey.length !== 16) {
        return res.status(400).json({ error: 'La clave debe tener 16 caracteres.' });
      }

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

   case 'asimetric':
    // Generar el par de claves pública y privada
    const { publicKey, privateKey } = asimetricoService.generateKeyPair();

    // Usamos la clave pública para cifrar los datos
    const resultado = {
        usuario: asimetricoService.encryptMessage(usuario, publicKey),
        correo: asimetricoService.encryptMessage(correo, publicKey),
        password: asimetricoService.encryptMessage(password, publicKey),
        numero: asimetricoService.encryptMessage(numero, publicKey),
        direccion: asimetricoService.encryptMessage(direccion, publicKey)
    };

    // Guardamos la clave privada en el servidor (en un futuro podrías almacenarla en un lugar seguro)
    // y devolvemos la clave pública al cliente
    res.json({
        mensaje: 'Datos encriptados con éxito usando cifrado asimétrico (ECC)',
        resultado,
        publicKey: publicKey // Devolvemos la clave pública al cliente
    });
    break;


    case 'sha224':
    case 'sha256':
    case 'sha384':
    case 'sha512':
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

// Obtener el puerto del entorno o usar el puerto 3000 por defecto
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;


