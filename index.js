const express = require('express');
const cors = require('cors');  // Importar el middleware de CORS
const app = express();
const bodyParser = require('body-parser');
const asimetricoService = require('./services/Asimetrico_model');
const simetricoService = require('./services/Simetrico_model');
const hashService = require('./services/hash_model');

let privateKey;  // Variable para almacenar la clave privada del servidor

// Habilitar CORS para todas las rutas
app.use(cors());

// Configuración para manejar JSON y formularios
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Ruta para generar y devolver la clave pública
app.get('/generate-keys', (req, res) => {
    const { publicKey, privateKey: privKey } = asimetricoService.generateKeyPair();
    privateKey = privKey; // Almacenar la clave privada en el servidor

    res.json({
        publicKey: publicKey,  // Devolver la clave pública al cliente
        mensaje: "Clave pública generada con éxito."
    });
});

// Ruta principal para recibir los datos y decidir el tipo de cifrado
app.post('/procesar', (req, res) => {
    const { usuario, password, correo, numero, direccion, option, userKey } = req.body;

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
            // Verificamos si la clave privada está generada
            if (!privateKey) {
                return res.status(500).json({ error: 'La clave privada no está disponible. Genera primero las claves.' });
            }

            // El cliente envía los datos cifrados con la clave pública que recibió antes
            const encryptedData = {
                usuario: req.body.usuario,
                correo: req.body.correo,
                password: req.body.password,
                numero: req.body.numero,
                direccion: req.body.direccion
            };

            // Descifrar los datos con la clave privada del servidor
            const resultado = {
                usuario: asimetricoService.decryptMessage(encryptedData.usuario, privateKey),
                correo: asimetricoService.decryptMessage(encryptedData.correo, privateKey),
                password: asimetricoService.decryptMessage(encryptedData.password, privateKey),
                numero: asimetricoService.decryptMessage(encryptedData.numero, privateKey),
                direccion: asimetricoService.decryptMessage(encryptedData.direccion, privateKey)
            };

            res.json({
                mensaje: 'Datos descifrados con éxito usando cifrado asimétrico (ECC)',
                resultado
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


