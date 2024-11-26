const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { claveSecreta } = require('../config/seguridad');
const db = require('../config/database');

function hashContrasena(contrasena) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(contrasena, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verificarContrasena(contrasena, hashAlmacenado) {
  const [salt, hash] = hashAlmacenado.split(':');
  const hashVerificacion = crypto.pbkdf2Sync(contrasena, salt, 1000, 64, 'sha512').toString('hex');
  return hash === hashVerificacion;
}

function registrarIntentoFallido(correo, ip) {
  db.run(
    'INSERT INTO intentos_fallidos (correo, ip) VALUES (?, ?)',
    [correo, ip]
  );
}


function cifrarCorreo(correo) {
  const iv = Buffer.alloc(16, 0); // Vector de inicialización (16 bytes de ceros)
  const cipher = crypto.createCipheriv('aes-256-cbc', claveSecreta.slice(0, 32), iv);
  const correoCifrado = cipher.update(correo, 'utf8', 'hex') + cipher.final('hex');
  return correoCifrado;
}

function generarToken(usuario) {
  const correoCifrado = cifrarCorreo(usuario.correo); // Cifrar el correo antes de incluirlo en el token
  //console.log('Correo original:', usuario.correo);
  //console.log('Correo cifrado:', correoCifrado);

  return jwt.sign(
    {
      id: usuario.id,
      correo: correoCifrado, // Guardar correo cifrado
      rol: usuario.rol
    },
    claveSecreta,
    { expiresIn: '1h' }
  );
}


module.exports = {
  hashContrasena,
  verificarContrasena,
  registrarIntentoFallido,
  generarToken,
  cifrarCorreo
};