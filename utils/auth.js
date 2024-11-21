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

function generarToken(usuario) {
  return jwt.sign(
    { 
      id: usuario.id, 
      correo: usuario.correo, 
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
  generarToken
};