const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { cookieConfig } = require('../config/seguridad');
const { hashContrasena, verificarContrasena, registrarIntentoFallido, generarToken } = require('../utils/auth');
const { limitarIntentos } = require('../middleware/auth');
const xss = require('xss'); // Requerir la biblioteca xss

router.get('/registro', (req, res) => {
  res.render('registro');
});

router.post('/registro', (req, res) => {
  const correo = xss(req.body.correo); // Sanitizar entrada del correo
  const contrasena = xss(req.body.contrasena); // Sanitizar entrada de contraseña
  try {
    const hashContrasenaSegura = hashContrasena(contrasena);
    db.run(
      'INSERT INTO usuarios (correo, contrasena) VALUES (?, ?)',
      [correo, hashContrasenaSegura],
      (err) => {
        if (err) {
          res.status(400).send('Error en el registro');
        } else {
          res.redirect('/iniciar-sesion');
        }
      }
    );
  } catch (error) {
    res.status(500).send('Error en el servidor');
  }
});

router.get('/iniciar-sesion', (req, res) => {
  res.render('iniciar-sesion');
});

router.post('/iniciar-sesion', limitarIntentos, (req, res) => {
  const correo = xss(req.body.correo); // Sanitizar entrada del correo
  const contrasena = xss(req.body.contrasena); // Sanitizar entrada de contraseña
  db.get('SELECT * FROM usuarios WHERE correo = ?', [correo], (err, usuario) => {
    if (err || !usuario) {
      registrarIntentoFallido(correo, req.ip);
      return res.status(400).send('Usuario no encontrado');
    }

    if (verificarContrasena(contrasena, usuario.contrasena)) {
      const token = generarToken(usuario);
      res.cookie('token', token, cookieConfig);
      res.redirect('/panel');
    } else {
      registrarIntentoFallido(correo, req.ip);
      res.status(400).send('Contraseña incorrecta');
    }
  });
});

router.post('/cerrar-sesion', (req, res) => {
  res.clearCookie('token', cookieConfig);
  req.session.destroy();
  res.redirect('/iniciar-sesion');
});

module.exports = router;