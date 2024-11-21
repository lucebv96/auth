const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { verificarToken, verificarAdmin } = require('../middleware/auth');
const xss = require('xss');


router.get('/panel', verificarToken, (req, res) => {
  const usuario = { ...req.usuario, correo: xss(req.usuario.correo) }; // Sanitizar datos antes de renderizar
  res.render('panel', { usuario });
});


router.get('/admin', verificarToken, verificarAdmin, (req, res) => {
  db.all('SELECT id, correo, rol, ultima_sesion FROM usuarios', (err, usuarios) => {
    if (err) {
      return res.status(500).send('Error del servidor');
    }
    res.render('admin', { usuarios });
  });
});


router.post('/asignar-admin', verificarToken, verificarAdmin, (req, res) => {
  const { correo } = req.body;
  db.run(
    'UPDATE usuarios SET rol = "admin" WHERE correo = ?',
    [correo],
    (err) => {
      if (err) {
        return res.status(500).send('Error al actualizar el rol');
      }
      res.send('El usuario ahora es administrador');
    }
  );
});


module.exports = router;