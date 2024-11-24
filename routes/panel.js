const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { verificarToken, verificarAdmin } = require('../middleware/auth');
const xss = require('xss');


router.get('/panel', verificarToken, (req, res) => {
  const usuario = { ...req.usuario };
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

router.delete('/admin/usuarios', verificarToken, verificarAdmin, (req, res) => {
  const { correo } = req.body;
  if (!correo) {
    return res.status(400).send('Correo requerido para eliminar usuario.');
  }

  db.run('DELETE FROM usuarios WHERE correo = ?', [correo], (err) => {
    if (err) {
      return res.status(500).send('Error al eliminar usuario.');
    }
    res.send('Usuario eliminado con éxito.');
  });
});


router.get('/admin/intentos-fallidos', verificarToken, verificarAdmin, (req, res) => {
  db.all('SELECT * FROM intentos_fallidos ORDER BY fecha DESC', (err, intentos) => {
    if (err) {
      return res.status(500).send('Error al recuperar intentos fallidos.');
    }
    res.json(intentos);
  });
});


router.get('/admin/intentos-fallidos-vista', verificarToken, verificarAdmin, (req, res) => {
  db.all('SELECT * FROM intentos_fallidos ORDER BY fecha DESC', (err, intentos) => {
    if (err) {
      return res.status(500).send('Error al recuperar intentos fallidos.');
    }
    res.render('admin-intentos', { intentos });
  });
});

router.get('/admin/eliminar-usuarios', verificarToken, verificarAdmin, (req, res) => {
  res.render('admin-eliminar-usuarios');
});


module.exports = router;