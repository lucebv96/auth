const jwt = require('jsonwebtoken');
const { claveSecreta, cookieConfig } = require('../config/seguridad');
const db = require('../config/database');

const verificarToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/iniciar-sesion');
  }
  try {
    const decodificado = jwt.verify(token, claveSecreta);
    req.usuario = decodificado;
    
    db.run('UPDATE usuarios SET ultima_sesion = CURRENT_TIMESTAMP WHERE id = ?', [decodificado.id]);
    
    next();
  } catch (error) {
    res.clearCookie('token', cookieConfig);
    res.redirect('/iniciar-sesion');
  }
};

const verificarAdmin = (req, res, next) => {
  if (req.usuario && req.usuario.rol === 'admin') {
    next();
  } else {
    res.status(403).send('Acceso denegado');
  }
};

const limitarIntentos = (req, res, next) => {
  const correo = req.body.correo;
  const ip = req.ip;
  
  db.get(
    'SELECT COUNT(*) as intentos FROM intentos_fallidos WHERE correo = ? AND fecha > datetime("now", "-15 minutes") AND ip = ?',
    [correo, ip],
    (err, row) => {
      if (err) {
        return res.status(500).send('Error del servidor');
      }
      
      if (row.intentos >= 5) {
        return res.status(429).send('Demasiados intentos fallidos. Intente nuevamente en 15 minutos.');
      }
      
      next();
    }
  );
};

module.exports = {
  verificarToken,
  verificarAdmin,
  limitarIntentos
};