const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');
const csrf = require('csurf');

const { claveSecreta, sessionConfig } = require('./config/seguridad');
const authRoutes = require('./routes/auth');
const panelRoutes = require('./routes/panel');

const app = express();
const puerto = 3000;

// Configuración
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser(claveSecreta));
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session(sessionConfig));

// Configurar csurf
const csrfProtection = csrf({ cookie: true }); // Genera tokens CSRF basados en cookies

// Excluir la ruta "/cerrar-sesion" del middleware CSRF
app.use((req, res, next) => {
  if (req.path === '/cerrar-sesion') {
    return next(); // Omitir CSRF para esta ruta
  }
  csrfProtection(req, res, next); // Aplicar CSRF para otras rutas
});

// Inyectar el token CSRF en las vistas y solicitudes
app.use((req, res, next) => {
  if (req.csrfToken) {
    res.locals.csrfToken = req.csrfToken(); // Token disponible en todas las vistas
  }
  next();
});

app.set('view engine', 'ejs');

// Rutas principales
app.get('/', (req, res) => {
  res.render('inicio');
});

// Rutas modulares
app.use('/', authRoutes);
app.use('/', panelRoutes);

// Manejo de errores CSRF
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).send('Solicitud no autorizada (CSRF inválido).');
  } else {
    next(err);
  }
});

app.listen(puerto, () => {
  console.log(`Servidor corriendo en http://localhost:${puerto}`);
});
