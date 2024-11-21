const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('baseDatos.sqlite', (err) => {
  if (err) {
    console.error('Error conectando a la base de datos:', err);
  } else {
    console.log('Conexión exitosa a SQLite');
  }
});

// Inicializar tablas
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correo TEXT UNIQUE,
    contrasena TEXT,
    rol TEXT DEFAULT 'usuario',
    ultima_sesion DATETIME
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS intentos_fallidos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correo TEXT,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip TEXT
  )`);
});

module.exports = db;