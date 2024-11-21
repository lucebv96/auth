//Archivo para generar contrasena hasheadas para admi

const { hashContrasena } = require('./utils/auth'); // Ruta del hash

const contrasena = 'admi'; 
const hash = hashContrasena(contrasena);

console.log(`Hash generado: ${hash}`);
