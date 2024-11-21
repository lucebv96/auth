const crypto = require('crypto');

const claveSecreta = crypto.randomBytes(32).toString('hex');

const cookieConfig = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000,
  path: '/',
};

const sessionConfig = {
  secret: claveSecreta,
  name: 'sessionId',
  cookie: cookieConfig,
  resave: false,
  saveUninitialized: false,
  rolling: true,
};

module.exports = {
  claveSecreta,
  cookieConfig,
  sessionConfig
};