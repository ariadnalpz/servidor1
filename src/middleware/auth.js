const jwt = require('jsonwebtoken');
const { saveLog } = require('../models/log');
require('dotenv').config();

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    await saveLog('error', 'Acceso no autorizado', { reason: 'Token no proporcionado' });
    return res.status(401).json({ error: 'Acceso no autorizado: Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Guardamos la información decodificada del token (como el email)
    next();
  } catch (error) {
    await saveLog('error', 'Acceso no autorizado', { reason: 'Token inválido', error: error.message });
    return res.status(401).json({ error: 'Acceso no autorizado: Token inválido' });
  }
};

module.exports = verifyToken;