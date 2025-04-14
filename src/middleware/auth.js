const jwt = require('jsonwebtoken');
const { saveLog } = require('../models/log');
require('dotenv').config();

const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extrae el token del header "Bearer <token>"

  if (!token) {
    await saveLog('error', 'Acceso denegado', { reason: 'Token no proporcionado' });
    return res.status(401).json({ error: 'Acceso denegado: Token no proporcionado' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Guarda los datos decodificados del token en req.user
    next();
  } catch (error) {
    await saveLog('error', 'Token inválido', { error: error.message });
    return res.status(401).json({ error: 'Acceso denegado: Token inválido' });
  }
};

module.exports = verifyToken;