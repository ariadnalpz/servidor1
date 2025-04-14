const jwt = require('jsonwebtoken');
const { saveLog } = require('../models/log');
require('dotenv').config();

const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Obtiene el token del header "Bearer <token>"

  if (!token) {
    await saveLog('error', 'Acceso denegado', { reason: 'No se proporcionó token' });
    return res.status(401).json({ error: 'Acceso denegado: No se proporcionó token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Guarda la información del usuario decodificado (email) en req.user
    next();
  } catch (error) {
    console.error('Error al verificar token:', error);
    await saveLog('error', 'Token inválido', { error: error.message });
    res.status(401).json({ error: 'Token inválido' });
  }
};

module.exports = verifyToken;