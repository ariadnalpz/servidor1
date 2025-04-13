const rateLimit = require('express-rate-limit');
const { saveLog } = require('../models/log');

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutos
  max: 100, // Máximo 100 peticiones por IP
  handler: async (req, res, next) => {
    try {
      // Log del exceso de solicitudes
      await saveLog('info', 'Límite de solicitudes excedido', {
        ip: req.ip,
        method: req.method,
        url: req.url,
      });

      // Devuelve un error 429 al frontend
      res.status(429).json({
        error: 'Has excedido el límite de 100 peticiones en 10 minutos.',
        retryAfter: 10, // Tiempo en segundos antes de que se restablezca el límite
      });
    } catch (error) {
      console.error('Error en rateLimit handler:', error.message);
      await saveLog('error', 'Error en rateLimit handler', {
        error: error.message,
        ip: req.ip,
        method: req.method,
        url: req.url,
      });
      res.status(500).json({
        error: 'Error interno del servidor',
      });
    }
  },
});

module.exports = limiter;