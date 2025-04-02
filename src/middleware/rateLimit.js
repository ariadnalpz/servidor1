const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutos
  max: 100, // Máximo 100 peticiones por IP
  message: 'Has excedido el límite de 100 peticiones en 10 minutos.',
});

module.exports = limiter;