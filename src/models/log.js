const db = require('../config/firebase');

// Función para guardar logs enriquecidos
const saveLog = async (level, message, details = {}, req = null) => {
  try {
    // Datos básicos del log
    const logData = {
      level, // 'info' o 'error'
      message,
      timestamp: new Date().toISOString(),
      server: 'Servidor 1', // Identificador del servidor
      details: { ...details }, // Detalles adicionales proporcionados
    };

    // Si se pasa un objeto `req`, enriquecer con datos de la solicitud
    if (req) {
      logData.method = req.method;
      logData.url = req.url;
      logData.ip = req.ip || req.connection.remoteAddress;
      logData.userAgent = req.get('User-Agent') || 'Desconocido';
      logData.body = req.body ? { ...req.body } : {}; // Copia superficial del body
    }

    // Guardar en Firestore
    await db.collection('logs').add(logData);

    // Registro en consola para depuración
    console.log(`[${logData.timestamp}] ${level.toUpperCase()} - ${message}`, {
      server: logData.server,
      method: logData.method,
      url: logData.url,
      details: logData.details,
    });

    return logData; // Opcional: devolver el log creado
  } catch (error) {
    console.error(`[${new Date().toISOString()}] ERROR - Error al guardar log en ${logData.server}:`, error);
    throw error; // Propagamos el error para manejarlo en las rutas
  }
};

module.exports = { saveLog };