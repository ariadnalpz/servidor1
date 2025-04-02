const db = require('../config/firebase');

const saveLog = async (level, message, details) => {
  try {
    await db.collection('logs').add({
      level, // Ejemplo: 'info', 'error'
      message,
      details,
      timestamp: new Date().toISOString(),
      server: 'Servidor 1',
    });
    console.log('Log guardado exitosamente:', { level, message });
  } catch (error) {
    console.error('Error al guardar log en Servidor 1:', error);
    throw error; // Opcional: lanza el error para manejarlo en la ruta
  }
};

module.exports = { saveLog };