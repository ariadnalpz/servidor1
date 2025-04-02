const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');

// Inicializa Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Inicializa Firestore
const db = admin.firestore();

// Opcional: Configura ajustes de Firestore si es necesario
db.settings({ ignoreUndefinedProperties: true });

module.exports = db;