const express = require('express');
const cors = require('cors'); // Importa el paquete cors
const rateLimit = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();

// Configura CORS para permitir solicitudes desde http://localhost:3000
app.use(cors({
  origin: 'http://localhost:3000', // Permite solo este origen
  methods: ['GET', 'POST'], // Métodos permitidos
  allowedHeaders: ['Content-Type'], // Encabezados permitidos
}));

app.use(express.json());
app.use(rateLimit); // Aplica Rate Limit globalmente
app.use('/api', authRoutes);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Servidor 1 corriendo en puerto ${PORT}`));