const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const { saveLog } = require('../models/log');
const db = require('../config/firebase');
const limiter = require('../middleware/rateLimit');
require('dotenv').config();

const router = express.Router();

// API getInfo (GET)
router.get('/getInfo', limiter, async (req, res) => {
  try {
    await saveLog('info', 'Solicitud a getInfo', { nodeVersion: process.version }, req);
    res.json({
      nodeVersion: process.version,
      student: {
        name: 'Ariadna Vanessa López Gómez',
        group: 'IDGS11',
      },
    });
  } catch (error) {
    console.error('Error en getInfo:', error);
    await saveLog('error', 'Error en getInfo', { error: error.message }, req);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Register (POST)
router.post('/register', limiter, async (req, res) => {
  const { email, username, password, grado, grupo } = req.body;

  if (!email || !username || !password || !grado || !grupo || !/\S+@\S+\.\S+/.test(email)) {
    await saveLog('error', 'Registro fallido', { reason: 'Datos inválidos' }, req);
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (!userSnapshot.empty) {
      await saveLog('error', 'Registro fallido', { reason: 'Usuario ya existe' }, req);
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const secret = speakeasy.generateSecret({
      name: `AriadnaApp:${email}`,
    });

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection('users').add({
      email,
      username,
      password: hashedPassword,
      grado,
      grupo,
      otpSecret: secret.base32,
    });

    await saveLog('info', 'Usuario registrado', { email, username }, req);
    res.status(201).json({
      message: 'Usuario registrado',
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
    });
  } catch (error) {
    console.error('Error en register:', error);
    await saveLog('error', 'Error al registrar usuario', { error: error.message }, req);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Login (POST)
router.post('/login', limiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      await saveLog('error', 'Login fallido', { reason: 'Usuario no encontrado' }, req);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = userSnapshot.docs[0].data();
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      await saveLog('error', 'Login fallido', { reason: 'Contraseña incorrecta' }, req);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    await saveLog('info', 'Credenciales verificadas, esperando OTP', { email }, req);
    res.json({ message: 'Ingresa el código OTP de Google Authenticator' });
  } catch (error) {
    console.error('Error en login:', error);
    await saveLog('error', 'Error al procesar login', { error: error.message }, req);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Verificar OTP y generar JWT
router.post('/verify-otp', limiter, async (req, res) => {
  const { email, otp } = req.body;

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      await saveLog('error', 'Verificación OTP fallida', { reason: 'Usuario no encontrado' }, req);
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const user = userSnapshot.docs[0].data();
    const secret = user.otpSecret;

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: otp,
      window: 1,
    });

    if (!verified) {
      await saveLog('error', 'Verificación OTP fallida', { email }, req);
      return res.status(401).json({ error: 'Código OTP inválido' });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await saveLog('info', 'Login exitoso', { email }, req);
    res.json({ token });
  } catch (error) {
    console.error('Error en verify-otp:', error);
    await saveLog('error', 'Error al verificar OTP', { error: error.message }, req);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Ruta para obtener logs (GET) - Ahora devuelve los logs completos
router.get('/logs', limiter, async (req, res) => {
  try {
    const logsSnapshot = await db.collection('logs')
      .orderBy('timestamp', 'desc')
      .get();

    const logs = logsSnapshot.docs.map(doc => {
      const logData = {
        id: doc.id,
        ...doc.data()
      };
      if (logData.body) {
        delete logData.body.password;
        delete logData.body.otp;
      }
      return logData;
    });

    const server1Logs = { info: 0, error: 0 };
    const server2Logs = { info: 0, error: 0 };

    logs.forEach(log => {
      if (log.server === 'Servidor 1') server1Logs[log.level]++;
      else if (log.server === 'Servidor 2') server2Logs[log.level]++;
    });

    // No registrar este evento como log
    res.json({
      server1: server1Logs,
      server2: server2Logs,
      totalLogs: logs.length,
      logs: logs
    });
  } catch (error) {
    console.error('Error al obtener logs:', error);
    await saveLog('error', 'Error al obtener logs', { error: error.message }, req);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;