const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy'); // Importa speakeasy
const { saveLog } = require('../models/log');
const db = require('../config/firebase');
require('dotenv').config();

const router = express.Router();

// API getInfo (GET)
router.get('/getInfo', async (req, res) => {
  try {
    await saveLog('info', 'Solicitud a getInfo', { nodeVersion: process.version });
    res.json({
      nodeVersion: process.version,
      student: {
        name: 'Ariadna Vanessa López Gómez',
        group: 'IDGS11',
      },
    });
  } catch (error) {
    console.error('Error en getInfo:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Register (POST)
router.post('/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password || !/\S+@\S+\.\S+/.test(email)) {
    await saveLog('error', 'Registro fallido', { reason: 'Datos inválidos' });
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  try {
    // Verifica si el usuario ya existe
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (!userSnapshot.empty) {
      await saveLog('error', 'Registro fallido', { reason: 'Usuario ya existe' });
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    // Genera un secreto para TOTP
    const secret = speakeasy.generateSecret({
      name: `AriadnaApp:${email}`, // Nombre que aparecerá en Google Authenticator
    });

    // Hashea la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Guarda el usuario con el secreto
    await db.collection('users').add({
      email,
      username,
      password: hashedPassword,
      otpSecret: secret.base32, // Guarda el secreto en base32
    });

    await saveLog('info', 'Usuario registrado', { email, username });
    res.status(201).json({
      message: 'Usuario registrado',
      secret: secret.base32, // Devuelve el secreto para generar el QR en el frontend
      otpauthUrl: secret.otpauth_url, // URL para el código QR
    });
  } catch (error) {
    console.error('Error en register:', error);
    await saveLog('error', 'Error al registrar usuario', { error: error.message });
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Login (POST)
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      await saveLog('error', 'Login fallido', { reason: 'Usuario no encontrado' });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = userSnapshot.docs[0].data();
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      await saveLog('error', 'Login fallido', { reason: 'Contraseña incorrecta' });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    await saveLog('info', 'Credenciales verificadas, esperando OTP', { email });
    res.json({ message: 'Ingresa el código OTP de Google Authenticator' });
  } catch (error) {
    console.error('Error en login:', error);
    await saveLog('error', 'Error al procesar login', { error: error.message });
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Verificar OTP y generar JWT
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      await saveLog('error', 'Verificación OTP fallida', { reason: 'Usuario no encontrado' });
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const user = userSnapshot.docs[0].data();
    const secret = user.otpSecret;

    // Verifica el código OTP
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: otp,
      window: 1, // Tolerancia de 1 intervalo (30 segundos)
    });

    if (!verified) {
      await saveLog('error', 'Verificación OTP fallida', { email });
      return res.status(401).json({ error: 'Código OTP inválido' });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await saveLog('info', 'Login exitoso', { email });
    res.json({ token });
  } catch (error) {
    console.error('Error en verify-otp:', error);
    await saveLog('error', 'Error al verificar OTP', { error: error.message });
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;