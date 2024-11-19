import express from 'express';
import { createUser, findUserByCredentials, updatePassword } from '../models/User.js';

const router = express.Router();

// Registro de usuario
router.post('/register', async (req, res) => {
  try {
    const { usuario, password, nombre, rol } = req.body;

    if (!usuario || !password || !nombre || !rol) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    await createUser({ usuario, password, nombre, rol });
    res.status(201).json({ message: 'Usuario creado exitosamente' });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Iniciar Sesion 
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { user, token } = await findUserByCredentials(username, password);
    res.json({ user, token });
  } catch (error) {
    res.status(401).json({ error: 'Credenciales inválidas' });
  }
});


// Actualizar contraseña
router.patch('/password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;

  if (!username || !oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Usuario, contraseña anterior y nueva son requeridos' });
  }

  try {
    const result = await updatePassword(username, oldPassword, newPassword);
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;