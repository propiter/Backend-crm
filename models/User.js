import sql from 'mssql';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { connectDB } from '../config/database.js';

export async function createUser(userData) {
  try {
    const pool = await connectDB();
    const hashedPassword = await bcrypt.hash(userData.password, 8);
    
    const result = await pool.request()
      .input('usuario', sql.NVarChar, userData.usuario)
      .input('password', sql.NVarChar, hashedPassword)
      .input('nombre', sql.NVarChar, userData.nombre)
      .input('rol', sql.NVarChar, userData.rol)
      .query(`
        INSERT INTO Usuarios (usuario, password, nombre, rol)
        VALUES (@usuario, @password, @nombre, @rol)
      `);
    return result;
  } catch (error) {
    console.error('Error al crear usuario:', error);
    throw error;
  }
}

export async function findUserByCredentials(username, password) {
  try {
    const pool = await connectDB();
    const result = await pool.request()
      .input('usuario', sql.NVarChar, username)
      .query('SELECT * FROM Usuarios WHERE usuario = @usuario');
    
    const user = result.recordset[0];
    if (!user) {
      throw new Error('Usuario no encontrado');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Contraseña incorrecta');
    }

    const token = jwt.sign(
      { id: user.id, username: user.usuario, role: user.rol },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    return { user, token };
  } catch (error) {
    console.error('Error en autenticación:', error);
    throw error;
  }
}