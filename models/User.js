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

// Funcion para actualizar contraseña:
export async function updatePassword(username, oldPassword, newPassword) {
  try {
    const pool = await connectDB();

    // Obtener datos del usuario por nombre de usuario
    const result = await pool.request()
      .input('usuario', sql.NVarChar, username)
      .query('SELECT id, password FROM Usuarios WHERE usuario = @usuario');

    const user = result.recordset[0];
    if (!user) {
      throw new Error('Usuario no encontrado');
    }

    // Verificar si la contraseña anterior coincide
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      throw new Error('La contraseña anterior no es correcta');
    }

    // Generar el hash de la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 8);

    // Actualizar la contraseña
    const updateResult = await pool.request()
      .input('id', sql.Int, user.id)
      .input('password', sql.NVarChar, hashedPassword)
      .query('UPDATE Usuarios SET password = @password WHERE id = @id');

    return updateResult.rowsAffected[0] > 0
      ? { message: 'Contraseña actualizada exitosamente' }
      : { message: 'No se pudo actualizar la contraseña' };
  } catch (error) {
    console.error('Error al actualizar contraseña:', error);
    throw error;
  }
}