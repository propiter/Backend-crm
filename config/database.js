import sql from 'mssql';
import dotenv from 'dotenv';

dotenv.config();

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER, // Ahora solo "localhost"
  port: parseInt(process.env.DB_PORT), // Convertir el puerto a número
  database: process.env.DB_NAME,
  options: {
    encrypt: false,
    trustServerCertificate: true
  }
};

export async function connectDB() {
  try {
    const pool = await sql.connect(dbConfig);
    console.log('Conectado a SQL Server');
    return pool;
  } catch (error) {
    console.error('Error de conexión a SQL Server:', error);
    throw error;
  }
}