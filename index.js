import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import leadsRoutes from './routes/leads.js';
import { connectDB } from './config/database.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Rutas
app.use('/api/auth', authRoutes);
app.use('/api/leads', leadsRoutes);

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

(async () => {
  try {
    await connectDB();
    app.listen(port, () => {
      console.log(`Servidor corriendo en puerto ${port}`);
    });
  } catch (error) {
    console.error('No se pudo iniciar el servidor:', error);
  }
})();