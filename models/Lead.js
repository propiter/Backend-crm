import sql from 'mssql';
import { connectDB } from '../config/database.js';

export async function createLead(leadData) {
  try {
    const pool = await connectDB();
    const result = await pool.request()
      .input('nombre', sql.NVarChar, leadData.nombre)
      .input('telefono', sql.NVarChar, leadData.telefono)
      .input('email', sql.NVarChar, leadData.email)
      .input('empresa', sql.NVarChar, leadData.empresa)
      .input('origen', sql.NVarChar, leadData.origen)
      .input('destino', sql.NVarChar, leadData.destino)
      .input('fecha', sql.Date, new Date(leadData.fecha))
      .input('hora', sql.NVarChar, leadData.hora)
      .input('pasajeros', sql.Int, leadData.pasajeros)
      .input('tipoVehiculo', sql.NVarChar, leadData.tipoVehiculo)
      .input('tipoServicio', sql.NVarChar, leadData.tipoServicio)
      .input('esperaEnDestino', sql.Bit, leadData.esperaEnDestino)
      .input('requisitos', sql.NVarChar, leadData.requisitos)
      .input('etapa', sql.NVarChar, 'Sin contactar')
      .query(`
        INSERT INTO Leads (
          nombre, telefono, email, empresa, origen, destino,
          fecha, hora, pasajeros, tipoVehiculo, tipoServicio,
          esperaEnDestino, requisitos, etapa
        )
        VALUES (
          @nombre, @telefono, @email, @empresa, @origen, @destino,
          @fecha, @hora, @pasajeros, @tipoVehiculo, @tipoServicio,
          @esperaEnDestino, @requisitos, @etapa
        )
      `);
    return result;
  } catch (error) {
    console.error('Error al crear lead:', error);
    throw error;
  }
}

export async function getLeads() {
  try {
    const pool = await connectDB();
    const result = await pool.request()
      .query('SELECT * FROM Leads ORDER BY fecha DESC');
    return result.recordset;
  } catch (error) {
    console.error('Error al obtener leads:', error);
    throw error;
  }
}

export async function updateLeadStage(leadId, newStage) {
  try {
    const pool = await connectDB();
    const result = await pool.request()
      .input('id', sql.Int, leadId)
      .input('etapa', sql.NVarChar, newStage)
      .query('UPDATE Leads SET etapa = @etapa WHERE id = @id');
    return result;
  } catch (error) {
    console.error('Error al actualizar etapa del lead:', error);
    throw error;
  }
}

export async function updateLead(id, leadData) {
  try {
    const pool = await connectDB();
    const request = pool.request().input('id', sql.Int, id);

    // Definición de tipos exactamente igual que en createLead
    const fieldTypes = {
      nombre: { type: sql.NVarChar, value: leadData.nombre },
      telefono: { type: sql.NVarChar, value: leadData.telefono },
      email: { type: sql.NVarChar, value: leadData.email },
      empresa: { type: sql.NVarChar, value: leadData.empresa },
      origen: { type: sql.NVarChar, value: leadData.origen },
      destino: { type: sql.NVarChar, value: leadData.destino },
      fecha: { type: sql.Date, value: leadData.fecha ? new Date(leadData.fecha) : null },
      hora: { type: sql.NVarChar, value: leadData.hora },
      pasajeros: { type: sql.Int, value: leadData.pasajeros },
      tipoVehiculo: { type: sql.NVarChar, value: leadData.tipoVehiculo },
      tipoServicio: { type: sql.NVarChar, value: leadData.tipoServicio },
      esperaEnDestino: { type: sql.Bit, value: leadData.esperaEnDestino },
      requisitos: { type: sql.NVarChar, value: leadData.requisitos },
      etapa: { type: sql.NVarChar, value: leadData.etapa },
      costo: { type: sql.Decimal(18,2), value: leadData.costo },
      precioVenta: { type: sql.Decimal(18,2), value: leadData.precioVenta }
    };

    // Construye dinámicamente la consulta SET
    let querySet = [];
    Object.entries(fieldTypes).forEach(([key, field]) => {
      // Solo incluye el campo si existe en leadData
      if (leadData.hasOwnProperty(key)) {
        querySet.push(`${key} = @${key}`);
        request.input(key, field.type, field.value);
      }
    });

    if (querySet.length === 0) {
      throw new Error('No se proporcionaron campos para actualizar');
    }

    const query = `UPDATE Leads SET ${querySet.join(', ')} WHERE id = @id`;
    console.log('Query:', query); // Para debugging
    const result = await request.query(query);

    return result;
  } catch (error) {
    console.error('Error al actualizar lead:', error);
    throw error;
  }
}