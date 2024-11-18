import express from 'express';
import { auth } from '../middleware/auth.js';
import { createLead, getLeads, updateLeadStage, updateLead } from '../models/Lead.js';

const router = express.Router();

router.post('/', async (req, res) => {
  try {
    const lead = await createLead(req.body);
    res.status(201).json(lead);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.get('/', auth, async (req, res) => {
  try {
    const leads = await getLeads();
    res.json(leads);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.patch('/stage/:id/', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { stage } = req.body;
    const result = await updateLeadStage(id, stage);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.patch('/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const leadData = req.body; // Recibe los datos actualizados del modal
    const result = await updateLead(id, leadData);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


export default router;