const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
const { JWT_SECRET } = require('../middleware/auth');

const router = express.Router();

// Register: Create tenant + user
router.post('/register', async (req, res) => {
  try {
    const { tenantName, email, password, name } = req.body;

    if (!tenantName || !email || !password || !name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 10);

    // Create tenant
    const tenantRes = await pool.query(
      'INSERT INTO public.tenants (name, subscription_plan) VALUES ($1, $2) RETURNING id',
      [tenantName, 'free']
    );
    const tenantId = tenantRes.rows[0].id;

    // Create user as tenant_admin
    const userRes = await pool.query(
      'INSERT INTO public.users (tenant_id, name, email, password_hash, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, role, tenant_id',
      [tenantId, name, email, hashedPassword, 'tenant_admin']
    );
    const user = userRes.rows[0];

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, tenant_id: user.tenant_id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ message: 'Registered successfully', token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const userRes = await pool.query(
      'SELECT id, email, password_hash, name, role, tenant_id FROM public.users WHERE email = $1',
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = userRes.rows[0];
    const isPasswordValid = await bcryptjs.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, tenant_id: user.tenant_id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ message: 'Logged in successfully', token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

module.exports = router;
