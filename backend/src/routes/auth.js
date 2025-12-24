const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
const { JWT_SECRET, authenticateToken } = require('../middleware/auth');

const router = express.Router();

/**
 * API 1: Tenant Registration
 * Requirement: Uses a database transaction for atomic creation of tenant and admin user.
 */
router.post('/register-tenant', async (req, res) => {
  const client = await pool.connect();
  try {
    const { tenantName, subdomain, adminEmail, adminPassword, adminFullName } = req.body;

    if (!tenantName || !subdomain || !adminEmail || !adminPassword || !adminFullName) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    await client.query('BEGIN'); // Start transaction

    // Create tenant with default 'free' plan limits
    const tenantRes = await client.query(
      'INSERT INTO public.tenants (name, subdomain, subscription_plan, max_users, max_projects) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [tenantName, subdomain, 'free', 5, 3]
    );
    const tenantId = tenantRes.rows[0].id;

    // Hash password and create admin user
    const hashedPassword = await bcryptjs.hash(adminPassword, 10);
    const userRes = await client.query(
      'INSERT INTO public.users (tenant_id, email, password_hash, full_name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, full_name, role, tenant_id',
      [tenantId, adminEmail, hashedPassword, adminFullName, 'tenant_admin']
    );

    await client.query('COMMIT'); // Commit both operations

    const user = userRes.rows[0];
    res.status(201).json({
      success: true,
      message: 'Tenant registered successfully',
      data: {
        tenantId: tenantId,
        subdomain: subdomain,
        adminUser: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          role: user.role
        }
      }
    });
  } catch (err) {
    await client.query('ROLLBACK'); // Rollback on any failure
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ success: false, message: 'Subdomain or email already exists' });
    }
    res.status(500).json({ success: false, message: 'Registration failed' });
  } finally {
    client.release();
  }
});

/**
 * API 2: User Login
 * Requirement: Includes tenant identification via subdomain and JWT generation.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password, tenantSubdomain } = req.body;

    if (!email || !password || !tenantSubdomain) {
      return res.status(400).json({ success: false, message: 'Email, password, and subdomain required' });
    }

    // Verify tenant and user via JOIN to ensure data isolation
    const query = `
      SELECT u.*, t.status as tenant_status 
      FROM public.users u 
      JOIN public.tenants t ON u.tenant_id = t.id 
      WHERE u.email = $1 AND t.subdomain = $2
    `;
    const userRes = await pool.query(query, [email, tenantSubdomain]);

    if (userRes.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = userRes.rows[0];

    // Verify tenant is active before allowing login
    if (user.tenant_status !== 'active') {
      return res.status(403).json({ success: false, message: 'Account suspended or inactive' });
    }

    const isPasswordValid = await bcryptjs.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate JWT containing userId, tenantId, and role
    const token = jwt.sign(
      { id: user.id, tenant_id: user.tenant_id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          role: user.role,
          tenantId: user.tenant_id
        },
        token,
        expiresIn: 86400
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

/**
 * API 3: Get Current User
 * Requirement: Returns authenticated user info and tenant details.
 */
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT u.id, u.email, u.full_name, u.role, u.is_active,
             t.id as tenant_id, t.name as tenant_name, t.subdomain, t.subscription_plan, t.max_users, t.max_projects
      FROM public.users u
      LEFT JOIN public.tenants t ON u.tenant_id = t.id
      WHERE u.id = $1
    `;
    const userRes = await pool.query(query, [req.user.id]);

    if (userRes.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const row = userRes.rows[0];
    res.json({
      success: true,
      data: {
        id: row.id,
        email: row.email,
        fullName: row.full_name,
        role: row.role,
        isActive: row.is_active,
        tenant: row.tenant_id ? {
          id: row.tenant_id,
          name: row.tenant_name,
          subdomain: row.subdomain,
          subscriptionPlan: row.subscription_plan,
          maxUsers: row.max_users,
          maxProjects: row.max_projects
        } : null
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch user data' });
  }
});

module.exports = router;
