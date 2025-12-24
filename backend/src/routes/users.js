const express = require('express');
const bcryptjs = require('bcryptjs');
const pool = require('../config/db');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

/**
 * API 8: Add User to Tenant
 * Requirement: Enforces max_users limit based on the tenant's subscription plan.
 */
router.post('/tenants/:tenantId/users', authenticateToken, authorizeRoles('tenant_admin'), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { email, password, fullName, role } = req.body;

    // Security: Ensure tenant_admin only adds users to their own tenant
    if (req.user.tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    // 1. Check Subscription Limits
    const tenantRes = await pool.query('SELECT max_users FROM tenants WHERE id = $1', [tenantId]);
    const currentUsersRes = await pool.query('SELECT COUNT(*) FROM users WHERE tenant_id = $1', [tenantId]);
    
    if (parseInt(currentUsersRes.rows[0].count) >= tenantRes.rows[0].max_users) {
      return res.status(403).json({ success: false, message: 'Subscription limit reached: Maximum users exceeded' });
    }

    // 2. Hash password and insert user
    const hashedPassword = await bcryptjs.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (tenant_id, email, password_hash, full_name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, full_name, role',
      [tenantId, email, hashedPassword, fullName, role || 'user']
    );

    res.status(201).json({ success: true, message: 'User created successfully', data: newUser.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, message: 'Email already exists in this organization' });
    }
    res.status(500).json({ success: false, message: 'Failed to create user' });
  }
});

/**
 * API 9: List Tenant Users
 * Requirement: Filtered by tenantId to ensure data isolation.
 */
router.get('/tenants/:tenantId/users', authenticateToken, async (req, res) => {
  try {
    const { tenantId } = req.params;

    if (req.user.role !== 'super_admin' && req.user.tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const users = await pool.query(
      'SELECT id, email, full_name, role, is_active, created_at FROM users WHERE tenant_id = $1 ORDER BY created_at DESC',
      [tenantId]
    );

    res.json({ success: true, data: { users: users.rows } });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/**
 * API 11: Delete User
 * Requirement: tenant_admin cannot delete themselves.
 */
router.delete('/:userId', authenticateToken, authorizeRoles('tenant_admin'), async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user.id === userId) {
      return res.status(403).json({ success: false, message: 'Cannot delete yourself' });
    }

    const result = await pool.query('DELETE FROM users WHERE id = $1 AND tenant_id = $2', [userId, req.user.tenant_id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

module.exports = router;
