const express = require('express');
const pool = require('../config/db');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

/**
 * API 5: Get Tenant Details
 * Requirement: User must belong to this tenant OR be super_admin.
 */
router.get('/:tenantId', authenticateToken, async (req, res) => {
  try {
    const { tenantId } = req.params;

    // Authorization check
    if (req.user.role !== 'super_admin' && req.user.tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access to this tenant' });
    }

    const tenantQuery = `
      SELECT id, name, subdomain, status, subscription_plan, max_users, max_projects, created_at
      FROM public.tenants WHERE id = $1
    `;
    const tenantRes = await pool.query(tenantQuery, [tenantId]);

    if (tenantRes.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Tenant not found' });
    }

    // Calculate Stats
    const userCount = await pool.query('SELECT COUNT(*) FROM public.users WHERE tenant_id = $1', [tenantId]);
    const projectCount = await pool.query('SELECT COUNT(*) FROM public.projects WHERE tenant_id = $1', [tenantId]);

    const tenant = tenantRes.rows[0];
    res.json({
      success: true,
      data: {
        ...tenant,
        stats: {
          totalUsers: parseInt(userCount.rows[0].count),
          totalProjects: parseInt(projectCount.rows[0].count)
        }
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/**
 * API 6: Update Tenant
 * Requirement: tenant_admin (name only) OR super_admin (all fields).
 */
router.put('/:tenantId', authenticateToken, authorizeRoles('tenant_admin', 'super_admin'), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { name, status, subscriptionPlan, maxUsers, maxProjects } = req.body;

    // Ensure tenant_admin only updates their own tenant
    if (req.user.role === 'tenant_admin' && req.user.tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    let query;
    let params;

    if (req.user.role === 'super_admin') {
      query = `
        UPDATE public.tenants 
        SET name = COALESCE($1, name), status = COALESCE($2, status), 
            subscription_plan = COALESCE($3, subscription_plan), max_users = COALESCE($4, max_users), 
            max_projects = COALESCE($5, max_projects), updated_at = CURRENT_TIMESTAMP
        WHERE id = $6 RETURNING *`;
      params = [name, status, subscriptionPlan, maxUsers, maxProjects, tenantId];
    } else {
      // tenant_admin can only update name
      query = `UPDATE public.tenants SET name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`;
      params = [name, tenantId];
    }

    const result = await pool.query(query, params);
    res.json({ success: true, message: 'Tenant updated successfully', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

/**
 * API 7: List All Tenants
 * Requirement: super_admin ONLY. Includes pagination and filters.
 */
router.get('/', authenticateToken, authorizeRoles('super_admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const query = `
      SELECT t.*, 
      (SELECT COUNT(*) FROM public.users WHERE tenant_id = t.id) as total_users
      FROM public.tenants t
      ORDER BY t.created_at DESC
      LIMIT $1 OFFSET $2
    `;
    const result = await pool.query(query, [limit, offset]);
    const totalCount = await pool.query('SELECT COUNT(*) FROM public.tenants');

    res.json({
      success: true,
      data: {
        tenants: result.rows,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalCount.rows[0].count / limit),
          totalTenants: parseInt(totalCount.rows[0].count)
        }
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
