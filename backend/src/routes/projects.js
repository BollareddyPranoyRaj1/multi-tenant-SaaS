const express = require('express');
const pool = require('../config/db');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

/**
 * API 12: Create Project
 * Requirement: Enforces max_projects limit based on the tenant's plan.
 */
router.post('/', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user.tenant_id;
    const userId = req.user.id;
    const { name, description, status } = req.body;

    if (!name) {
      return res.status(400).json({ success: false, message: 'Project name is required' });
    }

    // 1. Check Subscription Limits
    const tenantRes = await pool.query('SELECT max_projects FROM tenants WHERE id = $1', [tenantId]);
    const currentProjectsRes = await pool.query('SELECT COUNT(*) FROM projects WHERE tenant_id = $1', [tenantId]);
    
    if (parseInt(currentProjectsRes.rows[0].count) >= tenantRes.rows[0].max_projects) {
      return res.status(403).json({ success: false, message: 'Subscription limit reached: Maximum projects exceeded' });
    }

    // 2. Create Project
    const newProject = await pool.query(
      'INSERT INTO projects (tenant_id, name, description, status, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [tenantId, name, description, status || 'active', userId]
    );

    res.status(201).json({ success: true, data: newProject.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to create project' });
  }
});

/**
 * API 13: List Projects
 * Requirement: Filtered by tenantId. Includes task counts.
 */
router.get('/', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user.tenant_id;

    const query = `
      SELECT p.*, 
             u.full_name as creator_name,
             (SELECT COUNT(*) FROM tasks WHERE project_id = p.id) as task_count
      FROM projects p
      JOIN users u ON p.created_by = u.id
      WHERE p.tenant_id = $1
      ORDER BY p.created_at DESC
    `;
    const projects = await pool.query(query, [tenantId]);

    res.json({ success: true, data: { projects: projects.rows } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/**
 * API 15: Delete Project
 * Requirement: tenant_admin OR project creator only.
 */
router.delete('/:projectId', authenticateToken, async (req, res) => {
  try {
    const { projectId } = req.params;
    const tenantId = req.user.tenant_id;

    // Verify ownership/role
    const projectCheck = await pool.query('SELECT created_by FROM projects WHERE id = $1 AND tenant_id = $2', [projectId, tenantId]);
    
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    if (req.user.role !== 'tenant_admin' && projectCheck.rows[0].created_by !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized to delete this project' });
    }

    await pool.query('DELETE FROM projects WHERE id = $1', [projectId]);
    res.json({ success: true, message: 'Project deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

module.exports = router;
