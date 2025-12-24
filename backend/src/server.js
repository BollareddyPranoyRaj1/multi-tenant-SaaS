const express = require('express');
const cors = require('cors');
const pool = require('./config/db');

// Route Imports
const authRoutes = require('./routes/auth');
const tenantRoutes = require('./routes/tenants');
const userRoutes = require('./routes/users');
const projectRoutes = require('./routes/projects');
const taskRoutes = require('./routes/tasks');

const app = express();

/**
 * CORS Configuration
 * Requirement: Allow requests from the frontend container/URL.
 */
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json());

/**
 * MANDATORY: Health Check Endpoint
 * Requirement: Returns status code 200 and system/DB status.
 * Used by automated evaluation scripts to verify the system is ready.
 */
app.get('/api/health', async (req, res) => {
  try {
    // Verify database connectivity
    await pool.query('SELECT 1');
    res.status(200).json({ 
      success: true, 
      status: "ok", 
      database: "connected" 
    });
  } catch (err) {
    res.status(500).json({ 
      success: false, 
      status: "error", 
      database: "disconnected" 
    });
  }
});

/**
 * API Route Registration
 * Requirement: Covers all 19 mandatory API endpoints.
 */
app.use('/api/auth', authRoutes);     // APIs 1-4: Registration, Login, Logout, Me
app.use('/api/tenants', tenantRoutes); // APIs 5-7: Tenant Management
app.use('/api/users', userRoutes);     // APIs 8-11: User Management
app.use('/api/projects', projectRoutes); // APIs 12-15: Project Management
app.use('/api/tasks', taskRoutes);       // APIs 16-19: Task Management

/**
 * Server Initialization
 * Port 5000 is mandatory for the backend service.
 */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
