import React, { useState, useContext, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { projectService } from '../services/api';
import { AuthContext } from '../context/AuthContext';

export default function Dashboard() {
  const [projects, setProjects] = useState([]);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDesc, setNewProjectDesc] = useState('');
  const { user, logout } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      const res = await projectService.getAll();
      setProjects(res.data);
    } catch (err) {
      console.error('Failed to fetch projects', err);
    }
  };

  const handleCreateProject = async (e) => {
    e.preventDefault();
    try {
      await projectService.create(newProjectName, newProjectDesc);
      setNewProjectName('');
      setNewProjectDesc('');
      fetchProjects();
    } catch (err) {
      console.error('Failed to create project', err);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h1>Dashboard</h1>
        <div>
          <span>Welcome, {user?.name}</span>
          <button onClick={handleLogout} style={{ marginLeft: '20px', padding: '8px 16px', background: '#dc3545', color: 'white', border: 'none' }}>Logout</button>
        </div>
      </div>

      <form onSubmit={handleCreateProject} style={{ marginBottom: '30px', padding: '20px', border: '1px solid #ddd' }}>
        <h3>Create New Project</h3>
        <input type="text" placeholder="Project Name" value={newProjectName} onChange={(e) => setNewProjectName(e.target.value)} required style={{ width: '100%', padding: '8px', marginBottom: '10px' }} />
        <textarea placeholder="Description" value={newProjectDesc} onChange={(e) => setNewProjectDesc(e.target.value)} style={{ width: '100%', padding: '8px', marginBottom: '10px' }} />
        <button type="submit" style={{ padding: '10px 20px', background: '#007bff', color: 'white', border: 'none' }}>Create Project</button>
      </form>

      <h3>Your Projects</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: '#f8f9fa' }}>
            <th style={{ border: '1px solid #ddd', padding: '10px', textAlign: 'left' }}>Name</th>
            <th style={{ border: '1px solid #ddd', padding: '10px', textAlign: 'left' }}>Status</th>
            <th style={{ border: '1px solid #ddd', padding: '10px', textAlign: 'left' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {projects.map((p) => (
            <tr key={p.id}>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>{p.name}</td>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>{p.status}</td>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>
                <Link to={`/tasks/${p.id}`} style={{ color: '#007bff', textDecoration: 'none', marginRight: '10px' }}>View Tasks</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
