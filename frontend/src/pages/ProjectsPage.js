import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { projectService } from '../services/api';

export default function ProjectsPage() {
  const [projects, setProjects] = useState([]);
  const [newProjectName, setNewProjectName] = useState('');

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
      await projectService.create(newProjectName, '');
      setNewProjectName('');
      fetchProjects();
    } catch (err) {
      console.error('Failed to create project', err);
    }
  };

  const handleDeleteProject = async (id) => {
    try {
      await projectService.delete(id);
      fetchProjects();
    } catch (err) {
      console.error('Failed to delete project', err);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <Link to="/" style={{ color: '#007bff', marginBottom: '20px', display: 'inline-block' }}>← Back to Dashboard</Link>
      <h2>Projects</h2>
      <form onSubmit={handleCreateProject} style={{ marginBottom: '20px' }}>
        <input type="text" placeholder="Project Name" value={newProjectName} onChange={(e) => setNewProjectName(e.target.value)} required style={{ padding: '8px', marginRight: '10px' }} />
        <button type="submit" style={{ padding: '8px 16px', background: '#007bff', color: 'white', border: 'none' }}>Create</button>
      </form>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: '#f8f9fa' }}>
            <th style={{ border: '1px solid #ddd', padding: '10px' }}>Name</th>
            <th style={{ border: '1px solid #ddd', padding: '10px' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {projects.map((p) => (
            <tr key={p.id}>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>{p.name}</td>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>
                <Link to={`/tasks/${p.id}`} style={{ color: '#007bff', marginRight: '10px' }}>Tasks</Link>
                <button onClick={() => handleDeleteProject(p.id)} style={{ background: '#dc3545', color: 'white', border: 'none', padding: '4px 8px', cursor: 'pointer' }}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
