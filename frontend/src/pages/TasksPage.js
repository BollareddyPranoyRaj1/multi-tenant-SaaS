import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { taskService } from '../services/api';

export default function TasksPage() {
  const { projectId } = useParams();
  const [tasks, setTasks] = useState([]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('medium');

  useEffect(() => {
    fetchTasks();
  }, [projectId]);

  const fetchTasks = async () => {
    try {
      const res = await taskService.getAll(projectId);
      setTasks(res.data);
    } catch (err) {
      console.error('Failed to fetch tasks', err);
    }
  };

  const handleCreateTask = async (e) => {
    e.preventDefault();
    try {
      await taskService.create(projectId, title, description, priority, null, null);
      setTitle('');
      setDescription('');
      setPriority('medium');
      fetchTasks();
    } catch (err) {
      console.error('Failed to create task', err);
    }
  };

  const handleDeleteTask = async (id) => {
    try {
      await taskService.delete(id);
      fetchTasks();
    } catch (err) {
      console.error('Failed to delete task', err);
    }
  };

  const handleUpdateStatus = async (id, currentStatus) => {
    const newStatus = currentStatus === 'todo' ? 'in_progress' : currentStatus === 'in_progress' ? 'done' : 'todo';
    try {
      const task = tasks.find(t => t.id === id);
      await taskService.update(id, task.title, task.description, newStatus, task.priority, task.assigned_to, task.due_date);
      fetchTasks();
    } catch (err) {
      console.error('Failed to update task', err);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <Link to="/" style={{ color: '#007bff', marginBottom: '20px', display: 'inline-block' }}>← Back to Dashboard</Link>
      <h2>Tasks for Project {projectId}</h2>
      <form onSubmit={handleCreateTask} style={{ marginBottom: '20px', padding: '15px', border: '1px solid #ddd' }}>
        <input type="text" placeholder="Task Title" value={title} onChange={(e) => setTitle(e.target.value)} required style={{ width: '100%', padding: '8px', marginBottom: '10px' }} />
        <textarea placeholder="Description" value={description} onChange={(e) => setDescription(e.target.value)} style={{ width: '100%', padding: '8px', marginBottom: '10px' }} />
        <select value={priority} onChange={(e) => setPriority(e.target.value)} style={{ width: '100%', padding: '8px', marginBottom: '10px' }}>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
        </select>
        <button type="submit" style={{ padding: '10px 20px', background: '#007bff', color: 'white', border: 'none' }}>Create Task</button>
      </form>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: '#f8f9fa' }}>
            <th style={{ border: '1px solid #ddd', padding: '10px' }}>Title</th>
            <th style={{ border: '1px solid #ddd', padding: '10px' }}>Status</th>
            <th style={{ border: '1px solid #ddd', padding: '10px' }}>Priority</th>
            <th style={{ border: '1px solid #ddd', padding: '10px' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {tasks.map((task) => (
            <tr key={task.id}>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>{task.title}</td>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>
                <button onClick={() => handleUpdateStatus(task.id, task.status)} style={{ padding: '4px 8px', background: '#17a2b8', color: 'white', border: 'none', cursor: 'pointer' }}>
                  {task.status}
                </button>
              </td>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>{task.priority}</td>
              <td style={{ border: '1px solid #ddd', padding: '10px' }}>
                <button onClick={() => handleDeleteTask(task.id)} style={{ background: '#dc3545', color: 'white', border: 'none', padding: '4px 8px', cursor: 'pointer' }}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
