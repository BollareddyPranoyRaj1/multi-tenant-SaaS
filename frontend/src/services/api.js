import axios from 'axios';

const API_URL = 'http://localhost:5001/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authService = {
  register: (tenantName, email, password, name) =>
    api.post('/auth/register', { tenantName, email, password, name }),
  login: (email, password) =>
    api.post('/auth/login', { email, password }),
};

export const projectService = {
  getAll: () => api.get('/projects'),
  getOne: (id) => api.get(`/projects/${id}`),
  create: (name, description) => api.post('/projects', { name, description }),
  update: (id, name, description, status) =>
    api.put(`/projects/${id}`, { name, description, status }),
  delete: (id) => api.delete(`/projects/${id}`),
};

export const taskService = {
  getAll: (projectId) =>
    api.get('/tasks', { params: { project_id: projectId } }),
  getOne: (id) => api.get(`/tasks/${id}`),
  create: (projectId, title, description, priority, assignedTo, dueDate) =>
    api.post('/tasks', {
      project_id: projectId,
      title,
      description,
      priority,
      assigned_to: assignedTo,
      due_date: dueDate,
    }),
  update: (id, title, description, status, priority, assignedTo, dueDate) =>
    api.put(`/tasks/${id}`, {
      title,
      description,
      status,
      priority,
      assigned_to: assignedTo,
      due_date: dueDate,
    }),
  delete: (id) => api.delete(`/tasks/${id}`),
};

export default api;
