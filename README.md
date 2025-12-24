cat > ~/multi-tenant-saas/README.md << 'EOF'
# 🚀 Multi-Tenant SaaS Platform

[![Node.js](https://img.shields.io/badge/Backend-Node.js-green)](https://nodejs.org/)
[![React](https://img.shields.io/badge/Frontend-React-blue)](https://reactjs.org/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blueviolet)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Container-Docker-blue)](https://www.docker.com/)

A production-ready, multi-tenant SaaS application designed for project and task management. This system ensures **strict data isolation** between organizations (tenants), implements **Role-Based Access Control (RBAC)**, and is fully containerized with **Docker**.

---

## 🌟 Key Features

* **Multi-Tenancy:** Each organization has its own isolated data environment.
* **RBAC (Role-Based Access Control):** Three tiers: `Super Admin`, `Tenant Admin`, and `User`.
* **Security:** JWT-based stateless authentication (24h expiry) and Bcrypt password hashing.
* **Subscription Management:** Enforced limits on users and projects based on Free/Pro/Enterprise plans.
* **Architecture:** Clean separation of concerns with a centralized PostgreSQL database using a shared-schema (tenant_id) strategy.

---

## 🛠️ Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | React 18, React Router, Axios, Tailwind CSS |
| **Backend** | Node.js, Express.js |
| **Database** | PostgreSQL |
| **DevOps** | Docker, Docker Compose |
| **Auth** | JSON Web Tokens (JWT), Bcrypt |

---

## 📂 Project Structure

```text
/multi-tenant-saas
├── /backend                 # Express API
│   ├── /src
│   │   ├── /config          # DB Connection (Pool)
│   │   ├── /middleware      # JWT & Tenant Isolation
│   │   ├── /routes          # 19+ API Endpoints
│   │   └── server.js        # Main Entry Point
│   ├── /migrations          # SQL Table Schemas
│   └── Dockerfile
├── /frontend                # React UI
│   ├── /src
│   │   ├── /pages           # Dashboard, Projects, Tasks
│   │   └── /services        # API communication logic
│   └── Dockerfile
├── /docs                    # Mandatory Design Documents
├── docker-compose.yml       # Orchestration
└── submission.json          # Automated Test Credentials
🚀 Quick Start (Local Development)
1. Database Setup

Ensure you have a PostgreSQL instance running and create a database named saas_db.

2. Backend Configuration

Bash
cd backend
npm install
# Create .env file with your DB_HOST, DB_USER, DB_PASSWORD, and JWT_SECRET
npm run dev
3. Frontend Configuration

Bash
cd frontend
npm install
npm start
🔐 Data Isolation Logic
Data isolation is enforced at the database layer. Every query includes a tenant_id check extracted from the user's secure JWT.

Example Query:

SQL
-- No tenant can see another's data even with the same Project ID
SELECT * FROM projects 
WHERE id = $1 AND tenant_id = $2;
🐳 Docker Deployment (Mandatory)
To launch the entire production-ready stack (Database + Backend + Frontend):

Bash
docker-compose up -d
Frontend: http://localhost:3000

Backend: http://localhost:5000

Health Check: http://localhost:5000/api/health

📝 License
This project is part of the Internshala Student Partner learning track.
