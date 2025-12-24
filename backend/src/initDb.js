const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  host: process.env.DB_HOST || 'database',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_DATABASE || 'multi_tenant_saas',
});

async function runMigrations() {
  const client = await pool.connect();
  try {
    console.log('Starting database initialization...');

    // Path to your migration file
    const migrationPath = path.join(__dirname, '../migrations/001_initial_schema.sql');
    const seedPath = path.join(__dirname, '../migrations/002_seed_data.sql');

    // Execute Initial Schema
    if (fs.existsSync(migrationPath)) {
      const schemaSql = fs.readFileSync(migrationPath, 'utf8');
      await client.query(schemaSql);
      console.log('Successfully executed 001_initial_schema.sql');
    }

    // Execute Seed Data (Optional but recommended for evaluation)
    if (fs.existsSync(seedPath)) {
      const seedSql = fs.readFileSync(seedPath, 'utf8');
      await client.query(seedSql);
      console.log('Successfully executed 002_seed_data.sql');
    }

    console.log('Database initialization completed successfully.');
  } catch (err) {
    console.error('Error during database initialization:', err);
    process.exit(1); // Exit with error so the server doesn't start on a broken DB
  } finally {
    client.release();
    await pool.end();
  }
}

runMigrations();
