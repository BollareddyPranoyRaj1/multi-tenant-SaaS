-- Create a Super Admin
INSERT INTO users (email, password_hash, full_name, role, tenant_id)
VALUES ('superadmin@system.com', '$2a$10$76YVfH.Y06SoxV9V2N69u.REvSgVv9S8HhVvXvVvVvVvVvVvVvVvV', 'System Admin', 'super_admin', NULL)
ON CONFLICT DO NOTHING;

-- Create Demo Tenant
INSERT INTO tenants (name, subdomain, status, subscription_plan, max_users, max_projects)
VALUES ('Demo Company', 'demo', 'active', 'pro', 25, 15)
ON CONFLICT (subdomain) DO NOTHING;

-- Get the ID of the demo tenant to create an admin for it
DO $$
DECLARE
    demo_tenant_id UUID;
BEGIN
    SELECT id INTO demo_tenant_id FROM tenants WHERE subdomain = 'demo';
    
    INSERT INTO users (tenant_id, email, password_hash, full_name, role)
    VALUES (demo_tenant_id, 'admin@demo.com', '$2a$10$76YVfH.Y06SoxV9V2N69u.REvSgVv9S8HhVvXvVvVvVvVvVvVvVvV', 'Demo Admin', 'tenant_admin')
    ON CONFLICT DO NOTHING;
END $$;
