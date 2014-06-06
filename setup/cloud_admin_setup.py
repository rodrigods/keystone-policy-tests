import utils

"""
In the case of using cloud_admin rule using
a specific domain:
"admin_required": "(role:admin or is_admin:1) 
and domain_id:cloud_admin_domain_id",
"""

# Regular admin login
admin_client = utils.create_client('admin',
                                   'admin',
                                   'admin',
                                   'Default',
                                   'Default',
                                   'http://10.1.0.22:5000/v3')

# Create cloud_admin_domain
admin_domain = utils.create_domain(admin_client, 'cloud_admin_domain')

# Create cloud_admin_project
admin_project = utils.create_project(admin_client, 'cloud_admin_project',
                                     admin_domain)

# Craete cloud_admin user
cloud_admin = utils.create_user(admin_client,
                                'cloud_admin',
                                'cloud_admin',
                                'cloud_admin@example.com',
                                admin_project.id,
                                admin_domain.id)

# Create cloud_admin role (admin in this case)
admin_role = utils.create_role(admin_client, 'admin')

# Grant roles at cloud_admin_domain and cloud_admin_project
utils.grant_project_role(admin_client, admin_role.id,
                         cloud_admin.id, admin_project.id)
utils.grant_domain_role(admin_client, admin_role.id,
                        cloud_admin.id, admin_domain.id)

# Print cloud_admin_domain id to be used at domain_id rule
print admin_domain.id
