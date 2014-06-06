import utils

# LOGIN
admin_client = utils.create_client('admin',
                                   'admin',
                                   'admin',
                                   'Default',
                                   'Default',
                                   'http://10.1.0.22:5000/v3')

# CREATE CLOUD ADMIN DOMAIN
admin_domain = utils.create_domain(admin_client, 'cloud_admin_domain')

# CREATE CLOUD ADMIN DEFAULT PROJECT
admin_project = utils.create_project(admin_client, 'cloud_admin_project', admin_domain)

# CREATE CLOUD ADMIN USER
cloud_admin = utils.create_user(admin_client,
                                'cloud_admin',
                                'cloud_admin',
                                'cloud_admin@example.com',
                                admin_project.id,
                                admin_domain.id)

# CREATE ROLE ADMIN
admin_role = utils.create_role(admin_client, 'admin')

# GRANT ADMIN ROLE AT DOMAIN
utils.grant_domain_role(admin_client, admin_role.id,
                        cloud_admin.id, admin_domain.id)

print cloud_admin
print admin_domain
print admin_project
