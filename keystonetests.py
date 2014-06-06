import unittest
import utils


"""
Base class to be used during tests. It creates
the basic structure: users, projects, domains,
groups and roles.
"""

class KeystonePolicyTests(unittest.TestCase):

    def _create_test_domain(self, name):
        return utils.create_domain(
            self.admin_client, name)

    def _delete_test_domain(self, domain):
        return self.admin_client.domains.delete(domain)

    def _create_test_user(self, name, project, domain):
        return utils.create_user(
            self.admin_client, name, name,
            name + '@example.com', project.id,
            domain.id)

    def _delete_test_user(self, user):
        return self.admin_client.users.delete(user)

    def _create_test_group(self, name, domain):
        return utils.create_group(
            self.admin_client, name,
            domain.id)

    def _delete_test_group(self, group):
        return self.admin_client.groups.delete(group)

    def _create_test_policy(self, blob):
        return self.admin_client.policies.create(blob)

    def _delete_test_policy(self, policy):
        return self.admin_client.policies.delete(policy)

    def _create_test_service(self, name, type):
        return self.admin_client.services.create(name, type)

    def _delete_test_service(self, service):
        return self.admin_client.services.delete(service)

    def _create_test_endpoint(self, url):
        service = self._create_test_service('test', 'volume')
        return service, self.admin_client.endpoints.create(service,
                                                           interface='public',
                                                           url=url)

    def _delete_test_endpoint(self, service, endpoint):
        self._delete_test_service(service)
        self.admin_client.endpoints.delete(endpoint)

    def _create_test_credential(self, user, type, blob, project):
        return self.admin_client.credentials.create(user, type, blob=blob,
                                                    project=project)

    def _delete_test_credential(self, credential):
        self.admin_client.credentials.delete(credential)

    def _create_test_role(self, name):
        return utils.create_role(self.admin_client, name)

    def _delete_test_role(self, role):
        self.admin_client.roles.delete(role)

    # SETUP

    def _create_roles(self):
        self.admin_role = utils.create_role(self.admin_client, 'admin')
        self.member_role = utils.create_role(self.admin_client, '_member_')

    def _create_domains(self):
        self.d1 = utils.create_domain(self.admin_client, 'd1')
        utils.grant_domain_role(self.admin_client, self.admin_role.id,
                                self.admin.id, self.d1.id)
        self.d2 = utils.create_domain(self.admin_client, 'd2')
        utils.grant_domain_role(self.admin_client, self.admin_role.id,
                                self.admin.id, self.d2.id)

    def _create_projects(self):
        self.p1 = utils.create_project(self.admin_client, 'p1', self.d1.id)
        utils.grant_project_role(self.admin_client, self.admin_role.id,
                                 self.admin.id, self.p1.id)
        self.p2 = utils.create_project(self.admin_client, 'p2', self.d1.id)
        utils.grant_project_role(self.admin_client, self.admin_role.id,
                                 self.admin.id, self.p2.id)

    def _create_users(self):
        self.d1admin = utils.create_user(
            self.admin_client, 'd1admin', 'd1admin',
            'd1admin@example.com', self.p1.id,
            self.d1.id)
        self.d1member = utils.create_user(
            self.admin_client, 'd1member', 'd1member',
            'd1member@example.com', self.p1.id,
            self.d1.id)
        self.p1admin = utils.create_user(
            self.admin_client, 'p1admin', 'p1admin',
            'p1admin@example.com', self.p1.id,
            self.d1.id)
        self.p2admin = utils.create_user(
            self.admin_client, 'p2admin', 'p2admin',
            'p2admin@example.com', self.p2.id,
            self.d1.id)
        self.p1member = utils.create_user(
            self.admin_client, 'p1member', 'p1member',
            'p1member@example.com', self.p1.id,
            self.d1.id)
        self.p2member = utils.create_user(
            self.admin_client, 'p2member', 'p2member',
            'p2member@example.com', self.p2.id,
            self.d1.id)

    def _create_groups(self):
        self.g1 = utils.create_group(self.admin_client, 'g1', self.d1)
        self.g2 = utils.create_group(self.admin_client, 'g2', self.d1)

    def _grant_roles(self):
        # p1
        utils.grant_project_role(self.admin_client, self.admin_role.id,
                                 self.p1admin.id, self.p1.id)
        utils.grant_project_role(self.admin_client, self.member_role.id,
                                 self.p1member.id, self.p1.id)
        utils.grant_group_project_role(self.admin_client, self.member_role.id,
                                       self.g1.id, self.p1.id)

        # p2
        utils.grant_project_role(self.admin_client, self.admin_role.id,
                                 self.p2admin.id, self.p2.id)
        utils.grant_project_role(self.admin_client, self.member_role.id,
                                 self.p2member.id, self.p2.id)
        utils.grant_group_project_role(self.admin_client, self.member_role.id,
                                       self.g2.id, self.p2.id)
        # d1
        utils.grant_domain_role(self.admin_client, self.admin_role.id,
                                self.d1admin.id, self.d1.id)
        utils.grant_domain_role(self.admin_client, self.admin_role.id,
                                self.d1member.id, self.d1.id)
        utils.grant_domain_role(self.admin_client, self.member_role.id,
                                self.p1admin.id, self.d1.id)
        utils.grant_domain_role(self.admin_client, self.member_role.id,
                                self.p2admin.id, self.d2.id)
        utils.grant_domain_role(self.admin_client, self.member_role.id,
                                self.p1member.id, self.d1.id)
        utils.grant_domain_role(self.admin_client, self.member_role.id,
                                self.p2member.id, self.d2.id)

    def setUp(self):
        """
        Assumes the pre existence of the cloud_admin rule:
        "cloud_admin": "rule:admin_required and domain_id:admin_domain_id"

        projects: p1, p2
        domains: d1, d2
        groups: g1, g2
        users: p1admin, p1member, p2admin, p2member

        d1admin -> admin -> d1
        p1admin -> admin -> p1
        p1member -> member -> p1
        p2admin -> admin -> p2
        p2member -> member -> p2

        """

        # Authenticate with admin
        self.admin_client = utils.create_client_domain(
            'cloud_admin',
            'cloud_admin',
            'cloud_admin_domain',
            'http://10.1.0.22:5000/v3')
        self.admin = utils.find_user(self.admin_client, 'cloud_admin')

        self._create_roles()
        self._create_domains()
        self._create_projects()
        self._create_users()
        self._create_groups()

        # Add users to groups
        self.admin_client.users.add_to_group(self.p1member, self.g1)
        self.admin_client.users.add_to_group(self.p2member, self.g2)

        self._grant_roles()

    # TEAR DOWN

    def _delete_roles(self):
        pass

    def _delete_domains(self):
        self.admin_client.domains.update(self.d1, enabled=False)
        self.admin_client.domains.delete(self.d1)
        self.admin_client.domains.update(self.d2, enabled=False)
        self.admin_client.domains.delete(self.d2)

    def _delete_projects(self):
        self.admin_client.projects.delete(self.p1)
        self.admin_client.projects.delete(self.p2)

    def _delete_users(self):
        self.admin_client.users.delete(self.d1admin)
        self.admin_client.users.delete(self.p1admin)
        self.admin_client.users.delete(self.p1member)
        self.admin_client.users.delete(self.p2admin)
        self.admin_client.users.delete(self.p2member)

    def _delete_groups(self):
        self.admin_client.groups.delete(self.g1)
        self.admin_client.groups.delete(self.g2)

    def tearDown(self):
        self._delete_groups()
        self._delete_users()
        self._delete_projects()
        self._delete_domains()
        self._delete_roles()
