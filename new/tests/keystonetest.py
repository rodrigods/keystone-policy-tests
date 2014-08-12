
from contextlib import contextmanager

import abc
import config
import shutil
import unittest

from utils import client


class KeystoneTestCase(unittest.TestCase):

    def _create_domains(self):
        self.d1 = self.cloud_admin_client.create_domain('d1')
        self.d2 = self.cloud_admin_client.create_domain('d2')

    def _create_projects(self):
        self.p1 = self.cloud_admin_client.create_project('p1', 'd1')
        self.p2 = self.cloud_admin_client.create_project('p2', 'd1')

    def _delete_domains(self):
        self.cloud_admin_client.delete_domain('d1')
        self.cloud_admin_client.delete_domain('d2')

    def _delete_projects(self):
        self.cloud_admin_client.delete_project('p1', 'd1')
        self.cloud_admin_client.delete_project('p2', 'd1')

    @classmethod
    def setUpClass(cls):
	pass

    @classmethod
    def tearDownClass(cls):
	pass

    def setUp(self):
	self.cloud_admin_client = client.Client.for_domain('cloud_admin',
							   'cloud_admin',
							   'cloud_admin_domain',
							   config.auth_url)
        self._create_domains()
	self._create_projects()

    def tearDown(self):
        self._delete_domains()
	self._delete_projects()

    @contextmanager
    def throws_no_exception_if(self, enabled):
        if enabled:
            yield
        else:
            with self.assertRaises(Exception):
                yield


class RegionTestCase(KeystoneTestCase):
    pass


class ServiceTestCase(KeystoneTestCase):

    def setUp(self):
        super(ServiceTestCase, self).setUp()

        self.should_add_service = False
        self.should_list_services = False
        self.should_get_service = False
        self.should_update_service = False
        self.should_delete_service = False

    def test_add_service(self):
        with self.throws_no_exception_if(self.should_add_service):
            pass

    def test_list_services(self):
        with self.throws_no_exception_if(self.should_list_services):
            pass

    def test_get_service(self):
        with self.throws_no_exception_if(self.should_get_service):
            pass

    def test_update_service(self):
        with self.throws_no_exception_if(self.should_update_service):
            pass

    def test_delete_service(self):
        with self.throws_no_exception_if(self.should_delete_service):
            pass


class EndpointTestCase(KeystoneTestCase):

    def setUp(self):
        super(EndpointTestCase, self).setUp()

        self.should_add_endpoint = False
        self.should_list_endpoints = False
        self.should_update_endpoint = False
        self.should_delete_endpoint = False

    def test_add_endpoint(self):
        with self.throws_no_exception_if(self.should_add_endpoint):
            pass

    def test_list_endpoints(self):
        with self.throws_no_exception_if(self.should_list_endpoints):
            pass

    def test_update_endpoint(self):
        with self.throws_no_exception_if(self.should_update_endpoint):
            pass

    def test_delete_endpoint(self):
        with self.throws_no_exception_if(self.should_delete_endpoint):
            pass


class DomainTestCase(KeystoneTestCase):

    def setUp(self):
        super(DomainTestCase, self).setUp()

        self.should_add_domain = False
        self.should_list_domains = False
        self.should_get_domain = False
        self.should_update_domain = False
        self.should_list_domain_user_roles = False
        self.should_grant_user_role_in_domain = False
        self.should_check_user_role_in_domain = False
        self.should_revoke_user_role_in_domain = False
        self.should_list_domain_group_roles = False
        self.should_grant_group_role_in_domain = False
        self.should_check_group_role_in_domain = False
        self.should_revoke_group_role_in_domain = False
        self.should_delete_domain = False

    def test_add_domain(self):
        with self.throws_no_exception_if(self.should_add_domain):
            pass

    def test_list_domains(self):
        with self.throws_no_exception_if(self.should_list_domains):
            pass

    def test_get_domain(self):
        with self.throws_no_exception_if(self.should_get_domain):
            pass

    def test_update_domain(self):
        with self.throws_no_exception_if(self.should_update_domain):
            pass

    def test_list_domain_user_roles(self):
        with self.throws_no_exception_if(self.should_list_domain_user_roles):
            pass

    def test_grant_user_role_in_domain(self):
        with self.throws_no_exception_if(self.should_grant_user_role_in_domain):
            pass

    def test_check_user_role_in_domain(self):
        with self.throws_no_exception_if(self.should_check_user_role_in_domain):
            pass

    def test_revoke_user_role_in_domain(self):
        with self.throws_no_exception_if(self.should_revoke_user_role_in_domain):
            pass

    def test_list_domain_group_roles(self):
        with self.throws_no_exception_if(self.should_list_domain_group_roles):
            pass

    def test_grant_group_role_in_domain(self):
        with self.throws_no_exception_if(self.should_grant_group_role_in_domain):
            pass

    def test_check_group_role_in_domain(self):
        with self.throws_no_exception_if(self.should_check_group_role_in_domain):
            pass

    def test_revoke_group_role_in_domain(self):
        with self.throws_no_exception_if(self.should_revoke_group_role_in_domain):
            pass

    def test_delete_domain(self):
        with self.throws_no_exception_if(self.should_delete_domain):
            pass


class ProjectTestCase(KeystoneTestCase):

    def _create_roles(self):
        self.r1 = self.cloud_admin_client.create_role('project_admin')
        self.r2 = self.cloud_admin_client.create_role('project_member')

    def _create_users(self):
	self.p1_admin = self.cloud_admin_client.create_user('p1_admin', 'p1_admin', 'd1', 'p1')
	self.p1_member = self.cloud_admin_client.create_user('p1_member', 'p1_member', 'd1', 'p1')

	self.p2_admin = self.cloud_admin_client.create_user('p2_admin', 'p2_admin', 'd1', 'p2')
	self.p2_member = self.cloud_admin_client.create_user('p2_member', 'p2_member', 'd1', 'p2')

    def _create_group(self):
	self.g1 = self.cloud_admin_client.create_group('g1', 'd1')
	self.g2 = self.cloud_admin_client.create_group('g2', 'd1')

    def setUp(self):
        super(ProjectTestCase, self).setUp()
	self._create_roles()
	self._create_users()

        self.should_get_projects = False
        self.should_get_project_info = False
        self.should_update_project = False
        self.should_list_project_users = False
        self.should_list_project_user_roles = False
        self.should_list_project_own_roles = False
        self.should_grant_user_role_in_project = False
        self.should_check_user_role_in_project = False
        self.should_revoke_user_role_in_project = False
        self.should_list_project_group_roles = False
        self.should_grant_group_role_in_project = False
        self.should_check_group_role_in_project = False
        self.should_revoke_group_role_in_project = False
        self.should_delete_project = False

    def test_get_projects(self):
        with self.throws_no_exception_if(self.should_get_projects):
            pass

    def test_get_project_info(self):
        with self.throws_no_exception_if(self.should_get_project_info):
            pass

    def test_update_project(self):
        with self.throws_no_exception_if(self.should_update_project):
            pass

    def test_list_project_users(self):
        with self.throws_no_exception_if(self.should_list_project_users):
            pass

    def test_list_project_user_roles(self):
        with self.throws_no_exception_if(self.should_list_project_user_roles):
            pass

    def test_list_project_own_roles(self):
        with self.throws_no_exception_if(self.should_list_project_own_roles):
            pass

    def test_grant_user_role_in_project(self):
        with self.throws_no_exception_if(self.should_grant_user_role_in_project):
            pass

    def test_check_user_role_in_project(self):
        with self.throws_no_exception_if(self.should_check_user_role_in_project):
            pass

    def test_revoke_user_role_in_project(self):
        with self.throws_no_exception_if(self.should_revoke_user_role_in_project):
            pass

    def test_list_project_group_roles(self):
        with self.throws_no_exception_if(self.should_list_project_group_roles):
            pass

    def test_grant_group_role_in_project(self):
        with self.throws_no_exception_if(self.should_grant_group_role_in_project):
            pass

    def test_check_group_role_in_project(self):
        with self.throws_no_exception_if(self.should_check_group_role_in_project):
            pass

    def test_revoke_group_role_in_project(self):
        with self.throws_no_exception_if(self.should_revoke_group_role_in_project):
            pass

    def test_delete_project(self):
        with self.throws_no_exception_if(self.should_delete_project):
            pass


class UserTestCase(KeystoneTestCase):

    def setUp(self):
        super(UserTestCase, self).setUp()

        self.should_add_user = False
        self.should_list_users = False
        self.should_get_user = False
        self.should_update_user_password = False
        self.should_update_own_password = False
        self.should_delete_user = False
        self.should_list_user_groups = False
        self.should_list_own_groups = False
        self.should_list_user_projects = False
        self.should_list_user_roles = False

    def test_add_user(self):
        with self.throws_no_exception_if(self.should_add_user):
            pass

    def test_list_users(self):
        with self.throws_no_exception_if(self.should_list_users):
            pass

    def test_get_user(self):
        with self.throws_no_exception_if(self.should_get_user):
            pass

    def test_update_user_password(self):
        with self.throws_no_exception_if(self.should_update_user_password):
            pass

    def test_update_own_password(self):
        with self.throws_no_exception_if(self.should_update_own_password):
            pass

    def test_delete_user(self):
        with self.throws_no_exception_if(self.should_delete_user):
            pass

    def test_list_user_groups(self):
        with self.throws_no_exception_if(self.should_list_user_groups):
            pass

    def test_list_own_groups(self):
        with self.throws_no_exception_if(self.should_list_own_groups):
            pass

    def test_list_user_projects(self):
        with self.throws_no_exception_if(self.should_list_user_projects):
            pass

    def test_list_user_roles(self):
        with self.throws_no_exception_if(self.should_list_user_roles):
            pass


class GroupTestCase(KeystoneTestCase):

    def setUp(self):
        super(GroupTestCase, self).setUp()

        self.should_add_group = False
        self.should_list_groups = False
        self.should_get_group = False
        self.should_update_group = False
        self.should_delete_group = False
        self.should_list_group_users = False
        self.should_add_user_group = False
        self.should_check_user_in_group = False
        self.should_revoke_user_in_group = False

    def test_add_group(self):
        with self.throws_no_exception_if(self.should_add_group):
            pass

    def test_list_groups(self):
        with self.throws_no_exception_if(self.should_list_groups):
            pass

    def test_get_group(self):
        with self.throws_no_exception_if(self.should_get_group):
            pass

    def test_update_group(self):
        with self.throws_no_exception_if(self.should_update_group):
            pass

    def test_delete_group(self):
        with self.throws_no_exception_if(self.should_delete_group):
            pass

    def test_list_group_users(self):
        with self.throws_no_exception_if(self.should_list_group_users):
            pass

    def test_add_user_group(self):
        with self.throws_no_exception_if(self.should_add_user_group):
            pass

    def test_check_user_in_group(self):
        with self.throws_no_exception_if(self.should_check_user_in_group):
            pass

    def test_revoke_user_in_group(self):
        with self.throws_no_exception_if(self.should_revoke_user_in_group):
            pass


class CredentialTestCase(KeystoneTestCase):

    def setUp(self):
        super(CredentialTestCase, self).setUp()

        self.should_add_credential = False
        self.should_list_credentials = False
        self.should_get_credential = False
        self.should_update_credential = False
        self.should_delete_credential = False

    def test_add_credential(self):
        with self.throws_no_exception_if(self.should_add_credential):
            pass

    def test_list_credentials(self):
        with self.throws_no_exception_if(self.should_list_credentials):
            pass

    def test_get_credential(self):
        with self.throws_no_exception_if(self.should_get_credential):
            pass

    def test_update_credential(self):
        with self.throws_no_exception_if(self.should_update_credential):
            pass

    def test_delete_credential(self):
        with self.throws_no_exception_if(self.should_delete_credential):
            pass


class RoleTestCase(KeystoneTestCase):

    def setUp(self):
        super(RoleTestCase, self).setUp()

        self.should_add_role = False
        self.should_list_roles = False
        self.should_get_role = False
        self.should_update_role = False
        self.should_delete_role = False

    def test_add_role(self):
        with self.throws_no_exception_if(self.should_add_role):
            pass

    def test_list_roles(self):
        with self.throws_no_exception_if(self.should_list_roles):
            pass

    def test_get_role(self):
        with self.throws_no_exception_if(self.should_get_role):
            pass

    def test_update_role(self):
        with self.throws_no_exception_if(self.should_update_role):
            pass

    def test_delete_role(self):
        with self.throws_no_exception_if(self.should_delete_role):
            pass


class GrantTestCase(KeystoneTestCase):
    pass


class PolicyTestCase(KeystoneTestCase):
    pass


class TokenTestCase(KeystoneTestCase):
    pass


class TrustTestCase(KeystoneTestCase):
    pass


class ConsumerTestCase(KeystoneTestCase):
    pass


class AccessTokenTestCase(KeystoneTestCase):
    pass


class RequestTokenTestCase(KeystoneTestCase):
    pass


class IdentityProviderTestCase(KeystoneTestCase):
    pass


class ProtocolTestCase(KeystoneTestCase):
    pass


class MappingTestCase(KeystoneTestCase):
    pass


def load_policy(policy):
    dst = config.keystone_policy_path
    shutil.copyfile(policy, dst)

def replace_domain_id(source_policy, output_policy, domain_id):
    infile = open(source_policy)
    outfile = open(output_policy, 'w')
    for line in infile:
	line = line.replace('cloud_admin_domain_id', domain_id)
	outfile.write(line)
    infile.close()
    outfile.close()

def setUpModule():
    admin_client = client.Client.for_project('admin', 'admin', 'demo', 'Default', config.auth_url)

    # cp setup policy to keystone policy path
    load_policy(config.setup_policy)

    # create cloud_admin role
    cloud_admin_role = admin_client.create_role('cloud_admin')

    # create cloud_admin_domain
    cloud_admin_domain = admin_client.create_domain('cloud_admin_domain')

    # create cloud_admin_project
    cloud_admin_project = admin_client.create_project('cloud_admin_project', 'cloud_admin_domain')

    # create cloud_admin
    cloud_admin = admin_client.create_user('cloud_admin',
					   'cloud_admin',
					   'cloud_admin_domain',
					   'cloud_admin_project')

    # grant cloud_admin role to cloud_admin_user at cloud_admin_domain
    admin_client.grant_domain_role(cloud_admin_role, cloud_admin, cloud_admin_domain)

    # tests policy to keystone policy path replacing the cloud_admin_domain_id
    replace_domain_id(config.tests_policy, config.keystone_policy_path, cloud_admin_domain.id)

def tearDownModule():
    admin_client = client.Client.for_project('admin', 'admin', 'demo', 'Default', config.auth_url)

    # cp setup policy to keystone policy path
    load_policy(config.setup_policy)

    # clear everything
    admin_client.delete_user('cloud_admin')
    admin_client.delete_project('cloud_admin_project', 'cloud_admin_domain')
    admin_client.delete_domain('cloud_admin_domain')
    admin_client.delete_role('cloud_admin')

if __name__ == "__main__":
    unittest.main()
