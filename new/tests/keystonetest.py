
from contextlib import contextmanager

import abc
import ConfigParser
import shutil
import unittest

from utils.client import *

class KeystoneTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

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

    def setUp(self):
        super(ProjectTestCase, self).setUp()

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

def setup_cloud_admin_user(config):
    # cp setup policy to keystone policy path
    src = config.get('setup_tests_policy', 'policy.setup.json')
    dst = config.get('keystone_policy_file', '/etc/keystone/policy.json')
    shutil.copyfile(src, dst)

    # create cloud_admin_role
    # create cloud_admin_domain
    # create cloud_admin_user
    # grant cloud_admin_role to cloud_admin_user at cloud_admin_domain

def delete_cloud_admin_user():
    pass

def setUpModule():
    config = ConfigParser.ConfigParser()
    config.read('setup.cfg')
    setup_cloud_admin_user(config)

def tearDownModule():
    delete_cloud_admin_user()

if __name__ == "__main__":
    unittest.main()
