
from contextlib import contextmanager

import abc
import config
import shutil
import unittest

from utils.client import *
from utils.models import *


class RoleBasedTest:
    @abc.abstractmethod
    def project_role_name(self):
        pass

    @abc.abstractmethod
    def domain_role_name(self):
        pass

    @abc.abstractmethod
    def create_test_client(self):
        pass


class KeystoneTestCase(RoleBasedTest, unittest.TestCase):
    __metaclass__ = abc.ABCMeta

    def _create_domains(self, domains):
        for d in domains:
            self.domains[d.name] = self.cloud_admin_client.create_domain(d)

    def _create_projects(self, projects):
        for p in projects:
            self.projects[p.name] = self.cloud_admin_client.create_project(p)

    def _create_users(self, users):
        for u in users:
            self.users[u.name] = self.cloud_admin_client.create_user(u)

    def _create_groups(self, groups):
        for g in groups:
            self.groups[g.name] = self.cloud_admin_client.create_group(g)

    def _create_roles(self, roles):
        for r in roles:
            self.roles[r.name] = self.cloud_admin_client.create_role(r)

    def _delete_domains(self):
        for d in self.domains:
            self.cloud_admin_client.delete_domain(self.domains[d])

    def _delete_projects(self):
        for p in self.projects:
            try:
                self.cloud_admin_client.delete_project(self.projects[p])
            except Exception:
                pass

    def _delete_users(self):
        for u in self.users:
            self.cloud_admin_client.delete_user(self.users[u])

    def _delete_groups(self):
        for g in self.groups:
            self.cloud_admin_client.delete_group(self.groups[g])

    def _delete_roles(self):
        for r in self.roles:
            self.cloud_admin_client.delete_role(self.roles[r])

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.projects = {}
        self.domains = {}
        self.roles = {}
        self.users = {}
        self.groups = {}

        self.cloud_admin_client = Client.for_domain(
            'cloud_admin', 'cloud_admin', 'cloud_admin_domain',
            config.auth_url)

    def tearDown(self):
        self._delete_roles()
        self._delete_users()
        self._delete_groups()
        self._delete_projects()
        self._delete_domains()

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
        with self.throws_no_exception_if(
                self.should_grant_user_role_in_domain):
            pass

    def test_check_user_role_in_domain(self):
        with self.throws_no_exception_if(
                self.should_check_user_role_in_domain):
            pass

    def test_revoke_user_role_in_domain(self):
        with self.throws_no_exception_if(
                self.should_revoke_user_role_in_domain):
            pass

    def test_list_domain_group_roles(self):
        with self.throws_no_exception_if(
                self.should_list_domain_group_roles):
            pass

    def test_grant_group_role_in_domain(self):
        with self.throws_no_exception_if(
                self.should_grant_group_role_in_domain):
            pass

    def test_check_group_role_in_domain(self):
        with self.throws_no_exception_if(
                self.should_check_group_role_in_domain):
            pass

    def test_revoke_group_role_in_domain(self):
        with self.throws_no_exception_if(
                self.should_revoke_group_role_in_domain):
            pass

    def test_delete_domain(self):
        with self.throws_no_exception_if(self.should_delete_domain):
            pass


class ProjectTestCase(KeystoneTestCase):

    def _grant_roles(self):

        project_role = self.project_role()
        domain_role = self.domain_role()
        if project_role is not None:
            self.cloud_admin_client.grant_project_role(
                self.roles[self.role_name()],
                self.users['test_user'],
                self.projects['test_project'])

        if domain_role is not None:
            self.cloud_admin_client.grant_domain_role(
                self.roles[domain_role],
                self.users['test_user'],
                self.domains['test_domain'])

        self.cloud_admin_client.grant_domain_role(
            self.roles['test_role'], self.users['same_domain_user'],
            self.domains['test_domain'])
        self.cloud_admin_client.grant_domain_role(
            self.roles['test_role'], self.users['other_domain_user'],
            self.domains['other_domain'])

    def setUp(self):
        super(ProjectTestCase, self).setUp()
        self._create_roles([Role(self.project_role_name()),
                            Role(self.domain_role_name()),
                            Role('test_role')])
        self._create_domains([Domain('test_domain')])
        self._create_projects(
            [Project('test_project', 'test_domain'),
             Project('other_project', 'test_domain')])
        self._create_users(
            [User('test_user', 'test_domain', 'test_project'),
             User('other_user', 'test_domain', 'other_project')])
        self._grant_roles()
        self.client = self.create_test_client()

        self.should_list_projects = False
        self.should_get_own_project_info = False
        self.should_get_any_project_info = False
        self.should_update_own_project = False
        self.should_update_any_project = False
        self.should_delete_own_project = False
        self.should_delete_any_project = False
        self.should_list_own_user_projects = False
        self.should_list_any_user_projects = False

    def test_list_projects(self):
        with self.throws_no_exception_if(self.should_list_projects):
            self.client.list_projects()

    def test_get_own_project_info(self):
        with self.throws_no_exception_if(self.should_get_own_project_info):
            self.client.get_project(self.projects['test_project'])

    def test_get_any_project_info(self):
        with self.throws_no_exception_if(self.should_get_any_project_info):
            self.client.get_project(self.projects['other_project'])

    def test_update_own_project(self):
        with self.throws_no_exception_if(self.should_update_own_project):
            self.client.update_project(self.projects['test_project'])

    def test_update_any_project(self):
        with self.throws_no_exception_if(self.should_update_any_project):
            self.client.update_project(self.projects['other_project'])

    def test_delete_own_project(self):
        with self.throws_no_exception_if(self.should_delete_own_project):
            self.client.delete_project(self.projects['test_project'])

    def test_delete_any_project(self):
        with self.throws_no_exception_if(self.should_delete_any_project):
            self.client.delete_project(self.projects['other_project'])

    def test_list_own_user_projects(self):
        with self.throws_no_exception_if(self.should_list_own_user_projects):
            self.client.list_projects(user=self.users['test_user'])

    def test_list_any_user_projects(self):
        with self.throws_no_exception_if(self.should_list_any_user_projects):
            self.client.list_projects(user=self.users['other_user'])


class UserTestCase(KeystoneTestCase):

    def _grant_roles(self):
        project_role = self.project_role()
        domain_role = self.domain_role()
        if project_role is not None:
            self.cloud_admin_client.grant_project_role(
                self.roles[project_role], self.users['test_user'],
                self.projects['test_project'])

        if domain_role is not None:
            self.cloud_admin_client.grant_domain_role(
                self.roles[domain_role], self.users['test_user'],
                self.domains['test_domain'])

        self.cloud_admin_client.grant_domain_role(
            self.roles['test_role'], self.users['same_domain_user'],
            self.domains['test_domain'])
        self.cloud_admin_client.grant_domain_role(
            self.roles['test_role'], self.users['other_domain_user'],
            self.domains['other_domain'])

    def setUp(self):
        super(UserTestCase, self).setUp()
        self._create_roles([Role(self.project_role_name()),
                            Role(self.domain_role_name()),
                            Role('test_role')])

        self._create_domains([Domain('test_domain'), Domain('other_domain')])
        self._create_projects([Project('test_project', 'test_domain')])
        self._create_users([
            User('test_user', 'test_domain', 'test_project'),
            User('same_domain_user', 'test_domain', 'test_project'),
            User('other_domain_user', 'other_domain', 'test_project')])
        self._grant_roles()
        self.client = self.create_test_client()

        self.should_get_own_user = False
        self.should_get_user_own_domain = False
        self.should_get_user_any_domain = False
        self.should_list_own_domain_users = False
        self.should_list_any_domain_users = False
        self.should_create_user_own_domain = False
        self.should_create_user_any_domain = False
        self.should_update_own_user = False
        self.should_update_user_own_domain = False
        self.should_update_user_any_domain = False
        self.should_delete_own_user = False
        self.should_delete_user_own_domain = False
        self.should_delete_user_any_domain = False
        self.should_update_own_user_password = False
        self.should_update_user_password_own_domain = False
        self.should_update_user_password_any_domain = False

    def test_get_own_user(self):
        with self.throws_no_exception_if(self.should_get_own_user):
            self.client.get_user(self.users['test_user'])

    def test_get_user_own_domain(self):
        with self.throws_no_exception_if(self.should_get_user_own_domain):
            self.client.get_user(self.users['same_domain_user'])

    def test_get_user_any_domain(self):
        with self.throws_no_exception_if(self.should_get_user_any_domain):
            self.client.get_user(self.users['other_domain_user'])

    def test_list_own_domain_users(self):
        with self.throws_no_exception_if(self.should_list_own_domain_users):
            self.client.list_users(domain='test_domain')

    def test_list_any_domain_users(self):
        with self.throws_no_exception_if(self.should_list_any_domain_users):
            self.client.list_users(domain='other_domain')

    def test_create_user_own_domain(self):
        with self.throws_no_exception_if(self.should_create_user_own_domain):
            self._create_user(User('user1', 'test_domain', 'test_project'))

    def test_create_user_any_domain(self):
        with self.throws_no_exception_if(self.should_create_user_any_domain):
            self._create_user(User('user1', 'other_domain', 'test_project'))

    def _create_user(self, user):
        u = self.client.create_user(user)
        self.cloud_admin_client.delete_user(u)

    def test_update_own_user(self):
        with self.throws_no_exception_if(self.should_update_own_user):
            self.client.update_user(self.users['test_user'])

    def test_update_user_own_domain(self):
        with self.throws_no_exception_if(self.should_update_user_own_domain):
            self.client.update_user(self.users['same_domain_user'])

    def test_update_user_any_domain(self):
        with self.throws_no_exception_if(self.should_update_user_any_domain):
            self.client.update_user(self.users['other_domain_user'])

    def test_update_own_user_password(self):
        with self.throws_no_exception_if(self.should_update_own_user_password):
            self.client.update_user_password(self.users['test_user'])

    def test_update_user_password_own_domain(self):
        with self.throws_no_exception_if(
                self.should_update_user_password_own_domain):
            self.client.update_user_password(self.users['same_domain_user'])

    def test_update_user_password_any_domain(self):
        with self.throws_no_exception_if(
                self.should_update_user_password_any_domain):
            self.client.update_user_password(self.users['other_domain_user'])


class GroupTestCase(KeystoneTestCase):

    def _grant_roles(self):
        project_role = self.project_role()
        domain_role = self.domain_role()
        if project_role is not None:
            self.cloud_admin_client.grant_project_role(
                self.roles[self.project_role_name()], self.users['test_user'],
                self.projects['test_project'])

        if domain_role is not None:
            self.cloud_admin_client.grant_domain_role(
                self.roles[self.domain_role_name()], self.users['test_user'],
                self.domains['test_domain'])

        self.cloud_admin_client.grant_domain_role(
            self.roles['test_role'], self.users['same_domain_user'],
            self.domains['test_domain'])
        self.cloud_admin_client.grant_domain_role(
            self.roles['test_role'], self.users['other_domain_user'],
            self.domains['other_domain'])

        self.cloud_admin_client.grant_group_domain_role(
            self.roles['test_role'], self.users['same_domain_group'],
            self.domains['test_domain'])
        self.cloud_admin_client.grant_group_domain_role(
            self.roles['test_role'], self.users['other_domain_group'],
            self.domains['other_domain'])

    def _add_users_to_groups(self):
        self.cloud_admin_client.add_user_to_group(
            self.groups['same_domain_group'],
            self.users['test_user'])

        self.cloud_admin_client.add_user_to_group(
            self.groups['same_domain_group'],
            self.users['same_domain_user'])

        self.cloud_admin_client.add_user_to_group(
            self.groups['other_domain_group'],
            self.users['other_domain_user'])

    def setUp(self):
        super(GroupTestCase, self).setUp()
        self._create_roles([Role(self.project_role_name()),
                            Role(self.domain_role_name()),
                            Role('test_role')])

        self._create_domains([Domain('test_domain'), Domain('other_domain')])
        self._create_projects([Project('test_project', 'test_domain')])
        self._create_users([
            User('test_user', 'test_domain', 'test_project'),
            User('same_domain_user', 'test_domain', 'test_project'),
            User('other_domain_user', 'other_domain', 'test_project')])
        self._create_groups([Group('same_domain_group', 'test_domain'),
                             Group('other_domain_group', 'other_domain')])
        self._grant_roles()
        self._add_users_to_groups()
        self.client = self.create_test_client()

        self.should_get_group_own_domain = False
        self.should_get_group_any_domain = False
        self.should_list_groups_own_domain = False
        self.should_list_groups_any_domain = False
        self.should_list_groups_for_own_user = False
        self.should_list_groups_for_any_user = False
        self.should_create_group_own_domain = False
        self.should_create_group_any_domain = False
        self.should_update_group_own_domain = False
        self.should_update_group_any_domain = False
        self.should_delete_group_own_domain = False
        self.should_delete_group_any_domain = False
        self.should_remove_user_in_group_own_domain = False
        self.should_remove_user_in_group_any_domain = False
        self.should_check_own_user_in_group = False
        self.should_check_user_in_group_own_domain = False
        self.should_check_user_in_group_any_domain = False
        self.should_add_user_in_group_own_domain = False
        self.should_add_user_in_group_any_domain = False
        #self.should_list_users_in_group_own_domain = False
        #self.should_list_users_in_group_any_domain = False

    def test_get_group_own_domain(self):
        with self.throws_no_exception_if(self.should_get_group_own_domain):
            self.client.get_group(self.groups['same_domain_group'])

    def test_get_group_any_domain(self):
        with self.throws_no_exception_if(self.should_get_group_any_domain):
            self.client.get_group(self.groups['other_domain_group'])

    def test_list_groups_own_domain(self):
        with self.throws_no_exception_if(self.should_list_groups_own_domain):
            self.client.list_groups(domain=self.domains('test_domain'))

    def test_list_groups_any_domain(self):
        with self.throws_no_exception_if(self.should_list_groups_any_domain):
            self.client.list_groups(domain=self.domains('other_domain'))

    def test_list_groups_for_own_user(self):
        with self.throws_no_exception_if(self.should_list_groups_for_own_user):
            self.client.list_groups(user=self.users('test_user'))

    def test_list_groups_for_any_user(self):
        with self.throws_no_exception_if(self.should_list_groups_for_any_user):
            self.client.list_groups(user=self.users('other_domain_user'))

    def test_create_group_own_domain(self):
        with self.throws_no_exception_if(self.should_create_group_own_domain):
            self.client.create_group(Group('group1', 'test_domain'))

    def test_create_group_any_domain(self):
        with self.throws_no_exception_if(self.should_create_group_any_domain):
            self.client.create_group(Group('group1', 'other_domain'))

    def _create_group(self, group):
        g = self.client.create_group(group)
        self.cloud_admin_client.delete_group(g)

    def test_update_group_own_domain(self):
        with self.throws_no_exception_if(self.should_update_group_own_domain):
            self.client.update_group(self.groups['same_domain_group'])

    def test_update_group_any_domain(self):
        with self.throws_no_exception_if(self.should_update_group_any_domain):
            self.client.update_group(self.groups['other_domain_group'])

    def test_delete_group_own_domain(self):
        with self.throws_no_exception_if(self.should_delete_group_own_domain):
            self.client.delete_group(self.groups['same_domain_group'])

    def test_delete_group_any_domain(self):
        with self.throws_no_exception_if(self.should_delete_group_any_domain):
            self.client.delete_group(self.groups['other_domain_group'])

    #def test_list_users_in_group_own_domain(self):

    #def test_list_users_in_group_any_domain(self):

    def test_remove_user_in_group_own_domain(self):
        with self.throws_no_exception_if(
                self.should_remove_user_in_group_own_domain):
            self.client.remove_user_from_group(
                self.groups['same_domain_group'],
                self.users['same_domain_user'])

    def test_remove_user_in_group_any_domain(self):
        with self.throws_no_exception_if(
                self.should_remove_user_in_group_own_domain):
            self.client.remove_user_from_group(
                self.groups['other_domain_group'],
                self.users['other_domain_user'])

    def test_check_own_user_in_group(self):
        with self.throws_no_exception_if(
                self.should_check_own_user_in_group):
            self.client.check_user_in_group(
                self.groups['same_domain_group'],
                self.users['test_user'])

    def test_check_user_in_group_own_domain(self):
        with self.throws_no_exception_if(
                self.should_check_user_in_group_own_domain):
            self.client.check_user_in_group(
                self.groups['same_domain_group'],
                self.users['same_domain_user'])

    def test_check_user_in_group_any_domain(self):
        with self.throws_no_exception_if(
                self.should_check_user_in_group_any_domain):
            self.client.check_user_in_group(
                self.groups['other_domain_group'],
                self.users['other_domain_user'])

    def test_add_user_in_group_own_domain(self):
        with self.throws_no_exception_if(
                self.should_check_user_in_group_own_domain):
            self.client.add_user_to_group(
                self.groups['same_domain_group'],
                self.users['other_domain_user'])

    def test_add_user_in_group_any_domain(self):
        with self.throws_no_exception_if(
                self.should_check_user_in_group_any_domain):
            self.client.add_user_to_group(
                self.groups['other_domain_group'],
                self.users['same_domain_user'])


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
    admin_client = Client.for_project(
        'admin', 'admin', 'demo', 'Default', config.auth_url)

    # cp setup policy to keystone policy path
    load_policy(config.setup_policy)

    # create cloud_admin role
    cloud_admin_role = admin_client.create_role(Role('cloud_admin'))

    # create cloud_admin_domain
    cloud_admin_domain = admin_client.create_domain(
        Domain('cloud_admin_domain'))

    # create cloud_admin_project
    cloud_admin_project = admin_client.create_project(
        Project('cloud_admin_project', 'cloud_admin_domain'))

    # create cloud_admin
    cloud_admin = admin_client.create_user(
        User('cloud_admin', 'cloud_admin_domain', 'cloud_admin_project'))

    # grant cloud_admin role to cloud_admin_user at cloud_admin_domain
    admin_client.grant_domain_role(
        cloud_admin_role, cloud_admin, cloud_admin_domain)

    # tests policy to keystone policy path replacing the cloud_admin_domain_id
    replace_domain_id(
        config.tests_policy, config.keystone_policy_path,
        cloud_admin_domain.id)


def tearDownModule():
    admin_client = Client.for_project(
        'admin', 'admin', 'demo', 'Default', config.auth_url)

    # cp setup policy to keystone policy path
    load_policy(config.setup_policy)

    # clear everything
    admin_client.delete_user(admin_client.find_user('cloud_admin'))
    admin_client.delete_project(
        admin_client.find_project('cloud_admin_project'))
    admin_client.delete_domain(admin_client.find_domain('cloud_admin_domain'))
    admin_client.delete_role(admin_client.find_role('cloud_admin'))

if __name__ == "__main__":
    unittest.main()
