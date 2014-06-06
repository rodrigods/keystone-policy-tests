import keystonetests
import utils
import unittest
import uuid


"""
project_member tests. Those tests run in the contest
of a project_member.
"""

class ProjectMemberTests(keystonetests.KeystonePolicyTests):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()

        # Client used during tests
        self.client = utils.create_client(self.p1member.name,
                                          'p1member',
                                          self.p1.name,
                                          self.d1.name,
                                          'http://10.1.0.22:5000/v3')


class ServicesTests(ProjectAdminTests):
    #
    # SERVICES
    #

    def test_add_service(self):
        with self.assertRaises(Exception):
            self.client.services.create('test',
                                        'volume')

    def test_list_services(self):
        try:
            self.client.services.list()
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.services.list()')

    def test_get_service(self):
        test = self._create_test_service('test', 'volume')
        try:
            self.client.services.get(test)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.services.get(test)')
        self._delete_test_service(test)

    def test_update_service(self):
        test = self._create_test_service('test', 'volume')
        with self.assertRaises(Exception):
            self.client.services.update(test, name=uuid.uuid4().hex)
        self._delete_test_service(test)

    def test_delete_service(self):
        test = self._create_test_service('test', 'volume')
        with self.assertRaises(Exception):
            self.client.services.delete(test)
        self._delete_test_service(test)


class EndpointsTests(ProjectAdminTests):
    #
    # ENDPOINTS
    #

    def test_add_endpoint(self):
        service = self._create_test_service('test', 'volume')
        with self.assertRaises(Exception):
            self.client.endpoints.create(service,
                                         url='test_url')
        self._delete_test_service(service)

    def test_list_endpoints(self):
        try:
            self.client.endpoints.list()
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.endpoints.list()')

    def test_update_endpoint(self):
        service, endpoint = self._create_test_endpoint('test_url')
        with self.assertRaises(Exception):
            self.client.endpoints.update(endpoint,
                                         interface='internal')
        self._delete_test_endpoint(service, endpoint)

    def test_delete_endpoint(self):
        service, endpoint = self._create_test_endpoint('test_url')
        with self.assertRaises(Exception):
            self.client.endpoints.delete(endpoint)
        self._delete_test_endpoint(service, endpoint)


class DomainsTests(ProjectAdminTests):
    #
    # DOMAINS
    #

    def test_add_domain(self):
        with self.assertRaises(Exception):
            utils.create_domain(self.client, 'test')

    def test_list_domains(self):
        with self.assertRaises(Exception):
            self.client.domains.list()

    def test_get_domain(self):
        # AUTHORIZED
        try:
            self.client.domains.get(self.d1)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.domains.get(self.d1)')

        # NOT AUTHORIZED
        with self.assertRaises(Exception):
            self.client.domains.get(self.d2)

    def test_update_domain(self):
        with self.assertRaises(Exception):
            self.client.domains.update(self.d1, name='d1')

    def test_list_domain_user_roles(self):
        with self.assertRaises(Exception):
            self.client.roles.list(user=self.p1admin,
                                   domain=self.d1)

    def test_list_domain_own_roles(self):
        try:
            self.client.roles.list(user=self.p1member,
                                   domain=self.d1)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.roles.list('
                      'user=self.p1member,'
                      'domain=self.d1)')

    def test_grant_user_role_in_domain(self):
        with self.assertRaises(Exception):
            utils.grant_domain_role(self.client, self.member_role.id,
                                    self.p2member.id, self.d1.id)

    def test_check_user_role_in_domain(self):
        with self.assertRaises(Exception):
            self.client.roles.check(self.member_role, user=self.p1admin,
                                    domain=self.d1)

    def test_check_own_role_in_domain(self):
        try:
            self.client.roles.check(self.member_role, user=self.p1member,
                                    domain=self.d1)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.roles.check(self.member_role'
                      'user=self.p1member,'
                      'domain=self.d1')

    def test_revoke_user_role_in_domain(self):
        with self.assertRaises(Exception):
            self.client.roles.revoke(self.member_role, user=self.p1admin,
                                     domain=self.d1)

    def test_list_domain_group_roles(self):
        with self.assertRaises(Exception):
            self.client.roles.list(group=self.g1,
                                   domain=self.d1)

    def test_grant_group_role_in_domain(self):
        with self.assertRaises(Exception):
            utils.grant_group_project_role(self.client, self.member_role.id,
                                           self.g2.id, self.d2.id)

    def test_check_group_role_in_domain(self):
        with self.assertRaises(Exception):
            self.client.roles.check(self.member_role, group=self.g2,
                                    domain=self.d2)

    def test_revoke_group_role_in_domain(self):
        with self.assertRaises(Exception):
            self.client.roles.revoke(self.member_role, group=self.g2,
                                     domain=self.d2)

    def test_delete_domain(self):
        with self.assertRaises(Exception):
            self.client.domains.delete(self.d1)


class ProjectsTests(ProjectAdminTests):
    #
    # PROJECTS
    #

    def test_get_projects(self):
        with self.assertRaises(Exception):
            self.client.projects.list()

    def test_get_project_info(self):
        # AUTHORIZED
        try:
            self.client.projects.get(self.p1)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.projects.get(self.p1)')

        # NOT AUTHORIZED
        with self.assertRaises(Exception):
            self.client.projects.get(self.p2)

    def test_update_project(self):
        description = 'new description p1'
        with self.assertRaises(Exception):
            self.client.projects.update(self.p1, description=description)

    def test_list_project_users(self):
        with self.assertRaises(Exception):
            self.client.users.list(default_project=self.p1)

    def test_list_project_user_roles(self):
        with self.assertRaises(Exception):
            self.client.roles.list(user=self.p1admin,
                                   project=self.p1)

    def test_list_project_own_roles(self):
        try:
            self.client.roles.list(user=self.p1member,
                                   project=self.p1)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.roles.list('
                      'user=self.p1member,'
                      'project=self.p1)')

    def test_grant_user_role_in_project(self):
        test1 = self._create_test_user('test1', self.p1, self.d1)

        with self.assertRaises(Exception):
            utils.grant_project_role(self.client, self.member_role.id,
                                     test1.id, self.p1.id)

        self._delete_test_user(test1)

    def test_check_user_role_in_project(self):
        with self.assertRaises(Exception):
            self.client.roles.check(self.member_role, user=self.p1admin,
                                    project=self.p1)

    def test_check_own_role_in_project(self):
        try:
            self.client.roles.check(self.member_role, user=self.p1member,
                                    project=self.p1)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.roles.check('
                      'user=self.p1member,'
                      'project=self.p1)')

    def test_revoke_user_role_in_project(self):
        with self.assertRaises(Exception):
            self.client.roles.revoke(self.member_role, user=self.p1member,
                                     project=self.p1)

    def test_list_project_group_roles(self):
        with self.assertRaises(Exception):
            self.client.roles.list(group=self.g1,
                                   project=self.p1)

    def test_grant_group_role_in_project(self):
        test1 = self._create_test_group('test1', self.d1)
        
        with self.assertRaises(Exception):
            utils.grant_group_project_role(self.client, self.member_role.id,
                                           test1.id, self.p1.id)

        self._delete_test_group(test1)

    def test_check_group_role_in_project(self):
        with self.assertRaises(Exception):
            self.client.roles.check(self.member_role, group=self.g1,
                                    project=self.p1)

    def test_revoke_group_role_in_project(self):
        with self.assertRaises(Exception):
            self.client.roles.revoke(self.member_role, group=self.g1,
                                     project=self.p1)

    def test_delete_project(self):
        with self.assertRaises(Exception):
            self.client.projects.delete(self.p1)


class UsersTests(ProjectAdminTests):
    #
    # USERS
    #

    def test_add_user(self):
        with self.assertRaises(Exception):
            utils.create_user(
                self.client, 'test', 'test',
                'test@example.com', self.p1.id,
                self.d1.id)

    def test_list_users(self):
        with self.assertRaises(Exception):
            self.client.users.list(domain=self.d1)

    def test_get_user(self):
        with self.assertRaises(Exception):
            self.client.users.get(self.p1member)

    def test_get_own_user(self):
        try:
            self.client.users.get(self.p1admin)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.users.get(self.p1admin)')

    def test_update_user_password(self):
        with self.assertRaises(Exception):
            self.client.users.update(self.p1member, password='p1member')

    def test_update_own_password(self):
        try:
            self.client.users.update(self.p1member, password='p1member')
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.users.update(self.p1member,'
                      'password=\'p1member\')')

    def test_delete_user(self):
        test1 = self._create_test_user('test1', self.p1, self.d1)
        with self.assertRaises(Exception):
            self.client.users.delete(test1)
        self._delete_test_user(test1)

    def test_list_user_groups(self):
        with self.assertRaises(Exception):
            self.client.groups.list(user=self.p1member)

    def test_list_own_groups(self):
        try:
            self.client.groups.list(user=self.p1member)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.groups.list(user=self.p1member)')

    def test_list_user_projects(self):
        with self.assertRaises(Exception):
            self.client.projects.list(user=self.p1admin)

    def test_list_own_projects(self):
        try:
            self.client.projects.list(user=self.p1member)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.projects.list(user=self.p1member)')

    def test_list_user_roles(self):
        with self.assertRaises(Exception):
            self.client.roles.list(user=self.p1admin)

    def test_list_own_roles(self):
        try:
            self.client.roles.list(user=self.p1member)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.roles.list(user=self.p1member)')


class GroupsTests(ProjectAdminTests):
    #
    # GROUPS
    #

    def test_add_group(self):
        with self.assertRaises(Exception):
            utils.create_group('test1', self.d1)

    def test_list_groups(self):
        with self.assertRaises(Exception):
            self.client.groups.list(domain=self.d1)

    def test_get_group(self):
        with self.assertRaises(Exception):
            self.client.groups.get(self.g1)

    def test_update_group(self):
        description = 'new description g1'
        with self.assertRaises(Exception):
            self.client.users.update(self.g1, description=description)

    def test_delete_group(self):
        test1 = self._create_test_group('test1', self.d1)
        with self.assertRaises(Exception):
            self.client.groups.delete(test1)
        self._delete_test_group(test1)

    def test_list_group_users(self):
        with self.assertRaises(Exception):
            self.client.users.list(group=self.g1)

    def test_add_user_group(self):
        test1 = self._create_test_user('test1', self.p1, self.d1)
        with self.assertRaises(Exception):
            self.client.users.add_to_group(test1, self.g1)
        self._delete_test_user(test1)

    def test_check_user_in_group(self):
        with self.assertRaises(Exception):
            self.client.users.check_in_group(self.p1admin, self.g1)

    def test_revoke_user_in_group(self):
        test1 = self._create_test_user('test1', self.p1, self.d1)
        self.admin_client.users.add_to_group(test1, self.g1)

        with self.assertRaises(Exception):
            self.client.users.remove_from_group(test1, self.g1)

        self.admin_client.users.remove_from_group(test1, self.g1)
        test1 = self._delete_test_user(test1)


class CredentialsTests(ProjectAdminTests):
    #
    # CREDENTIALS
    #

    def test_add_credential(self):
        blob = {'access': 'access', 'secret': 'secret'}
        with self.assertRaises(Exception):
            self.client.credentials.create(self.p1member, 'ec2',
                                           blob=blob,
                                           project=self.p1)

    def test_list_credentials(self):
        with self.assertRaises(Exception):
            self.client.credentials.list(project=self.p1)

    def test_get_credential(self):
        blob = {'access': 'access', 'secret': 'secret'}
        test1 = self._create_test_credential(self.p1member, 'ec2',
                                             blob, self.p1)
        with self.assertRaises(Exception):
            self.client.credentials.get(test1)

        self._delete_test_credential(test1)

    def test_update_credential(self):
        blob = {'access': 'access', 'secret': 'secret'}
        test1 = self._create_test_credential(self.p1member, 'ec2',
                                             blob, self.p1)
        with self.assertRaises(Exception):
            self.client.credentials.update(test1, blob=blob)

        self._delete_test_credential(test1)

    def test_delete_credential(self):
        blob = {'access': 'access', 'secret': 'secret'}
        test1 = self._create_test_credential(self.p1member, 'ec2',
                                             blob, self.p1)
        with self.assertRaises(Exception):
            self.client.credentials.delete(test1)

        self._delete_test_credential(test1)


class RolesTests(ProjectAdminTests):
    #
    # ROLES
    #

    def test_add_role(self):
        with self.assertRaises(Exception):
            self.client.roles.create('test')

    def test_list_roles(self):
        with self.assertRaises(Exception):
            self.client.roles.list()

    def test_get_role(self):
        test = self._create_test_role('test')

        try:
            self.client.roles.get(test)
        except:
            self.fail('Unexpected exception raised: '
                      'self.client.roles.get(test)')

        self._delete_test_role(test)

    def test_update_role(self):
        test = self._create_test_role('test')

        with self.assertRaises(Exception):
            self.client.roles.update(test, name='test')

        self._delete_test_role(test)

    def test_delete_role(self):
        test = self._create_test_role('test')

        with self.assertRaises(Exception):
            self.client.roles.delete(test)

        self._delete_test_role(test)


# class PoliciesTests(ProjectAdminTests):
#     #
#     # POLICIES
#     #

#     def test_add_policy(self):
#         with self.assertRaises(Exception):
#             self.client.policies.create(uuid.uuid4().hex)

#     def test_list_policies(self):
#         with self.assertRaises(Exception):
#             self.client.policies.list()

#     def test_get_policy(self):
#         test = self._create_test_policy(uuid.uuid4().hex)
#         with self.assertRaises(Exception):
#             self.client.policies.get(test)
#         self._delete_test_policy(test)

#     def test_update_policy(self):
#         test = self._create_test_policy(uuid.uuid4().hex)
#         with self.assertRaises(Exception):
#             self.client.policies.update(blob=uuid.uuid4().hex,
#                                         type=uuid.uuid4().hex)
#         self._delete_test_policy(test)

#     def test_delete_test_policy(self):
#         test = self._create_test_policy(uuid.uuid4().hex)
#         with self.assertRaises(Exception):
#             self.client.policies.delete(test)
#         self._delete_test_policy(test)


def suite():
    """
        Gather all the tests from this module in a test suite.
    """
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(ServicesTests))
    test_suite.addTest(unittest.makeSuite(EndpointsTests))
    test_suite.addTest(unittest.makeSuite(DomainsTests))
    test_suite.addTest(unittest.makeSuite(ProjectsTests))
    test_suite.addTest(unittest.makeSuite(UsersTests))
    test_suite.addTest(unittest.makeSuite(GroupsTests))
    test_suite.addTest(unittest.makeSuite(CredentialsTests))
    test_suite.addTest(unittest.makeSuite(RolesTests))
    #test_suite.addTest(unittest.makeSuite(PoliciesTests))
    return test_suite

runner = unittest.TextTestRunner()
runner.run(suite())
