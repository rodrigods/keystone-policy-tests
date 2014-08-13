import unittest

from keystonetest import *
from utils.client import *

class ProjectAdminUserTestCase(UserTestCase, unittest.TestCase):
    def create_test_client(self):
        return Client.for_project('test_user', 'test_user', 'test_project', 'test_domain', config.auth_url)

    def role_name(self):
        return 'project_admin'

    def setUp(self):
        super(ProjectAdminUserTestCase, self).setUp()

        self.should_get_own_user = True
        self.should_get_user_own_domain = False
        self.should_get_user_any_domain = False
        self.should_list_own_domain_users = False
        self.should_list_any_domain_users = False
        self.should_create_user_own_domain = False
        self.should_create_user_any_domain = False
        self.should_update_own_user = True
        self.should_update_user_own_domain = False
        self.should_update_user_any_domain = False
        self.should_delete_own_user = False
        self.should_delete_user_own_domain = False
        self.should_delete_user_any_domain = False
        self.should_update_own_user_password = True
        self.should_update_user_password_own_domain = False
        self.should_update_user_password_any_domain = False


class ProjectAdminProjectTestCase(ProjectTestCase, unittest.TestCase):

    def create_test_client(self):
        return Client.for_project('test_user', 'test_user', 'test_project', 'test_domain', config.auth_url)

    def role_name(self):
        return 'project_admin'

    def setUp(self):
        super(ProjectAdminProjectTestCase, self).setUp()

        self.should_list_projects = False
        self.should_get_own_project_info = True
        self.should_get_any_project_info = False
        self.should_update_own_project = True
        self.should_update_any_project = False
        self.should_delete_own_project = True
        self.should_delete_any_project = False
        self.should_list_own_user_projects = True
        self.should_list_any_user_projects = False


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ProjectAdminProjectTestCase))
    suite.addTest(unittest.makeSuite(ProjectAdminUserTestCase))
    return suite

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
