import unittest

from keystonetest import *


class ProjectAdminProjectTestCase(ProjectTestCase, unittest.TestCase):

    def role_name(self):
        return 'project_admin'

    def setUp(self):
        super(ProjectAdminProjectTestCase, self).setUp()

        self.should_get_projects = False
        self.should_get_own_project_info = True
        self.should_get_any_project_info = False
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


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ProjectAdminProjectTestCase))
    return suite

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
