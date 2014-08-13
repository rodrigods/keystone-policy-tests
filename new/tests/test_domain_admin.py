import unittest

from keystonetest import *


class ProjectAdminProjectTestCase(ProjectTestCase, unittest.TestCase):
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
    return suite

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
