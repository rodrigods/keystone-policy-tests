Policy tests to OpenStack Identity API (Keystone)
=================================================

This project provides a sample policy.json that defines four
different roles:

- A super admin, which is able to peform any operation in the cloud scope: cloud_admin
- A project scope admin: project_admin
- A domain scope admin: domain_admin
- A project scope member: project_member

Also, tests scripts are provided for each role described above. They test 
if a user with a given role is able to peform the actions it should be
able to perform.

Those tests, create and delete actual elements. They were designed to be executed
in a running devstack environment.

Tests setup
-------------

There is a script called ``cloud_admin_setup.py`` under the setup folder.
It creates a user called cloud_admin, a project called cloud_admin_project
and a domain cloud_admin_domain. Will be considered a cloud_admin, a user
which matches the following rule:

    "admin_required": "(role:admin or is_admin:1) and domain_id:cloud_admin_domain_id"

The ``cloud_admin_setup.py``script will output an id to replace ``cloud_admin_domain_id``.

After that, you can replace or use the provided policy.json file as your
default policies file.

Running the tests
-----------------

After the tests setup, just run the tests directly:

    python project_admin_tests.py

If you are interested in a smaller set of tests, open the tests file and comment
the not interesting ones.
