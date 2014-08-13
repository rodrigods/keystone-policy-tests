
import models

from keystoneclient.v3 import client as keystoneclient


class Client:

    def __init__(self, keystone_client):
        self.client = keystone_client

    @classmethod
    def for_project(cls, username, password, project, project_domain, auth_url):
        return Client(keystoneclient.Client(username=username,
                                            password=password,
                                            user_domain_name=project_domain,
                                            project_name=project,
                                            project_domain_name=project_domain,
                                            auth_url=auth_url))

    @classmethod
    def for_domain(cls, username, password, domain_name, auth_url):
        return Client(keystoneclient.Client(username=username,
                                            password=password,
                                            user_domain_name=domain_name,
                                            domain_name=domain_name,
                                            auth_url=auth_url))

    def find_domain(self, name):
        return self.client.domains.find(name=name)

    def find_project(self, name):
        return self.client.projects.find(name=name)

    def get_project(self, project):
        return self.client.projects.get(project)

    def list_projects(self, user=None):
        return self.client.projects.list(user=user)

    def update_project(self, project):
        return self.client.projects.update(project, description='new description')

    def find_group(self, name):
        return self.client.groups.find(name=name)

    def find_user(self, name):
        return self.client.users.find(name=name)

    def find_role(self, name):
        return self.client.roles.find(name=name)

    def create_domain(self, domain):
        try:
            d = self.client.domains.create(name=domain.name)
        except Exception:
            d = self.find_domain(domain.name)
        return d

    def delete_domain(self, domain):
        self.client.domains.update(domain, enabled=False)
        self.client.domains.delete(domain)

    def create_project(self, project):
        d = self.find_domain(project.domain)
        try:
            p = self.client.projects.create(name=project.name,
                                            description='optional',
                                            domain=d)
        except Exception:
            p = self.find_project(project.name)
        return p

    def delete_project(self, project):
        self.client.projects.delete(project)

    def create_user(self, user):
        d = self.find_domain(user.domain)
        p = self.find_project(user.default_project)
        try:
            u = self.client.users.create(name=user.name,
                                         password=user.password,
                                         description='optional',
                                         email=user.email,
                                         domain=d,
                                         default_project=p)
        except Exception:
            u = self.find_user(user.name)
        return u

    def delete_user(self, user):
        self.client.users.delete(user)

    def create_group(self, group):
        d = self.find_domain(group.domain)
        try:
            g = self.client.groups.create(name=group.name,
                                          description='optional',
                                          domain=d)
        except Exception:
            g = self.find_group(group.name)
        return g

    def delete_group(self, group):
        self.client.groups.delete(group)

    def create_role(self, role):
        try:
            r = self.client.roles.create(name=role.name)
        except Exception:
            r = self.find_role(role.name)
        return r

    def delete_role(self, role):
        self.client.roles.delete(role)

    def grant_project_role(self, role, user, project):
        self.client.roles.grant(role, user=user, project=project)

    def grant_domain_role(self, role, user, domain):
        self.client.roles.grant(role, user=user, domain=domain)

    def grant_group_project_role(self, role, group, project):
        self.client.roles.grant(role, group=group, project=project)

    def grant_group_domain_role(self, role, group, domain):
        self.client.roles.grant(role, group=group, domain=domain)

    def create_region(self):
        pass

    def read_region(self):
        pass

    def update_region(self):
        pass

    def delete_region(self):
        pass
