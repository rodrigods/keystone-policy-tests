
import models

from keystoneclient.v3 import client as keystoneclient

class Client:

    def __init__(self, keystone_client):
        self.client = keystone_client

    @classmethod
    def for_project(cls, user_name, password, project, auth_url):
        return Client(keystoneclient.Client(username=user_name,
                                            password=password,
                                            user_domain_name=user.domain.name,
                                            project_name=project.name,
                                            project_domain_name=project.domain.name,
                                            auth_url=auth_url))
    @classmethod
    def for_domain(cls, user_name, password, domain_name, auth_url):
        return keystoneclient.Client(username=user_name,
                                     password=password,
                                     domain_name=domain_name,
                                     auth_url=auth_url)


    def create_region(self):
    	pass

    def read_region(self):
    	pass

    def update_region(self):
    	pass

    def delete_region(self):
    	pass

	# CRUD for each model