
class Region:
    pass


class Service:
    pass


class Endpoint:
    pass


class Domain:
    def __init__(self, name):
        self.name = name


class Project:
    def __init__(self, name, domain):
        self.name = name
        self.domain = domain


class User:
    def __init__(self, name, password, domain, default_project, email=None):
        self.name = name
        self.password = password
        self.email = email
        self.domain = domain
        self.default_project = default_project


class Group:
    pass


class Credential:
    pass


class Role:
    pass


class Grant:
    pass


class Policy:
    pass


class Token:
    pass


class Trust:
    pass


class Consumer:
    pass


class AccessToken:
    pass


class RequestToken:
    pass


class IdentityProvider:
    pass


class Protocol:
    pass


class Mapping:
    pass
