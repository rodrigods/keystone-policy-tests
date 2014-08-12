from keystoneclient.v3 import client


def create_client_domain(username, password,
                         domain_name, auth_url):
    return client.Client(username=username,
                         password=password,
                         user_domain_name=domain_name,
                         domain_name=domain_name,
                         auth_url=auth_url)


def create_client(username, password, project_name,
                  domain_name, auth_url):
    return client.Client(username=username,
                         password=password,
                         user_domain_name=domain_name,
                         project_name=project_name,
                         project_domain_name=domain_name,
                         auth_url=auth_url)


def find_group(client, name):
    return client.groups.find(name=name)


def find_user(client, name):
    return client.users.find(name=name)


def find_project(client, name):
    return client.projects.find(name=name)


def find_domain(client, name):
    return client.domains.find(name=name)


def find_role(client, name):
    return client.roles.find(name=name)


def create_domain(client, name):
    try:
        d = client.domains.create(name=name)
    except Exception:
        d = find_domain(client, name)
    return d


def create_project(client, name, domain):
    try:
        p = client.projects.create(name=name, description='optional',
                                   domain=domain)
    except Exception:
        p = find_project(client, name)
    return p


def create_user(client, name, password, email, default_project, domain):
    try:
        u = client.users.create(name=name, password=password,
                                description='optional',
                                domain=domain, email=email,
                                default_project=default_project)
    except Exception:
        u = find_user(client, name)
    return u


def create_group(client, name, domain):
    try:
        u = client.groups.create(name=name,
                                 description='optional',
                                 domain=domain)
    except Exception:
        u = find_group(client, name)
    return u


def create_role(client, name):
    try:
        r = client.roles.create(name=name)
    except Exception:
        r = find_role(client, name)
    return r


def grant_project_role(client, role, user, project):
    client.roles.grant(role, user=user, project=project)


def grant_domain_role(client, role, user, domain):
    client.roles.grant(role, user=user, domain=domain)


def grant_group_project_role(client, role, group, project):
    client.roles.grant(role, group=group, project=project)


def grant_group_domain_role(client, role, group, domain):
    client.roles.grant(role, group=group, domain=domain)
