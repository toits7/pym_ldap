import os
import keyring
import pym_ldap as ldap

if __name__ == "__main__":
    domain = ldap.LdapDomain("tgngu.loc")
    print(domain)
    username = f"{os.environ['USERNAME']}"
    password = keyring.get_password(service_name="ldapgui", username=username)
    if password:
        domain.connect(username=username, password=password)
        print(domain)
