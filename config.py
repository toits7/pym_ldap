from pym_ldap import LdapDomain

#domain = LdapDomain()
domain = LdapDomain("tgngu.loc")
domain.configure("domain.json")
