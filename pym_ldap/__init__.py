from .LdapObject import LdapObject
from .LdapObjectCollection import LdapObjectCollection
from .LdapDomain import LdapDomain
import typing

domain: typing.Optional[LdapDomain]
try:
    domain = LdapDomain()
except:
    domain = None


def set_domain(ldap_domain: LdapDomain):
    global domain
    domain = ldap_domain


