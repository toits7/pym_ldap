import typing
from typing import List
from .LdapObject import LdapObject
from .BaseLdapObjectCollection import BaseLdapObjectCollection


class LdapObjectCollection(typing.List[LdapObject], BaseLdapObjectCollection):
    def __init__(self, list_dicts: List[dict] = None):
        super(LdapObjectCollection, self).__init__()
        if list_dicts:
            for ldap_object_dict in list_dicts:
                self.append(LdapObject(ldap_object_dict))


