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
    
    def __call__(self, uniq_value: str) -> LdapObject:
        return super(LdapObjectCollection, self).__call__(uniq_value=uniq_value)

"""


class LdapObjectCollection(typing.Dict[str, LdapObject]):
    def __init__(self, list_dicts: List[dict] = None):
        super(LdapObjectCollection, self).__init__()
        self.ldap_objects: typing.List[LdapObject] = list()
        if list_dicts:
            for ldap_object_dict in list_dicts:
                self.add(LdapObject(ldap_object_dict))

    def add(self, ldap_object: LdapObject):
        if ldap_object.dn not in self.keys():
            self.ldap_objects.append(ldap_object)
            self[ldap_object.dn] = ldap_object

    def remove(self, ldap_object: LdapObject):
        if ldap_object.dn in self.keys():
            removed = self.pop(ldap_object.dn)
            self.ldap_objects.remove(removed)

    @property
    def dn(self) -> typing.List[str]:
        return [ldap_object.dn for ldap_object in self.ldap_objects]
    
    def __iter__(self):
        return self.ldap_objects.__iter__()

"""