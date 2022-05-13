from typing import List
from .LdapObject import LdapObject


class LdapObjectCollection(List[LdapObject]):
    def __init__(self, list_dicts: List[dict] = None):
        super(LdapObjectCollection, self).__init__()
        if list_dicts:
            for ldap_object_dict in list_dicts:
                self.append(LdapObject(ldap_object_dict))

    def __str__(self) -> str:
        result = "["
        for object_index in range(self.__len__()):
            if object_index == (self.__len__() - 1):
                result = result + "'" + str(self[object_index]) + "'"
            else:
                result = result + "'" + str(self[object_index]) + "'" + ', '
        return result + "]"

    @property
    def dn(self) -> List[str]:
        if len(self) > 0:
            dns = []
            for item in self:
                dns.append(item.dn)
            return dns
        else:
            return list()

    def get_by_dn(self, dn: str) -> LdapObject:
        for item in self:
            if item.dn == dn:
                return item

