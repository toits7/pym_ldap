import typing

class LdapObject:
    __multi_val_props = ["memberof", "member"]
    _user_id_property_name: str
    _group_id_property_name: str
    _org_unit_id_property_name: str

    def __init__(self, ldap_entry: dict):
        self._properties = ldap_entry

    @property
    def dn(self) -> str:
        return self._properties["distinguishedName"]

    @property
    def name(self) -> str:
        return self._properties["name"]

    @property
    def object_class(self) -> str:
        return self._properties["objectClass"][-1]

    @property
    def is_user(self) -> bool:
        return self.object_class == "user"

    @property
    def is_group(self) -> bool:
        return self.object_class == "group"

    @property
    def is_org_unit(self) -> bool:
        return self.object_class == "organizationalUnit"

    @property
    def description(self) -> str:
        return ' '.join(self._properties["description"])

    def get_property_value(self, property_name: str):
        if property_name in self._properties:
            property_value = self._properties[property_name]
            if isinstance(property_value, list) and property_name.lower() not in self.__multi_val_props:
                property_value = ' '.join(property_value)
            return property_value
        else:
            return ""

    def __str__(self) -> str:
        return self.name
