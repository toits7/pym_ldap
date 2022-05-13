class LdapObject:
    __multi_val_props = ["memberOf", "member"]

    def __init__(self, ldap_entry: dict):
        self.__properties = ldap_entry

    @property
    def dn(self) -> str:
        return self.__properties["distinguishedName"]

    @property
    def name(self) -> str:
        return self.__properties["name"]

    @property
    def object_class(self) -> str:
        return self.__properties["objectClass"][-1]

    @property
    def is_user(self) -> bool:
        return self.object_class == "user"

    @property
    def is_group(self) -> bool:
        return self.object_class == "group"

    @property
    def is_org_unit(self) -> bool:
        return self.object_class == "organizationalUnit"

    def __str__(self) -> str:
        return self.name




