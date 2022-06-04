class LdapObject:
    __multi_val_props = ["memberof", "member", "objectclass"]
    _user_id_property_name: str
    _group_id_property_name: str
    _org_unit_id_property_name: str

    def __init__(self, ldap_entry: dict):
        self._properties = ldap_entry

    def __str__(self) -> str:
        return self.name

    def __repr__(self):
        return f"LdapObject({self._properties})"

    def __call__(self, property_name: str):
        #if self.has_property(property_name=property_name):
            #property_value = self.__getattr__(property_name)
        #elif property_name in self.__dict__:
            #property_value = self.__getattribute__(property_name)
        #else:
            #property_value = None
        try:
            property_value = self.__getattribute__(property_name)
        except:
            if self.has_property(property_name):
                property_value = self._properties[property_name]
            else:
                property_value = None
        if isinstance(property_value, list) and property_name.lower() not in self.__multi_val_props:
            property_value = ' '.join(property_value)
        return property_value

    def __getattr__(self, property_name: str):
        try:
            property_value = self._properties[property_name]
            if isinstance(property_value, list) and property_name.lower() not in self.__multi_val_props:
                property_value = ' '.join(property_value)
            return property_value
        except:
            return None

    @property
    def dn(self) -> str:
        return self.__getattr__("distinguishedName")

    @property
    def name(self) -> str:
        return self.__getattr__("name")

    @property
    def object_class(self) -> str:
        return self.__getattr__("objectClass")[-1]

    @property
    def id(self) -> str:
        if self.is_user and self._user_id_property_name:
            return self.__getattr__(self._user_id_property_name)
        if self.is_group and self._group_id_property_name:
            return self.__getattr__(self._group_id_property_name)
        if self.is_org_unit and self._org_unit_id_property_name:
            return self.__getattr__(self._org_unit_id_property_name)
        else:
            return ""

    def is_user(self) -> bool:
        return self.object_class == "user"

    def is_group(self) -> bool:
        return self.object_class == "group"

    def is_org_unit(self) -> bool:
        return self.object_class == "organizationalUnit"

    def is_computer(self) -> bool:
        return self.object_class == "computer"

    def has_property(self, property_name: str):
        return property_name in self._properties


"""
    def get_property_value(self, property_name: str):
        if property_name in self._properties:
            property_value = self._properties[property_name]
            if isinstance(property_value, list) and property_name.lower() not in self.__multi_val_props:
                property_value = ' '.join(property_value)
            return property_value
        else:
            return ""


"""
