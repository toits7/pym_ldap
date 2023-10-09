from .LdapObject import LdapObject
from .LdapObjectCollection import LdapObjectCollection
from .BaseLdapDomain import BaseLdapDomain
import typing
import inspect


class LdapDomain(BaseLdapDomain):

    def __init__(self, name: str = None, server: str = None):
        super(LdapDomain, self).__init__(name=name, server=server)

    def configure(self, external_name: str = None, default_search_base: str = None,
                  disabled_org_unit_dn: str = None, user_properties: typing.List[str] = None,
                  group_properties: typing.List[str] = None, org_unit_properties: typing.List[str] = None,
                  user_id_property_name: str = None, group_id_property_name: str = None,
                  org_unit_id_property_name: str = None, computer_properties: typing.List[str] = None):
        args = inspect.getfullargspec(self.configure).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        super(LdapDomain, self).configure(**kwargs)
        if self._user_id_property_name:
            LdapObject._user_id_property_name = self._user_id_property_name
        if self._group_id_property_name:
            LdapObject._group_id_property_name = self._group_id_property_name
        if self._org_unit_id_property_name:
            LdapObject._org_unit_id_property_name = self._org_unit_id_property_name
    
    @property
    def current_user(self) -> LdapObject:
        return LdapObject(self._current_user)

    def get_object(self, uniq_value: str, properties: typing.List[str] = None,
                   object_class: str = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_object).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_object(**kwargs))

    def get_objects(self, uniq_values: typing.List[str], properties: typing.List[str] = None,
                    object_class: str = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.get_objects).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._get_objects(**kwargs))

    def get_user(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_user).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_user(**kwargs))

    def get_group(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_group).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_group(**kwargs))

    def get_org_unit(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_org_unit).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_org_unit(**kwargs))

    def get_computer(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_computer).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_computer(**kwargs))

    def get_user_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_user_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_user_ex(**kwargs))

    def get_group_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_object).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_group_ex(**kwargs))

    def get_org_unit_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_org_unit_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_org_unit_ex(**kwargs))

    def get_computer_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_computer_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self._get_computer_ex(**kwargs))

    def search_objects(self, property_name: str = None, property_value: str = None, search_base: str = None,
                       properties: typing.List[str] = None, object_class: str = None, recursive: bool = True,
                       properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_objects).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_objects(**kwargs))

    def search_users(self, property_name: str = None, property_value: str = None, search_base: str = None,
                     properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_users).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_users(**kwargs))

    def search_groups(self, property_name: str = None, property_value: str = None, search_base: str = None,
                      properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_groups).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_groups(**kwargs))

    def search_org_units(self, property_name: str = None, property_value: str = None, search_base: str = None,
                         properties: typing.List[str] = None, recursive: bool = True,
                         properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_org_units).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_org_units(**kwargs))

    def search_computers(self, property_name: str = None, property_value: str = None, search_base: str = None,
                         properties: typing.List[str] = None, recursive: bool = True,
                         properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_computers).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_computers(**kwargs))

    def search_users_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                        properties_dict: dict = None, search_base: str = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_users_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_users_ex(**kwargs))

    def search_groups_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                         properties_dict: dict = None, search_base: str = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_groups_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_groups_ex(**kwargs))

    def search_org_units_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                            properties_dict: dict = None, search_base: str = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_org_units_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_org_units_ex(**kwargs))

    def search_computers_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                            properties_dict: dict = None, search_base: str = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_computers_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self._search_computers_ex(**kwargs))

    def get_group_members(self, group: LdapObject) -> LdapObjectCollection:
        result = LdapObjectCollection()
        if group.is_group and group("member"):
            member_dns = group("member")
            for member_dn in member_dns:
                result.append(self.get_object(member_dn))
        return result

    def get_group_membership(self, object_dn, properties: typing.List[str] = ("member",)) -> LdapObjectCollection:
        return LdapObjectCollection(self._get_group_membership(object_dn=object_dn, properties=properties))

    def get_group_manager(self, group_dn: str, properties: typing.List[str] = None) -> LdapObject:
        return LdapObject(self._get_group_manager(group_dn=group_dn, properties=properties))
