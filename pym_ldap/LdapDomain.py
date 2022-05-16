from .LdapObject import LdapObject
from .LdapObjectCollection import LdapObjectCollection
from .LdapDomainInterface import LdapDomainInterface
from .BaseLdapDomain import BaseLdapDomain
import typing
import inspect


class LdapDomain(LdapDomainInterface):
    def __init__(self, name: str):
        self.domain = BaseLdapDomain(name=name)

    @property
    def current_user(self) -> LdapObject:
        return LdapObject(self.domain.user)
    
    def connect(self, username: str, password: str) -> bool:
        return self.domain.connect(username=username, password=password)
    
    def configure(self, json_file_path: str):
        self.domain.configure(json_file_path=json_file_path)
    
    def get_object(self, uniq_value: str, properties: typing.List[str] = None, object_class: str = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_object).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_object(**kwargs))
    
    def get_objects(self, uniq_values: typing.List[str], properties: typing.List[str] = None, object_class: str = None) \
            -> LdapObjectCollection:
        args = inspect.getfullargspec(self.get_objects).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.get_objects(**kwargs))

    def get_user(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_user).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_user(**kwargs))

    def get_group(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_group).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_group(**kwargs))

    def get_org_unit(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        args = inspect.getfullargspec(self.get_org_unit).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_org_unit(**kwargs))

    def get_user_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_user_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_user_ex(**kwargs))

    def get_group_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_object).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_group_ex(**kwargs))

    def get_org_unit_ex(self, uniq_value: str) -> LdapObject:
        args = inspect.getfullargspec(self.get_org_unit_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObject(self.domain.get_org_unit_ex(**kwargs))

    def search_objects(self, property_name: str = None, property_value: str = None, search_base: str = None,
                       properties: typing.List[str] = None, object_class: str = None, recursive: bool = True,
                       properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_objects).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_objects(**kwargs))

    def search_users(self, property_name: str = None, property_value: str = None, search_base: str = None,
                     properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_users).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_users(**kwargs))

    def search_groups(self, property_name: str = None, property_value: str = None, search_base: str = None,
                      properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_groups).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_groups(**kwargs))

    def search_org_units(self, property_name: str = None, property_value: str = None, search_base: str = None,
                         properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_org_units).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_org_units(**kwargs))

    def search_users_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                        properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_users_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_users_ex(**kwargs))

    def search_groups_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                         properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_groups_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_groups_ex(**kwargs))

    def search_org_units_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                            properties_dict: dict = None) -> LdapObjectCollection:
        args = inspect.getfullargspec(self.search_org_units_ex).args[1:]
        kwargs = {k: v for k, v in locals().items() if k in args}
        return LdapObjectCollection(self.domain.search_org_units_ex(**kwargs))

    def get_group_members(self, group: LdapObject):
        result = LdapObjectCollection()
        if group.is_group and group.get_property_value("member"):
            member_dns = group.get_property_value("member")
            for member_dn in member_dns:
                result.append(self.get_object(member_dn))
        return result

    def __str__(self):
        return str(self.domain)

