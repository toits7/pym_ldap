import os
import json
import typing

import ldap3
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as add_group_member
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups as remove_group_member
from .LdapObject import LdapObject
from .LdapObjectCollection import LdapObjectCollection
import inspect
from operator import itemgetter
from .Functions import grant_write_property_access, reset_ldap_object_access
import pym_logger as logger
import re

log = logger.get_logger(__name__)
begin_str = '=' * 50 + "НАЧАЛО" + '=' * 50
end_str = '=' * 50 + "КОНЕЦ" + '=' * 50

def search_user_wrapper(search_func):
    def search(*args, **kwargs):
        pass


class LdapDomain:
    __connection: ldap3.Connection = None
    __mandatory_properties = ("name", "distinguishedName", "objectClass")

    def __init__(self, name: str, server: str = None):
        self._name = name.lower()
        name_parts = self._name.split('.')
        dn_parts = list()
        for name_part in name_parts:
            dn_parts.append("dc=" + name_part)
        if server:
            self._server = server
        else:
            self._server = name.lower()
        self._netbios_name = name_parts[0].upper()
        self._dn = ','.join(dn_parts)
        self._properties = dict()
        self._current_user: LdapObject = None

    def connect(self, username: str, password: str) -> bool:
        if self.server:
            if self.__connection is not None:
                log.info(f"Отключение от подключения к контроллеру домена '{self.__connection.server.name}'")
                self.__connection.unbind()
            if "\\" not in username:
                username = self.net_bios_name + "\\" + username
            connection = ldap3.Connection(server=self.server, user=username, password=password,
                                          return_empty_attributes=True)
            connection.server.connect_timeout = 10
            try:
                if connection.bind():
                    if connection.result.get("description") == "success":
                        log.info(f"Подключение к контроллеру домена '{connection.server.name}' УСПЕШНО")
                        self.__connection = connection
                        self.__configure()
                        return True
                    else:
                        log.warning(f"Подключение к контроллеру домена '{connection.server.name}' ОШИБКА")
                        log.warning(f"{connection.result.get('description')}")
                        return False
                else:
                    log.warning(f"Подключение к контроллеру домена '{connection.server.name}' ОШИБКА")
                    log.warning(f"{connection.result.get('description')}")
                    return False
            except Exception as e:
                print(e)
                return False

    @property
    def name(self) -> str:
        return self._name

    @property
    def net_bios_name(self) -> str:
        return self._netbios_name

    @property
    def server(self) -> str:
        return self._server

    @property
    def user(self) -> LdapObject:
        return self._current_user

    @property
    def properties(self) -> typing.Dict[str, str]:
        return self._properties

    def __configure(self):
        log.info(f"Конфигурирование домена")
        if self.__connection and not self.__connection.closed:
            log.debug("Запрос аттрибутов из схемы домен контроллера")
            for k, v in self.__connection.server.schema.attribute_types._case_insensitive_keymap.items():
                if not k.startswith("ms"):
                    self._properties[k] = v
            log.debug("Получение текущего пользователя из домена")
            samaccountname = re.sub(r".*\\", "", self.__connection.user)
            self._current_user = self.get_user(uniq_value=samaccountname)
        else:
            log.critical("Отсутствует соединение с сервером")

    def __search(self, search_filter: str, search_base: str, search_scope: str, search_properties: list) -> typing.List[dict]:
        results = list()
        if self.__connection is not None:
            if search_filter is None or search_filter == "":
                log.error("Пустой search_filter, запрос не возможен.")
                return results
            if search_base is None or search_base == "":
                log.error("Пустой search_base, запрос не возможен.")
                return results
            if search_properties is None or search_properties == "" or len(search_properties) == 0:
                log.error("Пустой search_properties, запрос не возможен.")
                return results
            if search_scope is None or search_scope == "":
                log.error("Пустой search_scope, запрос не возможен.")
                return results
            try:
                args = inspect.getfullargspec(self.__search).args[1:]
                kwargs = {k: v for k, v in locals().items() if k in args}
                arg_string = str(kwargs)
                log.debug(f"Выполнение поискового запроса в каталоге параметрами: {arg_string}")
                generator = self.__connection.extend.standard.paged_search(search_filter=search_filter,
                                                                           search_base=search_base,
                                                                           search_scope=search_scope,
                                                                           attributes=search_properties,
                                                                           paged_size=1000,
                                                                           generator=True)
                for ldapentry in generator:
                    if "attributes" in ldapentry.keys() and len(ldapentry["attributes"]["distinguishedName"]) != 0 and \
                            len(ldapentry["attributes"]["name"]) != 0 and \
                            len(ldapentry["attributes"]["objectClass"]) != 0 and \
                            ldapentry["attributes"]["distinguishedName"] != search_base:
                        results.append(ldapentry["attributes"])
                results = sorted(results, key=itemgetter("name"))
            except Exception as e:
                log.error(f"Ошибка при выполнении поискового запроса: {e}")
        else:
            log.error("Не возможно выполнить запрос на сервер так как отсутствует соединение.")
        return results

    def __get_filter(self, uniq_value: str = None, property_name: str = None, property_value: str = None,
                     properties_dict: dict = None, object_class: str = None):
        log.debug("Генерация фильтра поиска")
        search_filter = ""
        if uniq_value is not None:
            uniq_property_name = self.__get_property_name(property_value=uniq_value, object_class=object_class)
            if uniq_property_name:
                search_filter += f"({uniq_property_name}={uniq_value})"
        if property_name is not None and property_value is not None:
            search_filter += f"({property_name}={property_value})"
        if properties_dict is not None:
            for key, value in properties_dict.items():
                search_filter += f"({key}={value})"
        if object_class is not None:
            if object_class.lower() == "user":
                search_filter += f"(objectClass={object_class})"
            elif object_class.lower() == "group":
                search_filter += f"(objectClass={object_class})"
            elif object_class.lower() == "orgunit" or object_class.lower() == "organizationalunit":
                search_filter += f"(objectClass={object_class})"
        else:
            search_filter += "(objectclass=*)"
        search_filter = f"(&{search_filter})"
        log.debug(f"Сгенерирован фильтр поиска: '{search_filter}'")
        return search_filter

    def __get_property_name(self, property_value: str, object_class: str = None):
        log.debug(f"Получение имени аттрибута по значению '{property_value}' и классу '{object_class}'")
        property_name: str
        if property_value.endswith(self._dn):
            property_name = "distinguishedName"
        else:
            property_name = "sAMAccountName"
        log.debug(f"Получено имя аттрибута '{property_name}'")
        return property_name
    
    def __get_properties(self, properties: typing.List[str]) -> typing.List[str]:
        if properties:
            search_properties = list(set(properties) | set(self.__mandatory_properties))
        else:
            search_properties = self.__mandatory_properties
        return search_properties

    def __get_class_properties(self, object_class):
        log.debug(f"Получение словаря аттрибутов для класса {object_class}")
        if self.__connection:
            class_def = ldap3.ObjectDef(object_class, self.__connection)
            if class_def:
                if "_attributes" in class_def.__dict__:
                    log.debug(f"Получение словаря аттрибутов для класса {object_class}: УСПЕХ")
                    return class_def.__dict__["_attributes"].__dict__["_case_insensitive_keymap"]
        log.error(f"Получение словаря аттрибутов для класса {object_class}: ОШИБКА")
        
    def get_object(self, uniq_value: str, properties: typing.List[str] = None, object_class: str = None) -> LdapObject:
        search_filter = self.__get_filter(uniq_value=uniq_value, object_class=object_class)
        search_properties = self.__get_properties(properties)
        entries = self.__search(search_filter, self._dn, ldap3.SUBTREE, search_properties)
        if entries and len(entries) > 0:
            return LdapObject(entries[0])
         
    def get_user(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        return self.get_object(uniq_value=uniq_value, properties=properties, object_class="user")
    
    def get_group(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        return self.get_object(uniq_value=uniq_value, properties=properties, object_class="group")
    
    def get_org_unit(self, uniq_value: str, properties: typing.List[str] = None) -> LdapObject:
        return self.get_object(uniq_value=uniq_value, properties=properties, object_class="organizationalUnit")
    
    def search_objects(self, property_name: str, property_value: str, search_base: str = None, 
                       properties: typing.List[str] = None, object_class: str = None, recursive: bool = True) \
            -> LdapObjectCollection:
        search_filter = self.__get_filter(property_name=property_name, property_value=property_value, 
                                          object_class=object_class)
        if not search_base:
            search_base = self._dn
        if recursive:
            search_scope = ldap3.SUBTREE
        else:
            search_scope = ldap3.LEVEL
        search_properties = self.__get_properties(properties)
        entries = self.__search(search_filter, search_base, search_scope, search_properties)
        return LdapObjectCollection(entries)
    
    def search_users(self, property_name: str, property_value: str, search_base: str = None, 
                     properties: typing.List[str] = None, recursive: bool = True) \
            -> LdapObjectCollection:
        return self.search_objects(property_name=property_name, property_value=property_value, recursive=recursive, 
                                   properties=properties, object_class="user", search_base=search_base)

    def search_groups(self, property_name: str, property_value: str, search_base: str = None,
                      properties: typing.List[str] = None, recursive: bool = True) \
            -> LdapObjectCollection:
        return self.search_objects(property_name=property_name, property_value=property_value, recursive=recursive,
                                   properties=properties, object_class="group", search_base=search_base)
    
    def search_org_units(self, property_name: str, property_value: str, search_base: str = None, 
                         properties: typing.List[str] = None, recursive: bool = True) \
            -> LdapObjectCollection:
        return self.search_objects(property_name=property_name, property_value=property_value, recursive=recursive, 
                                   properties=properties, object_class="organizationalUnit", search_base=search_base)
        
    def __str__(self):
        return self._name

    def add_group_members(self, group_dn, member_dns):
        add_group_member(self.__connection, members_dn=member_dns, groups_dn=group_dn, fix=True)

    def remove_group_members(self, group_dn, member_dns):
        remove_group_member(self.__connection, members_dn=member_dns, groups_dn=group_dn, fix=True)




