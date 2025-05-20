import sys
import typing
import ldap3
import json
import ssl
import os
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as add_group_member
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups as remove_group_member
from operator import itemgetter
import logging
import re


log = logging.getLogger(__name__)
begin_str = '=' * 50 + "НАЧАЛО" + '=' * 50
end_str = '=' * 50 + "КОНЕЦ" + '=' * 50


class BaseLdapDomain:
    _mandatory_properties = ("name", "distinguishedName", "objectClass", "objectGUID")

    def __init__(self, name: str = None, server: str = None):
        if sys.platform == 'win32':
            current_domain_name = os.environ["USERDNSDOMAIN"].lower()
            current_logon_server = os.environ["LOGONSERVER"].strip('\\')
        elif sys.platform == 'linux':
            from .linux_utils import parse_krb5_conf
            krb_config = parse_krb5_conf()
            current_realm = krb_config['libdefaults']['default_realm']
            current_domain_name = current_realm.lower()
            current_logon_server = krb_config['realms'][current_realm]['admin_server'][0]
        else:
            current_domain_name = ""
            current_logon_server = ""
        if name:
            self._name = name.lower()
        else:
            self._name = current_domain_name
        if server:
            self._ldap_host = server
        else:
            self._ldap_host = current_logon_server
        self._netbios_name = self.__build_net_bios_domain_name()
        self._dn = self.__build_root_dn()
        self._external_name: typing.Optional[str] = None
        self._default_search_base: typing.Optional[str] = None
        self._disabled_org_unit_dn: typing.Optional[str] = None
        self._user_properties: typing.Optional[typing.List[str]] = None
        self._user_id_property_name: typing.Optional[str] = None
        self._group_properties: typing.Optional[typing.List[str]] = None
        self._group_id_property_name: typing.Optional[str] = None
        self._org_unit_properties: typing.Optional[typing.List[str]] = None
        self._org_unit_id_property_name: typing.Optional[str] = None
        self._computer_properties: typing.Optional[typing.List[str]] = None

        self._current_user: typing.Optional[dict] = None
        self._connection: typing.Optional[ldap3.Connection] = None
        self._server: typing.Optional[ldap3.Server] = None

    @classmethod
    def load_from_json(cls, json_file_path: str):
        if os.path.exists(json_file_path):
            log.info(f"Чтение конфигурационного файла домена: '{json_file_path}'")
            with open(json_file_path, 'r', encoding='utf-8') as json_file:
                properties = json.load(json_file)
                instance = cls(**properties)
                return instance
        else:
            log.error(f"Конфигурационного файла домена не существует: '{json_file_path}'")

    def connect(self, username: str = None, password: str = None, use_ssl: bool = True) -> bool:
        if use_ssl:
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
            self._server = ldap3.Server(self._ldap_host, use_ssl=True, tls=tls)
        else:
            self._server = ldap3.Server(self._ldap_host)
        if username and password:
            username = self.__build_net_bios_username(username=username)
            connection = ldap3.Connection(server=self._server, user=username, password=password,
                                          return_empty_attributes=True, client_strategy=ldap3.RESTARTABLE)
        else:
            connection = ldap3.Connection(server=self._server, authentication=ldap3.SASL, sasl_mechanism=ldap3.GSSAPI,
                                          return_empty_attributes=True, client_strategy=ldap3.RESTARTABLE)

        try:
            if connection.bind():
                if connection.result.get("description") == "success":
                    log.info(f"Подключение к контроллеру домена '{connection.server.name}' УСПЕШНО")
                    self._connection = connection
                    # self.__set_schema_properties()
                    self.__set_current_user()
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

    def configure(self, external_name: str = None, default_search_base: str = None,
                  disabled_org_unit_dn: str = None, user_properties: typing.List[str] = None,
                  group_properties: typing.List[str] = None, org_unit_properties: typing.List[str] = None,
                  user_id_property_name: str = None, group_id_property_name: str = None,
                  org_unit_id_property_name: str = None, computer_properties: typing.List[str] = None):
        self._external_name = external_name
        self._default_search_base = default_search_base
        self._disabled_org_unit_dn = disabled_org_unit_dn
        self._user_properties = user_properties
        self._user_id_property_name = user_id_property_name
        self._group_properties = group_properties
        self._group_id_property_name = group_id_property_name
        self._org_unit_properties = org_unit_properties
        self._org_unit_id_property_name = org_unit_id_property_name
        self._computer_properties = computer_properties

    def configure_from_json(self, json_file_path: str = None):
        if not json_file_path:
            json_file_path = os.path.join(os.path.dirname(__file__), "domain.json")
        if os.path.exists(json_file_path):
            log.info(f"Чтение конфигурационного файла домена: '{json_file_path}'")
            with open(json_file_path, 'r', encoding='utf-8') as json_file:
                properties = json.load(json_file)
                self.configure(**properties)
        else:
            log.error(f"Конфигурационного файла домена не существует: '{json_file_path}'")

    @property
    def name(self) -> str:
        return self._name

    @property
    def net_bios_name(self) -> str:
        return self._netbios_name

    @property
    def server(self) -> str:
        return self._ldap_host

    @property
    def current_user(self) -> dict:
        return self._current_user

    def __build_net_bios_username(self, username: str) -> str:
        if "\\" not in username:
            username = self.net_bios_name + "\\" + username
        return username

    def __build_root_dn(self) -> str:
        name_parts = self._name.split('.')
        dn_parts = list()
        for name_part in name_parts:
            dn_parts.append("dc=" + name_part)
        return ','.join(dn_parts)

    def __build_net_bios_domain_name(self) -> str:
        name_parts = self._name.split('.')
        return name_parts[0].upper()

    def __get_schema_properties(self) -> dict:
        log.info(f"Конфигурирование домена")
        if self._connection and not self._connection.closed:
            log.debug("Запрос аттрибутов из схемы домен контроллера")
            properties = dict()
            for k, v in self._connection.server.schema.attribute_types._case_insensitive_keymap.items():
                if not k.startswith("ms"):
                    properties[k] = v
            return properties
        else:
            log.critical("Отсутствует соединение с сервером")

    def __set_current_user(self):
        if self._connection and not self._connection.closed:
            log.debug("Получение текущего пользователя из домена")
            netbios_username = self._connection.extend.standard.who_am_i().split(":")[1]
            samaccountname = netbios_username.split("\\")[1]
            self._current_user = self._get_user_ex(uniq_value=samaccountname)
        else:
            log.critical("Отсутствует соединение с сервером")

    def __build_filter(self, uniq_value: str = None, property_name: str = None, property_value: str = None,
                       properties_dict: dict = None, object_class: str = None):
        log.debug("Генерация фильтра поиска")
        search_filter = ""
        if uniq_value is not None:
            uniq_value = uniq_value.replace('(', '\\28').replace(')', '\\29')
            uniq_property_name = self.__build_property_name(property_value=uniq_value, object_class=object_class)
            if uniq_property_name:
                search_filter += f"({uniq_property_name}={uniq_value})"
        if property_name is not None and property_value is not None:
            property_value = property_value.replace('(', '\\28').replace(')', '\\29')
            search_filter += f"({property_name}={property_value})"
        if properties_dict is not None:
            for key, value in properties_dict.items():
                value = value.replace('(', '\\28').replace(')', '\\29')
                search_filter += f"({key}={value})"
        if object_class is not None:
            if object_class.lower() == "user":
                search_filter += f"(objectCategory=Person)(objectClass={object_class})"
            elif object_class.lower() == "group":
                search_filter += f"(objectClass={object_class})"
            elif object_class.lower() == "computer":
                search_filter += f"(objectClass={object_class})"
            elif object_class.lower() == "orgunit" or object_class.lower() == "organizationalunit":
                search_filter += f"(objectClass={object_class})"
        else:
            search_filter += "(objectclass=*)"
        search_filter = f"(&{search_filter})"
        log.debug(f"Сгенерирован фильтр поиска: '{search_filter}'")
        return search_filter

    def __build_property_name(self, property_value: str, object_class: str = None):
        log.debug(f"Получение имени аттрибута по значению '{property_value}' и классу '{object_class}'")
        property_name: str = ""
        if property_value.lower().endswith(self._dn):
            property_name = "distinguishedName"
        elif property_value.startswith("{") and object_class:
            property_name = "objectGUID"
        elif property_value.startswith("0") and object_class:
            if object_class == "user" and self._user_id_property_name:
                property_name = self._user_id_property_name
            elif object_class == "group" and self._group_id_property_name:
                property_name = self._group_id_property_name
            elif object_class == "organizationalUnit" and self._org_unit_id_property_name:
                property_name = self._org_unit_id_property_name
        else:
            property_name = "sAMAccountName"
        if property_name and property_name != "":
            log.debug(f"Получено имя аттрибута '{property_name}'")
            return property_name
        else:
            log.error(f"Не получено имя аттрибута '{property_name}'")

    def __build_properties(self, properties: typing.List[str]) -> typing.List[str]:
        if properties:
            search_properties = list(set(properties) | set(self._mandatory_properties))
        else:
            search_properties = self._mandatory_properties
        return search_properties

    def get_class_properties(self, object_class):
        log.debug(f"Получение словаря аттрибутов для класса {object_class}")
        if self._connection:
            class_def = ldap3.ObjectDef(object_class, self._connection)
            if class_def:
                if "_attributes" in class_def.__dict__:
                    log.debug(f"Получение словаря аттрибутов для класса {object_class}: УСПЕХ")
                    return class_def.__dict__["_attributes"].__dict__["_case_insensitive_keymap"]
        log.error(f"Получение словаря аттрибутов для класса {object_class}: ОШИБКА")

    def __search(self, search_filter: str, search_base: str, search_scope: str, search_properties: list) \
            -> typing.List[dict]:
        search_properties = [prop.lower() for prop in search_properties]
        results: typing.List[dict] = list()
        if self._connection is not None:
            try:
                entries = self._connection.extend.standard.paged_search(search_filter=search_filter,
                                                                        search_base=search_base,
                                                                        search_scope=search_scope,
                                                                        attributes=search_properties,
                                                                        paged_size=1000,
                                                                        generator=False)
                for entry in entries:
                    if entry["type"] == "searchResEntry" and entry["dn"] != search_base:
                        results.append(entry["attributes"])
                results = sorted(results, key=itemgetter("name"))
            except Exception as e:
                log.error(f"Ошибка при выполнении поискового запроса: {e}")
        else:
            log.error("Не возможно выполнить запрос на сервер так как отсутствует соединение.")
        return results

    def _get_object(self, uniq_value: str, properties: typing.List[str] = None, object_class: str = None) -> dict:
        search_filter = self.__build_filter(uniq_value=uniq_value, object_class=object_class)
        search_properties = self.__build_properties(properties)
        entries = self.__search(search_filter, self._dn, ldap3.SUBTREE, search_properties)
        if entries and len(entries) > 0:
            return entries[0]
            # return LdapObject(entries[0])

    def _get_objects(self, uniq_values: typing.List[str], properties: typing.List[str] = None, object_class: str = None) \
            -> typing.List[dict]:
        result: typing.List[dict] = list()
        for uniq_value in uniq_values:
            ldap_object = self._get_object(uniq_value=uniq_value, properties=properties, object_class=object_class)
            if ldap_object:
                result.append(ldap_object)
        return result

    def _get_user(self, uniq_value: str, properties: typing.List[str] = None) -> dict:
        return self._get_object(uniq_value=uniq_value, properties=properties, object_class="user")

    def _get_group(self, uniq_value: str, properties: typing.List[str] = None) -> dict:
        return self._get_object(uniq_value=uniq_value, properties=properties, object_class="group")

    def _get_org_unit(self, uniq_value: str, properties: typing.List[str] = None) -> dict:
        return self._get_object(uniq_value=uniq_value, properties=properties, object_class="organizationalUnit")

    def _get_computer(self, uniq_value: str, properties: typing.List[str] = None) -> dict:
        if not uniq_value.endswith("$"):
            uniq_value = uniq_value + "$"
        return self._get_object(uniq_value=uniq_value, properties=properties, object_class="computer")

    def _search_objects(self, property_name: str = None, property_value: str = None, search_base: str = None,
                        properties: typing.List[str] = None, object_class: str = None, recursive: bool = True,
                        properties_dict: dict = None) -> typing.List[dict]:
        search_filter = self.__build_filter(property_name=property_name, property_value=property_value,
                                            object_class=object_class, properties_dict=properties_dict)
        if not search_base:
            search_base = self._dn
        if recursive:
            search_scope = ldap3.SUBTREE
        else:
            search_scope = ldap3.LEVEL
        search_properties = self.__build_properties(properties)
        entries = self.__search(search_filter, search_base, search_scope, search_properties)
        return entries
        # return LdapObjectCollection(entries)

    def _search_users(self, property_name: str = None, property_value: str = None, search_base: str = None,
                      properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.List[dict]:
        return self._search_objects(property_name=property_name, property_value=property_value, recursive=recursive,
                                    properties=properties, object_class="user", search_base=search_base,
                                    properties_dict=properties_dict)

    def _search_groups(self, property_name: str = None, property_value: str = None, search_base: str = None,
                       properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.List[dict]:
        return self._search_objects(property_name=property_name, property_value=property_value, recursive=recursive,
                                    properties=properties, object_class="group", search_base=search_base,
                                    properties_dict=properties_dict)

    def _search_org_units(self, property_name: str = None, property_value: str = None, search_base: str = None,
                          properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.List[dict]:
        return self._search_objects(property_name=property_name, property_value=property_value, recursive=recursive,
                                    properties=properties, object_class="organizationalUnit", search_base=search_base,
                                    properties_dict=properties_dict)

    def _search_computers(self, property_name: str = None, property_value: str = None, search_base: str = None,
                          properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.List[dict]:
        return self._search_objects(property_name=property_name, property_value=property_value, recursive=recursive,
                                    properties=properties, object_class="computer", search_base=search_base,
                                    properties_dict=properties_dict)

    def _get_user_ex(self, uniq_value: str) -> dict:
        return self._get_user(uniq_value=uniq_value, properties=self._user_properties)

    def _get_group_ex(self, uniq_value: str) -> dict:
        return self._get_group(uniq_value=uniq_value, properties=self._group_properties)

    def _get_org_unit_ex(self, uniq_value: str) -> dict:
        return self._get_org_unit(uniq_value=uniq_value, properties=self._org_unit_properties)

    def _get_computer_ex(self, uniq_value: str) -> dict:
        return self._get_computer(uniq_value=uniq_value, properties=self._computer_properties)

    def _search_users_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                         properties_dict: dict = None, search_base: str = None) -> typing.List[dict]:
        if not search_base:
            search_base = self._default_search_base
        return self._search_users(property_name=property_name, property_value=property_value, recursive=recursive,
                                  search_base=search_base, properties=self._user_properties,
                                  properties_dict=properties_dict)

    def _search_groups_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                          properties_dict: dict = None, search_base: str = None) -> typing.List[dict]:
        if not search_base:
            search_base = self._default_search_base
        return self._search_groups(property_name=property_name, property_value=property_value, recursive=recursive,
                                   search_base=search_base, properties=self._group_properties,
                                   properties_dict=properties_dict)

    def _search_org_units_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                             properties_dict: dict = None, search_base: str = None) -> typing.List[dict]:
        if not search_base:
            search_base = self._default_search_base
        return self._search_org_units(property_name=property_name, property_value=property_value, recursive=recursive,
                                      search_base=search_base, properties=self._org_unit_properties,
                                      properties_dict=properties_dict)

    def _search_computers_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                             properties_dict: dict = None, search_base: str = None) -> typing.List[dict]:
        if not search_base:
            search_base = self._default_search_base
        return self._search_computers(property_name=property_name, property_value=property_value, recursive=recursive,
                                      search_base=search_base, properties=self._computer_properties,
                                      properties_dict=properties_dict)

    def _get_group_manager(self, group_dn: str, properties: typing.List[str] = None) -> dict:
        group = self._get_group(uniq_value=group_dn, properties=["managedBy"])
        if "managedBy" in group and group["managedBy"]:
            return self._get_object(group["managedBy"], properties=properties)

    def _get_group_membership(self, object_dn, properties: typing.List[str] = None) -> typing.List[dict]:
        return self._search_groups(property_name="member:1.2.840.113556.1.4.1941:", property_value=object_dn,
                                   properties=properties)

    def add_group_members(self, group_dn, member_dns):
        add_group_member(self._connection, members_dn=member_dns, groups_dn=group_dn, fix=True)

    def remove_group_members(self, group_dn, member_dns):
        remove_group_member(self._connection, members_dn=member_dns, groups_dn=group_dn, fix=True)

    def create_object(self, name: str, parent_dn: str, object_class: str,
                      properties: dict = None) -> str:
        log.info(
            f"Создание нового объекта в каталоге name='{name}' path='{parent_dn}' class='{object_class}' attrs='{str(properties)}'")
        if properties is None:
            properties = dict()
        if object_class == "user" or object_class == "group":
            dn = "CN=" + name + "," + parent_dn
            if "sAMAccountName" not in properties:
                properties["sAMAccountName"] = name
        elif object_class == "organizationalUnit":
            dn = "OU=" + name + "," + parent_dn
        else:
            dn = ""
        if "name" not in properties:
            properties["name"] = name
        if dn != "":
            try:
                log.info(f"Финальные аттрибуты для создания объекта dn='{dn}', object_class='{object_class}', "
                         f"attributes='{properties}'")
                self._connection.add(dn=dn, object_class=object_class, attributes=properties)
                log.info(f"Создание оъекта '{dn}' УСПЕХ")
                return dn
            except Exception as e:
                log.error(f"Создание оъекта '{dn}' ОШИБКА: {e}")
                print(e)

    def set_group_manager(self, group_dn: str, manager_dn: str):
        from .Functions import grant_write_property_access, reset_ldap_object_access
        log.info(f"Назначение для группы '{group_dn}' владельца '{manager_dn}'")
        manager = self._get_object(uniq_value=manager_dn, properties=["sAMAccountName"])
        netbios_login = f"{self.net_bios_name}\\{manager['sAMAccountName']}"
        log.info(f"Запуск программы сброса разрешений для группы '{group_dn}'")
        if reset_ldap_object_access(object_dn=group_dn):
            log.info(f"Запуск программы сброса разрешений для группы '{group_dn}' УСПЕШНО")
            log.info(f"Запуск программы назначения разрешений для группы '{group_dn}'")
            if grant_write_property_access(object_dn=group_dn, netbios_login=netbios_login, property_name="member"):
                log.info(f"Запуск программы назначения разрешений для группы '{group_dn}' УСПЕШНО")
                log.info(f"Модификация аттрибута 'managedBy' объекта '{group_dn}' -> '{manager_dn}")
                self._connection.modify(group_dn, {"managedBy": ["MODIFY_REPLACE", [manager_dn]]})

    def __str__(self):
        return self._name
