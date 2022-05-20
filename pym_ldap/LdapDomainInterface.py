import typing


class LdapDomainInterface:
    def connect(self, username: str, password: str) -> bool:
        pass

    def configure(self, json_file_path: str):
        pass

    def get_object(self, uniq_value: str, properties: typing.List[str] = None, object_class: str = None) -> typing.Any:
        pass

    def get_objects(self, uniq_values: typing.List[str], properties: typing.List[str] = None,
                    object_class: str = None) -> typing.Any:
        pass

    def get_user(self, uniq_value: str, properties: typing.List[str] = None) -> typing.Any:
        pass

    def get_group(self, uniq_value: str, properties: typing.List[str] = None) -> typing.Any:
        pass

    def get_org_unit(self, uniq_value: str, properties: typing.List[str] = None) -> typing.Any:
        pass

    def search_objects(self, property_name: str = None, property_value: str = None, search_base: str = None,
                       properties: typing.List[str] = None, object_class: str = None, recursive: bool = True,
                       properties_dict: dict = None) -> typing.Any:
        pass

    def search_users(self, property_name: str = None, property_value: str = None, search_base: str = None,
                     properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.Any:
        pass

    def search_groups(self, property_name: str = None, property_value: str = None, search_base: str = None,
                      properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.Any:
        pass

    def search_org_units(self, property_name: str = None, property_value: str = None, search_base: str = None,
                         properties: typing.List[str] = None, recursive: bool = True, properties_dict: dict = None) \
            -> typing.Any:
        pass

    def get_user_ex(self, uniq_value: str) -> typing.Any:
        pass

    def get_group_ex(self, uniq_value: str) -> typing.Any:
        pass

    def get_org_unit_ex(self, uniq_value: str) -> typing.Any:
        pass

    def search_users_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                        properties_dict: dict = None) -> typing.Any:
        pass

    def search_groups_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                         properties_dict: dict = None) -> typing.Any:
        pass

    def search_org_units_ex(self, property_name: str = None, property_value: str = None, recursive: bool = True,
                            properties_dict: dict = None) -> typing.Any:
        pass

    def test_func(self, myarg):
        pass
