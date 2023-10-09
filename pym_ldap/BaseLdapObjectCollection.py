import typing
from abc import ABC


class BaseLdapObjectCollection(typing.Iterable, ABC):

    def __str__(self) -> str:
        return str([str(obj) for obj in self])

    @property
    def dn(self) -> typing.List[str]:
        return [obj.dn for obj in self]

    @property
    def id(self) -> typing.List[str]:
        return [obj.id for obj in self]

    def __call__(self, uniq_value: str):
        result = None
        if uniq_value[2] == '=':
            for item in self:
                if item.dn == uniq_value:
                    result = item
        elif uniq_value.startswith('0'):
            for item in self:
                if item.id == uniq_value:
                    result = item
        return result

    def cast(self, property_name: str) -> list:
        return [obj(property_name) for obj in self]


