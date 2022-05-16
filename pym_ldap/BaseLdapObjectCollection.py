import typing


class BaseLdapObjectCollection:

    def __str__(self) -> str:
        return str([str(obj) for obj in self])

    @property
    def dn(self) -> typing.List[str]:
        return [obj.dn for obj in self]

    def get_by_dn(self, dn: str) -> typing.Any:
        for item in self:
            if item.dn == dn:
                return item
