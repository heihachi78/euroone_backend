"""IP address request model."""

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, IPvAnyAddress, field_validator


class Ip(BaseModel):
    """A public unicast IP address to look up.

    Attributes:
        ip: The IPv4 or IPv6 address; IPv4-mapped IPv6 addresses become IPv4.
    """

    ip: IPvAnyAddress

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
        """Accept only public unicast addresses, and unwrap IPv4-mapped IPv6 ones.

        Args:
            value: The parsed IP address.

        Returns:
            The address, converted to IPv4 if it is an IPv4-mapped IPv6 address.

        Raises:
            ValueError: If the address has a scope ID or is not public unicast.
        """
        if isinstance(value, IPv6Address) and value.scope_id is not None:
            raise ValueError("IP address must not contain a scope ID")
        if not value.is_global or value.is_multicast:
            raise ValueError("IP address must be a public unicast address")
        if isinstance(value, IPv6Address) and value.ipv4_mapped is not None:
            return value.ipv4_mapped
        return value
