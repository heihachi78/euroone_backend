"""Exceptions raised by the API clients."""


class UnusableResponseError(Exception):
    """An external API answered without an error status, but with an unusable body."""
