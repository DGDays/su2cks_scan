"""Custom exceptions for the vulnerability database."""


class VulnDBError(Exception):
    """Base exception for vulnerability database errors."""

    pass


class DownloadError(VulnDBError):
    """Failed to download vulnerability data."""

    pass


class RedisConnectionError(VulnDBError):
    """Failed to connect to Redis."""

    pass


class XMLParseError(VulnDBError):
    """Failed to parse XML data."""

    pass
