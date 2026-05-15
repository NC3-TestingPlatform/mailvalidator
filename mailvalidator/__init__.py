"""mailvalidator – Mail server configuration assessment library."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mailvalidator")
except PackageNotFoundError:  # pragma: no cover – only when package not installed
    __version__ = "0.1.6"

# NullHandler so library users who have not configured logging
# do not see "No handler found" warnings (PEP 3118 / logging HOWTO).
import logging as _logging

_logging.getLogger("mailvalidator").addHandler(_logging.NullHandler())
del _logging

__all__ = ["__version__"]
