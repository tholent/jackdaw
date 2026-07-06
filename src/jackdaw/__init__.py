"""Jackdaw — an ACME relay."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("jackdaw")
except PackageNotFoundError:  # not installed (e.g. running from a raw checkout)
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
