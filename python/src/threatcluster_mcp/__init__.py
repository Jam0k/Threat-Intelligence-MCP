"""threatcluster-mcp: the ThreatCluster public API as MCP tools (stdio)."""
from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("threatcluster-mcp")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.0.0"

__all__ = ["__version__"]
