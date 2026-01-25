import platform

from ._pystack import NativeReportingMode
from ._pystack import StackMethod
from ._pystack import get_process_threads

__all__ = [
    "StackMethod",
    "NativeReportingMode",
    "get_process_threads",
]

# Core file support is only available on Linux
if platform.system() != "Darwin":
    from ._pystack import CoreFileAnalyzer
    from ._pystack import get_process_threads_for_core

    __all__.extend(["CoreFileAnalyzer", "get_process_threads_for_core"])
