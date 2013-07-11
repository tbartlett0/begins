"Convenience function for starting Python programs"
from __future__ import absolute_import, division, print_function
from begin.convert import convert
from begin.main import start
from begin.version import __version__

from begin.extensions import tracebacks

import begin.utils

__all__ = ['start']
