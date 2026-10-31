"""Test configuration: always run against the fake binaryninja package."""

from helpers import install_fake_binaryninja

install_fake_binaryninja()

import binja_plugin  # noqa: E402,F401  (imported after the fake is installed so tools register)
