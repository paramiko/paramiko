# Obtain shared config values
import os, sys
from os.path import abspath, join, dirname

sys.path.append(abspath(".."))
sys.path.append(abspath("../.."))
from shared_conf import *

# Enable autodoc, intersphinx
extensions.extend(["sphinx.ext.autodoc"])

# Autodoc settings
autodoc_default_flags = ["members", "special-members"]

# Default is 'local' building, but reference the public www site when building
# under RTD.
target = join(dirname(__file__), "..", "www", "_build")
if os.environ.get("READTHEDOCS") == "True":
    target = "http://paramiko.org"
intersphinx_mapping["www"] = (target, None)

# Sister-site links to WWW
html_theme_options["extra_nav_links"] = {
    "Main website": "http://www.paramiko.org"
}
