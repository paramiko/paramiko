# Obtain shared config values
import os, sys

sys.path.append(os.path.abspath(".."))
sys.path.append(os.path.abspath("../.."))
from shared_conf import *

# Enable autodoc, intersphinx
extensions.extend(["sphinx.ext.autodoc"])

# Autodoc settings
autodoc_default_flags = ["members", "special-members"]

# Sister-site links to WWW
html_theme_options["extra_nav_links"] = {
    "Main website": "http://www.paramiko.org"
}
