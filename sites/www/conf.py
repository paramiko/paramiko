# Obtain shared config values
from pathlib import Path
import os
import sys

updir = Path(__file__).parent.parent.resolve()
sys.path.append(str(updir))
from shared_conf import *

# Releases changelog extension
extensions.append("releases")
releases_release_uri = "https://github.com/paramiko/paramiko/tree/%s"
releases_issue_uri = "https://github.com/paramiko/paramiko/issues/%s"
releases_development_branch = "main"
# Don't show unreleased_X.x sections up top for 1.x or 2.x anymore
releases_supported_versions = [3]

# Default is 'local' building, but reference the public docs site when building
# under RTD.
target = updir / "docs" / "_build"
if os.environ.get("READTHEDOCS") == "True":
    target = "http://docs.paramiko.org/en/latest/"
intersphinx_mapping["docs"] = (str(target), None)

# Sister-site links to API docs
html_theme_options["extra_nav_links"] = {
    "API Docs": "http://docs.paramiko.org"
}
