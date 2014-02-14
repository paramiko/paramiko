# Obtain shared config values
import os, sys
sys.path.append(os.path.abspath('..'))
sys.path.append(os.path.abspath('../..'))
from shared_conf import *

# Enable autodoc, intersphinx
extensions.extend(['sphinx.ext.autodoc', 'sphinx.ext.intersphinx'])

# Autodoc settings
autodoc_default_flags = ['members', 'special-members']
