# Obtain shared config values
import os, sys
sys.path.append(os.path.abspath('..'))
sys.path.append(os.path.abspath('../..'))
from shared_conf import *

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.intersphinx']
