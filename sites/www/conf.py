# Obtain shared config values
import os, sys
sys.path.append(os.path.abspath('..'))
from shared_conf import *

# Add local blog extension
sys.path.append(os.path.abspath('.'))
extensions = ['blog']
rss_link = 'http://paramiko.org'
rss_description = 'Paramiko project news'

