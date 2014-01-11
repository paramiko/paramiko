from datetime import datetime
import os
import sys

import alabaster


# Add local blog extension
sys.path.append(os.path.abspath('.'))
extensions = ['blog']
rss_link = 'http://paramiko.org'
rss_description = 'Paramiko project news'

# Alabaster theme
html_theme_path = [alabaster.get_path()]
html_static_path = ['_static']
html_theme = 'alabaster'
html_theme_options = {
    'logo': 'logo.png',
    'logo_name': 'true',
    'description': "A Python implementation of SSHv2.",
    'github_user': 'paramiko',
    'github_repo': 'paramiko',
    'gittip_user': 'bitprophet',
    'analytics_id': 'UA-18486793-2',

    'link': '#3782BE',
    'link_hover': '#3782BE',

}
html_sidebars = {
    # Landing page (no ToC)
    'index': [
        'about.html',
        'searchbox.html',
        'donate.html',
    ],
    # Inner pages get a ToC
    '**': [
        'about.html',
        'localtoc.html',
        'searchbox.html',
        'donate.html',
    ]
}

# Regular settings
project = u'Paramiko'
year = datetime.now().year
copyright = u'%d Jeff Forcier, 2003-2012 Robey Pointer' % year
master_doc = 'index'
templates_path = ['_templates']
exclude_trees = ['_build']
source_suffix = '.rst'
default_role = 'obj'
