from datetime import datetime

import alabaster


# Alabaster theme + mini-extension
html_theme_path = [alabaster.get_path()]
extensions = ['alabaster']
# Paths relative to invoking conf.py - not this shared file
html_theme = 'alabaster'
html_theme_options = {
    'description': "A Python implementation of SSHv2.",
    'github_user': 'paramiko',
    'github_repo': 'paramiko',
    'gittip_user': 'bitprophet',
    'analytics_id': 'UA-18486793-2',

    'link': '#3782BE',
    'link_hover': '#3782BE',
}
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'searchbox.html',
        'donate.html',
    ]
}

# Regular settings
project = u'Paramiko'
year = datetime.now().year
copyright = u'%d Jeff Forcier' % year
master_doc = 'index'
templates_path = ['_templates']
exclude_trees = ['_build']
source_suffix = '.rst'
default_role = 'obj'
