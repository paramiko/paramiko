from os.path import join

from invoke import Collection
from invocations import docs as _docs, testing


d = 'sites'

# Usage doc/API site (published as docs.paramiko.org)
path = join(d, 'docs')
docs = Collection.from_module(_docs, name='docs', config={
    'sphinx.source': path,
    'sphinx.target': join(path, '_build'),
})

# Main/about/changelog site ((www.)?paramiko.org)
path = join(d, 'www')
www = Collection.from_module(_docs, name='www', config={
    'sphinx.source': path,
    'sphinx.target': join(path, '_build'),
})

ns = Collection(testing.test, docs=docs, www=www)
