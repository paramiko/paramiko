from invoke import Collection
from invocations import docs, testing


# Usage doc/API site
api = Collection.from_module(docs, name='docs', config={
    'sphinx.source': 'sites/docs',
    'sphinx.target': 'sites/docs/_build',
})
# Main/about/changelog site
main = Collection.from_module(docs, name='main', config={
    'sphinx.source': 'sites/main',
    'sphinx.target': 'sites/main/_build',
})

ns = Collection(testing.test, docs=api, main=main)
