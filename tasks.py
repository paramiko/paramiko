from invoke import Collection
from invocations import docs, testing


# TODO: let from_module specify new name
api = Collection.from_module(docs)
# TODO: maybe allow rolling configuration into it too heh
api.configure({
    'sphinx.source': 'api',
    'sphinx.target': 'api/_build',
})
api.name = 'api'
site = Collection.from_module(docs)
site.name = 'site'
site.configure({
    'sphinx.source': 'site',
    'sphinx.target': 'site/_build',
})

ns = Collection(testing.test, api=api, site=site)
