from invoke import Collection
from invocations import docs, testing


# TODO: let from_module specify new name
api = Collection.from_module(docs)
# TODO: maybe allow rolling configuration into it too heh
api.configure({
    'sphinx.source': 'sites/docs',
    'sphinx.target': 'sites/docs/_build',
})
api.name = 'docs'
main = Collection.from_module(docs)
main.name = 'main'
main.configure({
    'sphinx.source': 'sites/main',
    'sphinx.target': 'sites/main/_build',
})

ns = Collection(testing.test, docs=api, main=main)
