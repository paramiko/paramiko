from os import mkdir
from os.path import join
from shutil import rmtree, copytree

from invoke import Collection, ctask as task
from invocations import docs as _docs
from invocations.packaging import publish


d = 'sites'

# Usage doc/API site (published as docs.paramiko.org)
docs_path = join(d, 'docs')
docs_build = join(docs_path, '_build')
docs = Collection.from_module(_docs, name='docs', config={
    'sphinx.source': docs_path,
    'sphinx.target': docs_build,
})

# Main/about/changelog site ((www.)?paramiko.org)
www_path = join(d, 'www')
www = Collection.from_module(_docs, name='www', config={
    'sphinx.source': www_path,
    'sphinx.target': join(www_path, '_build'),
})


# Until we move to spec-based testing
@task
def test(ctx, coverage=False):
    runner = "python"
    if coverage:
        runner = "coverage run --source=paramiko"
    flags = "--verbose"
    ctx.run("{0} test.py {1}".format(runner, flags), pty=True)


# Until we stop bundling docs w/ releases. Need to discover use cases first.
@task
def release(ctx):
    # Build docs first. Use terribad workaround pending invoke #146
    ctx.run("inv docs")
    # Move the built docs into where Epydocs used to live
    target = 'docs'
    rmtree(target, ignore_errors=True)
    copytree(docs_build, target)
    # Publish
    publish(ctx, wheel=True)
    # Remind
    print("\n\nDon't forget to update RTD's versions page for new minor releases!")


ns = Collection(test, release, docs=docs, www=www)
