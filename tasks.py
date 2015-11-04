from os import mkdir
from os.path import join
from shutil import rmtree, copytree

from invoke import Collection, ctask as task
from invocations.docs import docs, www, sites
from invocations.packaging import publish


# Until we move to spec-based testing
@task
def test(ctx, coverage=False, flags=""):
    if "--verbose" not in flags.split():
        flags += " --verbose"
    runner = "python"
    if coverage:
        runner = "coverage run --source=paramiko"
    ctx.run("{0} test.py {1}".format(runner, flags), pty=True)


@task
def coverage(ctx):
    ctx.run("coverage run --source=paramiko test.py --verbose")


# Until we stop bundling docs w/ releases. Need to discover use cases first.
@task
def release(ctx):
    # Build docs first. Use terribad workaround pending invoke #146
    ctx.run("inv docs")
    # Move the built docs into where Epydocs used to live
    target = 'docs'
    rmtree(target, ignore_errors=True)
    # TODO: make it easier to yank out this config val from the docs coll
    copytree('sites/docs/_build', target)
    # Publish
    publish(ctx)
    # Remind
    print("\n\nDon't forget to update RTD's versions page for new minor releases!")


ns = Collection(test, coverage, release, docs, www, sites)
