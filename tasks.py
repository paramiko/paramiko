from os.path import join
from shutil import rmtree, copytree

from invoke import Collection, task
from invocations.docs import docs, www, sites
from invocations.packaging.release import ns as release_coll, publish
from invocations.testing import count_errors


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
# TODO: would be nice to tie this into our own version of build() too, but
# still have publish() use that build()...really need to try out classes!
@task
def release(ctx, sdist=True, wheel=True, sign=True, dry_run=False):
    """
    Wraps invocations.packaging.publish to add baked-in docs folder.
    """
    # Build docs first. Use terribad workaround pending invoke #146
    ctx.run("inv docs", pty=True, hide=False)
    # Move the built docs into where Epydocs used to live
    target = 'docs'
    rmtree(target, ignore_errors=True)
    # TODO: make it easier to yank out this config val from the docs coll
    copytree('sites/docs/_build', target)
    # Publish
    publish(ctx, sdist=sdist, wheel=wheel, sign=sign, dry_run=dry_run)
    # Remind
    print("\n\nDon't forget to update RTD's versions page for new minor "
          "releases!")


# TODO: "replace one task with another" needs a better public API, this is
# using unpublished internals & skips all the stuff add_task() does re:
# aliasing, defaults etc.
release_coll.tasks['publish'] = release

ns = Collection(test, coverage, release_coll, docs, www, sites, count_errors)
ns.configure({
    'packaging': {
        # NOTE: many of these are also set in kwarg defaults above; but having
        # them here too means once we get rid of our custom release(), the
        # behavior stays.
        'sign': True,
        'wheel': True,
        'changelog_file': join(
            www.configuration()['sphinx']['source'],
            'changelog.rst',
        ),
    },
})
