import os
from os.path import join
from shutil import rmtree, copytree

from invoke import Collection, task
from invocations import travis
from invocations.checks import blacken
from invocations.docs import docs, www, sites
from invocations.packaging.release import ns as release_coll, publish
from invocations.testing import count_errors


# TODO: this screams out for the invoke missing-feature of "I just wrap task X,
# assume its signature by default" (even if that is just **kwargs support)
@task
def test(
    ctx,
    verbose=True,
    color=True,
    capture="sys",
    module=None,
    k=None,
    x=False,
    opts="",
    coverage=False,
    include_slow=False,
    loop_on_fail=False,
):
    """
    Run unit tests via pytest.

    By default, known-slow parts of the suite are SKIPPED unless
    ``--include-slow`` is given. (Note that ``--include-slow`` does not mesh
    well with explicit ``--opts="-m=xxx"`` - if ``-m`` is found in ``--opts``,
    ``--include-slow`` will be ignored!)
    """
    if verbose and "--verbose" not in opts and "-v" not in opts:
        opts += " --verbose"
    # TODO: forget why invocations.pytest added this; is it to force color when
    # running headless? Probably?
    if color:
        opts += " --color=yes"
    opts += " --capture={}".format(capture)
    if "-m" not in opts and not include_slow:
        opts += " -m 'not slow'"
    if k is not None and not ("-k" in opts if opts else False):
        opts += " -k {}".format(k)
    if x and not ("-x" in opts if opts else False):
        opts += " -x"
    if loop_on_fail and not ("-f" in opts if opts else False):
        opts += " -f"
    modstr = ""
    if module is not None:
        # NOTE: implicit test_ prefix as we're not on pytest-relaxed yet
        modstr = " tests/test_{}.py".format(module)
    # Switch runner depending on coverage or no coverage.
    # TODO: get pytest's coverage plugin working, IIRC it has issues?
    runner = "pytest"
    if coverage:
        # Leverage how pytest can be run as 'python -m pytest', and then how
        # coverage can be told to run things in that manner instead of
        # expecting a literal .py file.
        runner = "coverage run --source=paramiko -m pytest"
    # Strip SSH_AUTH_SOCK from parent env to avoid pollution by interactive
    # users.
    # TODO: once pytest coverage plugin works, see if there's a pytest-native
    # way to handle the env stuff too, then we can remove these tasks entirely
    # in favor of just "run pytest"?
    env = dict(os.environ)
    if "SSH_AUTH_SOCK" in env:
        del env["SSH_AUTH_SOCK"]
    cmd = "{} {} {}".format(runner, opts, modstr)
    # NOTE: we have a pytest.ini and tend to use that over PYTEST_ADDOPTS.
    ctx.run(cmd, pty=True, env=env, replace_env=True)


@task
def coverage(ctx, opts=""):
    """
    Execute all tests (normal and slow) with coverage enabled.
    """
    return test(ctx, coverage=True, include_slow=True, opts=opts)


@task
def guard(ctx, opts=""):
    """
    Execute all tests and then watch for changes, re-running.
    """
    # TODO if coverage was run via pytest-cov, we could add coverage here too
    return test(ctx, include_slow=True, loop_on_fail=True, opts=opts)


# Until we stop bundling docs w/ releases. Need to discover use cases first.
# TODO: would be nice to tie this into our own version of build() too, but
# still have publish() use that build()...really need to try out classes!
@task
def release(ctx, sdist=True, wheel=True, sign=True, dry_run=False, index=None):
    """
    Wraps invocations.packaging.publish to add baked-in docs folder.
    """
    # Build docs first. Use terribad workaround pending invoke #146
    ctx.run("inv docs", pty=True, hide=False)
    # Move the built docs into where Epydocs used to live
    target = "docs"
    rmtree(target, ignore_errors=True)
    # TODO: make it easier to yank out this config val from the docs coll
    copytree("sites/docs/_build", target)
    # Publish
    publish(
        ctx, sdist=sdist, wheel=wheel, sign=sign, dry_run=dry_run, index=index
    )
    # Remind
    print(
        "\n\nDon't forget to update RTD's versions page for new minor "
        "releases!"
    )


# TODO: "replace one task with another" needs a better public API, this is
# using unpublished internals & skips all the stuff add_task() does re:
# aliasing, defaults etc.
release_coll.tasks["publish"] = release

ns = Collection(
    test,
    coverage,
    guard,
    release_coll,
    docs,
    www,
    sites,
    count_errors,
    travis,
    blacken,
)
ns.configure(
    {
        "packaging": {
            # NOTE: many of these are also set in kwarg defaults above; but
            # having them here too means once we get rid of our custom
            # release(), the behavior stays.
            "sign": True,
            "wheel": True,
            "changelog_file": join(
                www.configuration()["sphinx"]["source"], "changelog.rst"
            ),
        },
        "travis": {"black": {"version": "18.6b4"}},
    }
)
