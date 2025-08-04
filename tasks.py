import os
from pathlib import Path
from os.path import join
from shutil import rmtree, copytree

from invoke import Collection, task
from invocations import checks
from invocations.docs import docs, www, sites, watch_docs
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
        base = f"{module}.py"
        tests = Path("tests")
        legacy = tests / f"test_{base}"
        modstr = str(legacy if legacy.exists() else tests / base)
    # Switch runner depending on coverage or no coverage.
    # TODO: get pytest's coverage plugin working, IIRC it has issues?
    runner = "pytest"
    if coverage:
        # Leverage how pytest can be run as 'python -m pytest', and then how
        # coverage can be told to run things in that manner instead of
        # expecting a literal .py file.
        runner = "coverage run -m pytest"
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
    test(ctx, coverage=True, include_slow=True, opts=opts)
    # NOTE: codecov now handled purely in invocations/orb


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
# TODO 4.0: I'd like to just axe the 'built docs in sdist', none of my other
# projects do it.
@task
def publish_(
    ctx, sdist=True, wheel=True, sign=False, dry_run=False, index=None
):
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


# Also have to hack up the newly enhanced all_() so it uses our publish
@task(name="all", default=True)
def all_(c, dry_run=False):
    release_coll["prepare"](c, dry_run=dry_run)
    publish_(c, dry_run=dry_run)
    release_coll["push"](c, dry_run=dry_run)


# TODO: "replace one task with another" needs a better public API, this is
# using unpublished internals & skips all the stuff add_task() does re:
# aliasing, defaults etc.
release_coll.tasks["publish"] = publish_
release_coll.tasks["all"] = all_

ns = Collection(
    test,
    coverage,
    guard,
    release_coll,
    docs,
    www,
    watch_docs,
    sites,
    count_errors,
    checks.blacken,
    checks,
)
ns.configure(
    {
        "packaging": {
            # NOTE: many of these are also set in kwarg defaults above; but
            # having them here too means once we get rid of our custom
            # release(), the behavior stays.
            "sign": False,
            "wheel": True,
            "changelog_file": join(
                www.configuration()["sphinx"]["source"], "changelog.rst"
            ),
        },
        "blacken": {"find_opts": r"-and -not -path '*.cci_pycache*'"},
        "docs": {"browse": "remote"},
    }
)
