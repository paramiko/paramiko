from fabric.api import task, sudo, env, local, hosts
from fabric.contrib.project import rsync_project
from fabric.contrib.console import confirm


@task
@hosts("paramiko.org")
def upload_docs():
    target = "/var/www/paramiko.org"
    staging = "/tmp/paramiko_docs"
    sudo("mkdir -p %s" % staging)
    sudo("chown -R %s %s" % (env.user, staging))
    sudo("rm -rf %s/*" % target)
    rsync_project(local_dir='docs/', remote_dir=staging, delete=True)
    sudo("cp -R %s/* %s/" % (staging, target))

@task
def build_docs():
    local("epydoc --no-private -o docs/ paramiko")

@task
def clean():
    local("rm -rf build dist docs")
    local("rm -f MANIFEST *.log demos/*.log")
    local("rm -f paramiko/*.pyc")
    local("rm -f test.log")
    local("rm -rf paramiko.egg-info")

@task
def test():
    local("python ./test.py")

@task
def release():
    confirm("Only hit Enter if you remembered to update the version!")
    confirm("Also, did you remember to tag your release?")
    build_docs()
    local("python setup.py sdist register upload")
    upload_docs()
