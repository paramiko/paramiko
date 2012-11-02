from fabric.api import task, sudo, env
from fabric.contrib.project import rsync_project


@task
def upload_docs():
    target = "/var/www/paramiko.org"
    staging = "/tmp/paramiko_docs"
    sudo("mkdir -p %s" % staging)
    sudo("chown -R %s %s" % (env.user, staging))
    sudo("rm -rf %s/*" % target)
    rsync_project(local_dir='docs/', remote_dir=staging, delete=True)
    sudo("cp -R %s/* %s/" % (staging, target))
