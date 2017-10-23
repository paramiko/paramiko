import os

root_path = os.path.dirname(os.path.realpath(__file__))

def _support(filename):
    return os.path.join(root_path, filename)

