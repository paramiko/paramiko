import os

root_path = os.path.dirname(os.path.realpath(__file__))

def test_path(filename):
    return os.path.join(root_path, filename)

