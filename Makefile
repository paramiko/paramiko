# releases:
# aerodactyl (13sep03)
# bulbasaur (18sep03)
# charmander (10nov03)

RELEASE=charmander

release:
	python ./setup.py sdist --formats=zip

docs:
	epydoc -o docs/ paramiko

# places where the version number is stored:
#
# setup.py
# __init__.py
# README
