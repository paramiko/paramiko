# releases:
# aerodactyl (13sep03)
# bulbasaur
# charmander (10nov03)

RELEASE=charmander

release:
	python ./setup.py sdist --formats=zip

# places where the version number is stored:
#
# setup.py
# secsh.py
# README
