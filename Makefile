# releases:
# aerodactyl (13sep03)
# bulbasaur (18sep03)
# charmander (10nov03)
# doduo (04jan04) - 0.9
# eevee (08mar04)
# fearow (23apr04)

release:
	python ./setup.py sdist --formats=zip

docs: always
	epydoc -o docs/ paramiko
always:

# places where the version number is stored:
#
# setup.py
# __init__.py
# README
