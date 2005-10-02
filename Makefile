# releases:
# aerodactyl (13sep03)
# bulbasaur (18sep03)
# charmander (10nov03)
# doduo (04jan04) - 0.9
# eevee (08mar04)
# fearow (23apr04)
# gyarados (31may04)
# horsea (27jun04)
# ivysaur (22oct04)
# jigglypuff (6nov04) - 1.0
# kabuto (12dec04) - 1.1
# lapras (28feb05) - 1.2
# marowak (9apr05) - 1.3
# nidoran (28jun05) - 1.3.1
# oddish (17jul05) - 1.4
# paras (2oct05) - 1.5

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
# transport.py
