# releases:
# aerodactyl (13sep03)
# bulbasaur
# charmander

RELEASE=bulbasaur

release:
	mkdir ../secsh-$(RELEASE)
	cp README ../secsh-$(RELEASE)
	cp *.py ../secsh-$(RELEASE)
	cd .. && zip -r secsh-$(RELEASE).zip secsh-$(RELEASE)
	echo rm -rf ../secsh-$(RELEASE)

py:
	python ./setup.py sdist --formats=zip

# places where the version number is stored:
#
# setup.py
# secsh.py
# README
