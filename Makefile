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
# quilava (31oct05) - 1.5.1
# rhydon (04dec05) - 1.5.2
# squirtle (19feb06) - 1.5.3
# tentacool (11mar06) - 1.5.4
# umbreon (10may06) - 1.6
# vulpix (10jul06) - 1.6.1
# weedle (16aug06) - 1.6.2
# xatu (14oct06) - 1.6.3
# yanma (19nov06) - 1.6.4


ifeq ($(wildcard /sbin/md5),/sbin/md5)
# os x
MD5SUM := /sbin/md5
else
MD5SUM := md5sum
endif

release: docs
	python ./setup.py sdist --formats=zip
	python ./setup.py sdist --formats=gztar
	python ./setup.py bdist_egg
	zip -r dist/docs.zip docs && rm -rf docs
	cd dist && $(MD5SUM) paramiko*.zip *.gz > md5-sums
	

docs: always
	epydoc --no-private -o docs/ paramiko
always:

clean:
	rm -rf build dist docs
	rm -f MANIFEST *.log demos/*.log
	rm -f paramiko/*.pyc
	rm -f test.log
	rm -rf paramiko.egg-info

test:
	python ./test.py

# places where the version number is stored:
#
# setup.py
# __init__.py
# README
# transport.py
#
# POST md5sum on website!
