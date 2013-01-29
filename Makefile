release: docs
	python setup.py sdist register upload

docs: paramiko/*
	epydoc --no-private -o docs/ paramiko

clean:
	rm -rf build dist docs
	rm -f MANIFEST *.log demos/*.log
	rm -f paramiko/*.pyc
	rm -f test.log
	rm -rf paramiko.egg-info

test:
	python ./test.py
