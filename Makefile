release: docs
	python setup.py sdist register upload

docs:
	epydoc --no-private -o docs/ ssh

clean:
	rm -rf build dist docs
	rm -f MANIFEST *.log demos/*.log
	rm -f ssh/*.pyc
	rm -f test.log
	rm -rf ssh.egg-info

test:
	python ./test.py
