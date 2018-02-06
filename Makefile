
.PHONY: sdist docs clean release

sdist: clean
	python setup.py sdist && \
	make clean

docs:
	cd build && \
	bash docs.sh

install:
	python setup.py install

release: docs
	python setup.py register sdist upload

clean:
	rm -rf agavedb.egg-info build/bdist* build/lib

dist-clean:
	rm -rf dist
