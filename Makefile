
.PHONY: sdist docs clean release tests

sdist: clean
	python setup.py sdist && \
	make clean

docs:
	cd scripts && \
	bash docs.sh

install:
	python setup.py install

release: docs
	python setup.py sdist upload

clean:
	rm -rf agavedb/tests/*pyc agavedb/*pyc agavedb.egg-info build/ .cache agavedb/tests/__pycache__

dist-clean:
	rm -rf dist

tests:
	cd agavedb && py.test
