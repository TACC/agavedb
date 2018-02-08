version := $(shell cat VERSION)

.PHONY: sdist docs clean dist-clean release tests preflight tag
.SILENT: sdist docs clean dist-clean release tests preflight tag

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

preflight:
	echo "checking git repo is in shape for release"
	bash scripts/checkrepo.sh

tag: preflight
	echo "git tag will be: $(version)"
	git tag -f "${version}"
	git push origin "${version}"
