# magic....
version := $(shell cat agavedb/__init__.py | grep 'version' | cut -d ' ' -f 3 | tr -d /\'//)

.PHONY: sdist docs clean dist-clean release tests preflight tag
.SILENT: sdist docs clean dist-clean release tests preflight tag

sdist: dist-clean
	python setup.py sdist && \
	make clean

docs:
	cd docs && \
	make html

install:
	python setup.py install

clean:
	rm -rf *.pyc
	rm -rf *egg-info*
	rm -rf .cache
	rm -rf *__pycache__*
	rm -rf *.pytest_cache*
	rm -rf *.hypothesis
	cd docs && make clean

dist-clean: clean
	rm -rf dist

pytest:
	python -m pytest -s -vv --cov=agavedb agavedb/tests ${PYTESTOPTS}

tests:
	tox

prerelease: docs sdist
	git add . && \
	git commit -m "Releasing ${version}" || true

preflight: prerelease
	echo "checking git repo is in shape for release"
	bash scripts/checkrepo.sh

release: preflight
	echo "git tag will be: $(version)"
	git tag -f "${version}"
	git push origin "${version}"
