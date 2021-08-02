# vim: ts=8:sw=8:ft=make:noai:noet
PYTHON=python3.8
SHELL=/bin/bash

.PHONY: version
.PHONY: build
.PHONY: update_requirements

DIR="$(shell realpath .)"
NAME="$(shell basename "${DIR}")"
RELEASE_VERSION?=
VENV?=venv
PIP="${VENV}/bin/pip"
PY="${VENV}/bin/python"
PYLINT="${VENV}/bin/pylint"
PYLINT_RCFILE?=".git/hooks/etc/python/.pylintrc"

BUILD_VERSION_EXISTS=$(shell test "${RELEASE_VERSION}" != "" && echo 1 || echo 0)
COVERAGE_REQUESTED=$(shell test "${COVERAGE}" = "1" && echo 1 || echo 0)
FULL_LINT_REQUESTED=$(shell test "${FULL_LINT}" = "1" && echo 1 || echo 0)

name:
	@echo "${NAME}"

version:
ifeq ($(BUILD_VERSION_EXISTS), 1)
	@printf "%s" "${RELEASE_VERSION}" > VERSION
endif

test: export PYTHONPATH=lib
test:
ifeq ($(COVERAGE_REQUESTED), 1)
	@"${PIP}" install --quiet --upgrade coverage
	@coverage run --omit="${VENV}*" -m "${NAME}".test.run_tests
	@coverage report --omit="${VENV}*"
else
	@${PY} -m "${NAME}".test.run_tests
endif

lint: export PYTHONPATH=lib
lint:
ifeq ($(FULL_LINT_REQUESTED), 1)
	@"${PYLINT}" --rcfile "${PYLINT_RCFILE}" --reports no "${NAME}"
else
	@"${PYLINT}" --rcfile "${PYLINT_RCFILE}" --reports no --errors-only "${NAME}"
endif

build: export PYTHONPATH=lib
build: version test
	@"${PY}" -m pip  install --upgrade pip build
	@"${PY}" -m build
	@git checkout -- VERSION

prep:
	@mkdir -p etc certs data

venv: prep
	@"${PYTHON}" -m venv "${VENV}"

update_requirements:
	@scripts/update_requirements.sh "${PIP}"
