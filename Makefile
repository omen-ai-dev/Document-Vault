VENV=.venv
PYTHON=$(VENV)/bin/python
PIP=$(VENV)/bin/pip
PORT ?= 8007

.PHONY: venv install deps test run clean

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

# Convenience alias
deps: install

run:
	$(PYTHON) -m uvicorn app.main:app --reload --port $(PORT)

test:
	$(PYTHON) -m pytest -vv

clean:
	rm -rf $(VENV) .pytest_cache
