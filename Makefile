test: venv
	./venv/bin/pytest -s

venv:
	python3 -m venv venv
	./venv/bin/pip install -U pip
	./venv/bin/pip install -e .[test]
