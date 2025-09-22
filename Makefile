.PHONY: install
install:
	uv pip install -e .
	find . -name "*.egg-info" -exec rm -rf {} +