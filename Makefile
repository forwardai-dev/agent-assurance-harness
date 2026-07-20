.PHONY: install test run gate verify dashboard lint clean
install:      ; pip install -e ".[dev]"
test:         ; PYTHONPATH=src python -m pytest tests/ -q
run:          ; PYTHONPATH=src python -m aah.cli.main run --out out
run-vuln:     ; PYTHONPATH=src python -m aah.cli.main run --vulnerable --out out-vuln
verify:       ; PYTHONPATH=src python -m aah.cli.main verify out/evidence.json
gate:         ; PYTHONPATH=src python -m aah.cli.main gate out/evidence.json
lint:         ; ruff check src tests || true ; mypy src || true
clean:        ; rm -rf out out-* .pytest_cache **/__pycache__
demo:         ; bash demo.sh
run-arbiter:  ; PYTHONPATH=src python -m aah.cli.main run --target arbiter --out out
