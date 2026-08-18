.PHONY: run test report dataset demo-data

run:
	python3 app.py

test:
	python3 -m unittest discover -s tests -v

report:
	python3 scripts/train_model.py --report work/model-report.json

dataset:
	python3 scripts/generate_dataset.py --rows 10000 --output data/synthetic_payments.jsonl

demo-data:
	python3 scripts/build_demo_data.py
