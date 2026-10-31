.PHONY: install train test lint run up deploy

install:
	pip install -r backend/requirements-dev.txt

train:            ## regenerate corpus, retrain, export model.json + sample log
	python ml/train.py

test:
	cd backend && pytest -q
	cd frontend && node --test tests/engine.test.mjs

lint:
	ruff check .
	shellcheck agent/*.sh

run:              ## API on :8000, dashboard on :8080
	cd backend && uvicorn app.main:app --reload --port 8000 & cd frontend && python3 -m http.server 8080

up:
	docker compose up --build

deploy:           ## AWS free tier via SAM (needs `aws configure`)
	cd infra && sam build --use-container && sam deploy
