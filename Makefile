.PHONY: env venv install db-up db-check db-down test migrate api worker demo frontend-install frontend

PY ?= python3

env:            ## создать .env из шаблона, если его ещё нет
	@test -f .env || cp .env.example .env

venv:           ## создать виртуальное окружение .venv
	$(PY) -m venv .venv

install:        ## поставить пакеты проекта в режиме разработки (запускать внутри .venv)
	python -m pip install -U pip
	python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
	python -m pip install -e ./core -e ./ml -e "./backend[test]"

db-up: env      ## поднять PostgreSQL и дождаться готовности
	docker compose up -d --wait db

db-check:       ## проверить, что БД отвечает на запросы
	docker compose exec -T db sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -tAc "select version();"'

db-down:        ## остановить контейнеры (данные БД сохраняются в томе)
	docker compose down

test:           ## все тесты
	python -m pytest core/tests ml/tests backend/tests -q

migrate:        ## применить миграции БД (Alembic)
	cd backend && alembic upgrade head

api:            ## запустить API: http://localhost:8000/docs
	cd backend && uvicorn app.main:app --reload --port 8000

worker:         ## запустить worker (разбирает файлы из очереди)
	cd backend && python -m worker.main

demo:           ## подготовить векторы тестовой выборки для режима «образец из теста»
	python -m mltrain.export_demo

frontend-install: ## поставить пакеты веб-интерфейса (нужен Node.js 18+)
	cd frontend && npm install

frontend:       ## запустить веб-интерфейс: http://localhost:5173 (API и worker должны работать)
	cd frontend && npm run dev
