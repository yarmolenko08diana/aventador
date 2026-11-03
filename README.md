# Система статического анализа и классификации семейств ВПО

Учебный проект: веб-система, которая без запуска файла анализирует Windows PE (.exe, .dll),
определяет, вредоносный ли он, и классифицирует его по семейству. Используются три модели:
Random Forest, LightGBM и MLP.
Полное техническое задание лежит в Claude Docs (ссылка в описании репозитория), краткая версия будет в `docs/`.

> Файлы никогда не запускаются. Анализ только статический. Обучение идёт на готовых
> векторах признаков BODMAS, бинарники ВПО в проекте не используются.

## Структура

| Папка | Что внутри | Этап |
| --- | --- | --- |
| `core/` | Общий пакет `malcore`: признаки, индикаторы, инференс | 2–3, 6 |
| `ml/` | Пакет `mltrain`: данные BODMAS, обучение, оценка | 1, 4–5 |
| `backend/` | FastAPI (`app/`) и изолированный worker (`worker/`) | 6, 8–9 |
| `frontend/` | React + TypeScript + Tailwind | 7–8 |
| `data/` | Датасет и разбиения (не в git) | 1 |
| `artifacts/models/` | Обученные модели и их манифесты (не в git) | 4–5 |
| `docs/` | ТЗ, описание датасета, сценарий защиты | — |

## Установка на Windows 11 (WSL2)

Всё запускается внутри WSL2 (Ubuntu). Так команды одинаковые на ноутбуке и в Docker.

1. **WSL2 и Ubuntu.** В PowerShell от администратора выполните `wsl --install -d Ubuntu`, затем перезагрузите компьютер и задайте пользователя Ubuntu.
2. **Docker Desktop.** Установите [Docker Desktop](https://www.docker.com/products/docker-desktop/). В Settings → Resources → WSL integration включите Ubuntu.
3. **Память для WSL.** При 16 ГБ ОЗУ создайте файл `C:\Users\<имя>\.wslconfig` с содержимым ниже, затем выполните `wsl --shutdown`:
   ```ini
   [wsl2]
   memory=10GB
   ```
4. **Инструменты в Ubuntu:**
   ```bash
   sudo apt update && sudo apt install -y python3 python3-venv python3-pip make git
   ```
5. **Код храните внутри WSL** (например, `~/projects/`), а не на `C:\`: так работа с файлами в разы быстрее.

## Запуск этапа 0

```bash
git clone <url-репозитория> && cd malware-classifier
make env          # создаёт .env из .env.example
make venv && . .venv/bin/activate
make install      # ставит core, ml, backend в режиме разработки
make db-up        # поднимает PostgreSQL 16 и ждёт готовности
make db-check     # печатает версию PostgreSQL
make test         # 3 теста, включая подключение к БД
```

Этап 0 готов, когда `make test` показывает `3 passed`.

## Данные (этап 1)

Скачайте со [страницы BODMAS](https://whyisyoung.github.io/BODMAS/) три файла и положите их в `data/raw/bodmas/`:

- `bodmas.npz`: векторы признаков EMBER v2 и метки;
- `bodmas_metadata.csv`: sha256, время и семейство;
- `bodmas_malware_category.csv`: категория (trojan, worm, …).
