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
cd ~ && git clone https://github.com/yarmolenko08diana/aventador.git && cd aventador
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

Затем:

```
python -m mltrain.data.prepare
```

## Индикаторы (этап 3)

Оценка ложных срабатываний правил на безопасных файлах Windows (файлы только читаются):

```
python -m malcore.indicators.fp_report /mnt/c/Windows/System32 --limit 1000 --top 10
```

## Обучение моделей (этап 4)

После `git pull` переустановите пакеты: появились lightgbm и PyTorch (CPU-сборка).

```
make install
python -m mltrain.train --all
```

Обучаются 9 моделей (RF, LightGBM, MLP × detection, family, category) и 3 ансамбля.
Параметры лежат в `ml/configs/train.yaml`. Гиперпараметры и пороги подбираются только на validation,
тестовая выборка на этом этапе не загружается. Можно обучать по частям:

```
python -m mltrain.train --task detection              # три модели и ансамбль одной задачи
python -m mltrain.train --task family --model lgbm    # одна модель
```

Результат: `artifacts/models/<задача>/<модель>/` с файлом модели, `manifest.json` (классы, пороги,
гиперпараметры, метрики validation, sha256 файлов, версии библиотек) и `train.log`.
После сохранения модель загружается заново через `malcore` (как в сервисе) и сверяется с исходной.

Проверка воспроизводимости (переобучает модель во временную папку и сравнивает метрики validation):

```
python -m mltrain.train --task detection --model lgbm --verify
```

## Оценка на тесте (этап 5)

```
pip install -e ./ml                  # добавился matplotlib для рисунков
python -m mltrain.evaluate --all     # единственный прогон на тестовой выборке
python -m mltrain.experiments        # случайное разбиение, дата компиляции, важность признаков
```

Результаты: `evaluation.json` рядом с каждой моделью, `artifacts/reports/evaluation.md`,
`artifacts/reports/experiments.md` и рисунки в `artifacts/reports/figures/`.
Тест используется один раз: повторный запуск `evaluate` требует флага `--again` и отмечается в отчёте.
Модель итогового вердикта выбирается по validation (`artifacts/models/<задача>/selection.json`).

## Backend: API, БД и worker (этап 6)

```
make install          # добавились fastapi, sqlalchemy, alembic
make db-up            # PostgreSQL в Docker
make migrate          # создать таблицы
make demo             # векторы тестовой выборки для режима «образец из теста»
make worker           # терминал 1: worker разбирает файлы из очереди
make api              # терминал 2: API, документация на http://localhost:8000/docs
```

Поток анализа: `POST /api/v1/samples` (файл) → проверка MZ/PE, хеши, карантин `quarantine/<sha256>.bin`
(только чтение) → анализ в статусе `queued` → worker берёт его из очереди, разбирает файл в дочернем процессе
с тайм-аутом и лимитом памяти, применяет правила и модели → `done` или `failed` с причиной.
API сам PE-файлы не разбирает, а скачать файл обратно через API нельзя.

Режим «образец из тестовой выборки»: `POST /api/v1/analyses/from-dataset` с sha256 из `GET /api/v1/dataset/examples`.
Индикаторов в этом режиме нет: самого файла нет, есть только вектор признаков.

## Веб-интерфейс (этап 7)

Нужен Node.js 18 или новее (`node -v`). Перед запуском должны работать `make api` и `make worker`.

```
make frontend-install   # один раз: пакеты React, Vite, Tailwind, Chart.js
make frontend           # терминал 3: http://localhost:5173
```

Страницы:
- **Загрузка** (`/upload`): перетащить PE-файл или выбрать образец из тестовой выборки BODMAS
  (безопасный, известное семейство, семейство, которого нет в классификаторе). Повторная загрузка
  того же файла предлагает открыть прошлый анализ или запустить новый.
- **Анализ** (`/analyses/:id`): статус обновляется раз в секунду, пока worker работает. Затем вердикт,
  семейство («не определено», если уверенность ниже порога), категория, ответ каждой из 4 моделей
  с топ-3 вероятностями, индикаторы, сведения о PE, секции, импорты. Для образца из теста есть
  сравнение с правильным ответом.
- **Панель** (`/`): число анализов, вердикты, семейства, анализы по дням, последние анализы.

Dev-сервер Vite проксирует `/api` на `http://127.0.0.1:8000`, поэтому CORS настраивать не нужно.
Проверка типов и сборка: `cd frontend && npm run build`.
