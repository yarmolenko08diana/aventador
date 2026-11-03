"""PDF-отчёт по одному анализу (ReportLab).

Всё содержимое берётся из БД — тех же записей, что показывает страница анализа:
файл и хеши, вердикт, ответы каждой модели, индикаторы, сведения о PE,
версии моделей и их метрики на тесте. Кириллица — через встроенный шрифт DejaVu Sans
(лежит в app/assets/fonts, лицензия рядом), поэтому отчёт не зависит от шрифтов системы.

Все строки из файла (имя, секции, импорты, улики индикаторов) экранируются перед
вставкой в Paragraph: ReportLab понимает в тексте разметку, а имя файла задаёт пользователь.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.db.models import Analysis, ModelVersion

FONTS = Path(__file__).resolve().parents[1] / "assets" / "fonts"
TASK_TITLE = {"detection": "Обнаружение", "family": "Семейство", "category": "Категория"}
ALGO_TITLE = {"rf": "Random Forest", "lgbm": "LightGBM", "mlp": "MLP", "ensemble": "Ансамбль"}
VERDICT_TITLE = {"clean": "БЕЗОПАСНЫЙ", "suspicious": "ПОДОЗРИТЕЛЬНЫЙ", "malicious": "ВРЕДОНОСНЫЙ"}
VERDICT_COLOR = {"clean": "#047857", "suspicious": "#b45309", "malicious": "#b91c1c"}
LABEL_RU = {"benign": "безопасный", "malware": "вредоносный"}
SEVERITY_RU = {"high": "высокая", "medium": "средняя", "low": "низкая"}
GREY = colors.HexColor("#64748b")
LINE = colors.HexColor("#e2e8f0")

LIMITATIONS = [
    "Анализ только статический: файл не запускался, поэтому поведение, которое проявляется лишь при запуске "
    "(загрузка модулей из сети, распаковка в памяти), не наблюдается.",
    "Упакованные и обфусцированные файлы описываются признаками упаковщика, а не исходной программы: это снижает "
    "точность определения семейства.",
    "Модели обучены на BODMAS (вредоносные файлы собраны в 2019–2020 годах). Новые семейства модель не знает: для них правильный ответ "
    "системы — «семейство не определено», а не угадывание ближайшего.",
    "Пороги вердикта выбраны на validation: «вредоносный» — при доле ложных тревог не выше 1%, «подозрительный» — "
    "не выше 5%. Значит, часть безопасных файлов будет получать «подозрительный».",
    "Индикаторы — правила для человека; они объясняют, на что смотреть, и не влияют на вердикт моделей. "
    "Наличие цифровой подписи отмечается, но цепочка сертификатов не проверяется.",
    "Отчёт — вспомогательный инструмент. Окончательное решение о файле принимает специалист.",
]

_registered = False


def _register_fonts() -> None:
    global _registered
    if _registered:
        return
    pdfmetrics.registerFont(TTFont("DejaVu", str(FONTS / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(FONTS / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVuMono", str(FONTS / "DejaVuSansMono.ttf")))
    pdfmetrics.registerFontFamily("DejaVu", normal="DejaVu", bold="DejaVu-Bold", italic="DejaVu", boldItalic="DejaVu-Bold")
    _registered = True


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName="DejaVu", fontSize=9, leading=12, alignment=TA_LEFT)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=10, textColor=GREY),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=10),
        "mono": ParagraphStyle("mono", parent=base, fontName="DejaVuMono", fontSize=7.5, leading=10),
        "h1": ParagraphStyle("h1", parent=base, fontName="DejaVu-Bold", fontSize=16, leading=20, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base, fontName="DejaVu-Bold", fontSize=11.5, leading=15,
                             spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("h3", parent=base, fontName="DejaVu-Bold", fontSize=9.5, leading=12,
                             spaceBefore=6, spaceAfter=2),
        "verdict": ParagraphStyle("verdict", parent=base, fontName="DejaVu-Bold", fontSize=14, leading=18),
    }


def t(value) -> str:
    """Текст из БД/файла → безопасная строка для Paragraph."""
    return escape("—" if value is None or value == "" else str(value))


def _pct(x: float | None, digits: int = 1) -> str:
    return "—" if x is None else f"{x * 100:.{digits}f}%"


def _num(x: float | None, digits: int = 4) -> str:
    return "—" if x is None else f"{x:.{digits}f}"


def _dt(d: datetime | None) -> str:
    return "—" if d is None else d.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")


def _size(n: int | None) -> str:
    if n is None:
        return "—"
    return f"{n} Б" if n < 1024 else f"{n / 1024:.1f} КБ" if n < 1024 ** 2 else f"{n / 1024 ** 2:.1f} МБ"


def _table(rows: list[list], widths: list[float], header: bool = True, zebra: bool = False) -> Table:
    tbl = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONTNAME", (0, 0), (-1, -1), "DejaVu"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"), ("TEXTCOLOR", (0, 0), (-1, 0), GREY),
                  ("FONTSIZE", (0, 0), (-1, 0), 7.5), ("LINEBELOW", (0, 0), (-1, 0), 0.8, GREY)]
    if zebra:
        for i in range(1 if header else 0, len(rows), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8fafc")))
    tbl.setStyle(TableStyle(style))
    return tbl


def _kv(pairs: list[tuple[str, str]], s: dict, width: float) -> Table:
    rows = [[Paragraph(t(k), s["small"]), Paragraph(v, s["cell"])] for k, v in pairs]
    return _table(rows, [width * 0.3, width * 0.7], header=False)


def _main_metrics(mv: ModelVersion) -> str:
    ev = mv.evaluations[0] if mv.evaluations else None
    if ev is None:
        return "нет оценки на тесте"
    m = ev.metrics or {}
    if mv.task == "detection":
        return (f"TPR при FPR≤1%: {_num(ev.tpr_at_fpr_1pct)}; ROC-AUC: {_num(ev.roc_auc)}; "
                f"FPR вердикта «вредоносный»: {_num(m.get('malicious_fpr'))}")
    text = f"macro-F1: {_num(ev.f1_macro)}; accuracy: {_num(ev.accuracy)}"
    open_set = m.get("open_set")
    if mv.task == "family" and open_set:
        text += (f"; open-set macro-F1: {_num(open_set.get('open_set_macro_f1'))}; "
                 f"неизвестных отвергнуто: {_pct(open_set.get('unknown_rejected'))}")
    return text


def _evidence(ev: dict) -> str:
    """Короткая строка с уликами правила; длинные списки обрезаются."""
    parts = []
    for k, v in (ev or {}).items():
        if isinstance(v, list):
            shown = ", ".join(str(x) for x in v[:8]) + (f" … ещё {len(v) - 8}" if len(v) > 8 else "")
        elif isinstance(v, dict):
            shown = ", ".join(f"{a}={b}" for a, b in list(v.items())[:6])
        else:
            shown = str(v)
        parts.append(f"{k}: {shown}")
    text = "; ".join(parts)
    return text[:600] + ("…" if len(text) > 600 else "")


def report_filename(a: Analysis) -> str:
    return f"report-{a.sample.sha256}.pdf"


def build_report(a: Analysis, generated_at: datetime | None = None) -> bytes:
    """Собирает PDF для завершённого анализа и возвращает его байты."""
    if a.status != "done":
        raise ValueError(f"анализ в статусе {a.status}: отчёт строится только для завершённого")
    _register_fonts()
    s = _styles()
    generated_at = generated_at or datetime.now(timezone.utc)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"Отчёт анализа №{a.id}", author="Malscan",
                            subject=f"SHA-256 {a.sample.sha256}")
    W = doc.width
    sample = a.sample
    story: list = []

    # Заголовок
    name = sample.original_name or ("Образец из тестовой выборки BODMAS" if sample.source == "dataset" else sample.sha256)
    story += [
        Paragraph("Отчёт статического анализа файла", s["h1"]),
        Paragraph(f"Анализ №{a.id} · {t(name)} · сформирован {_dt(generated_at)}", s["small"]),
        Spacer(1, 8),
    ]

    # 1. Заключение
    final_det = next((p for p in a.predictions if p.task == "detection" and p.is_final), None)
    thr = final_det.model_version.thresholds if final_det else {}
    verdict_par = Paragraph(
        f'<font color="{VERDICT_COLOR[a.verdict]}">{VERDICT_TITLE[a.verdict]}</font>', s["verdict"])
    if a.family_status == "identified":
        family = f"<b>{t(a.final_family)}</b> (уверенность {_pct(a.family_confidence)})"
    elif a.family_status == "unknown":
        family = (f"<b>не определено</b>: уверенность {_pct(a.family_confidence)} ниже порога, выбранного на "
                  f"validation; вероятно, семейства нет среди тех, на которых училась модель")
    else:
        family = "не определялось: файл признан безопасным"
    category = (f"<b>{t(a.final_category)}</b> (уверенность {_pct(a.category_confidence)})"
                if a.final_category else "не определялась")
    disagree = [TASK_TITLE[k] for k, v in (a.disagreement or {}).items() if v]
    pairs = [
        ("Вероятность вредоносности", f"<b>{_num(a.detector_score)}</b> (итоговая модель: "
                                      f"{t(ALGO_TITLE.get(final_det.model_version.algorithm)) if final_det else '—'})"),
        ("Пороги вердикта", f"вредоносный ≥ {_num(thr.get('malicious'))}, подозрительный ≥ {_num(thr.get('suspicious'))}"),
        ("Семейство", family),
        ("Категория", category),
        ("Согласие моделей", "модели расходятся в задачах: " + ", ".join(disagree) if disagree else "все модели согласны"),
    ]
    story += [Paragraph("1. Заключение", s["h2"]), verdict_par, Spacer(1, 4), _kv(pairs, s, W)]

    # Сравнение с правдой для образца из теста
    truth = sample.dataset_truth
    if truth:
        target_cat = truth.get("category_target") or truth.get("category")
        rows = [["", "Правильный ответ (BODMAS)", "Прогноз системы"],
                ["Класс", LABEL_RU.get(truth.get("label"), truth.get("label")),
                 VERDICT_TITLE[a.verdict].lower()]]
        if truth.get("label") == "malware":
            fam_truth = str(truth.get("family")) + ("" if truth.get("family_in_classifier") else " (нет среди классов модели)")
            rows.append(["Семейство", fam_truth, a.final_family or ("не определено" if a.family_status == "unknown" else "—")])
            rows.append(["Категория", f"{truth.get('category')} (для модели: {target_cat})"
                         if target_cat != truth.get("category") else str(target_cat), a.final_category or "—"])
        rows = [[Paragraph(escape(str(c or "")), s["cell"]) for c in r] for r in rows]
        story += [Paragraph("Сравнение с правильным ответом", s["h3"]), _table(rows, [W * 0.2, W * 0.45, W * 0.35])]

    # 2. Файл
    pairs = [
        ("Имя файла", t(sample.original_name)),
        ("Источник", "загрузка пользователем" if sample.source == "upload" else "тестовая выборка BODMAS (только вектор признаков)"),
        ("Размер", t(_size(sample.size_bytes))),
        ("SHA-256", f'<font name="DejaVuMono">{t(sample.sha256)}</font>'),
        ("SHA-1", f'<font name="DejaVuMono">{t(sample.sha1)}</font>'),
        ("MD5", f'<font name="DejaVuMono">{t(sample.md5)}</font>'),
        ("Впервые получен", _dt(sample.first_seen_at)),
        ("Анализ", f"поставлен {_dt(a.created_at)}, завершён {_dt(a.finished_at)}, "
                   f"{a.duration_ms:.0f} мс" if a.duration_ms is not None else _dt(a.finished_at)),
        ("Версия признаков", t(a.feature_version)),
    ]
    story += [Paragraph("2. Файл", s["h2"]), _kv(pairs, s, W)]

    # 3. Ответы моделей
    story.append(Paragraph("3. Ответ каждой модели", s["h2"]))
    for task in ("detection", "family", "category"):
        preds = [p for p in a.predictions if p.task == task]
        if not preds:
            continue
        rows = [["Модель", "Версия", "Ответ", "Уверенность", "Топ-3", "Время"]]
        for p in sorted(preds, key=lambda p: ["rf", "lgbm", "mlp", "ensemble"].index(p.model_version.algorithm)):
            top = ", ".join(f"{LABEL_RU.get(k['label'], k['label'])} {_pct(k['probability'])}" for k in p.top_k)
            rows.append([
                Paragraph(t(ALGO_TITLE[p.model_version.algorithm]) + (" <b>(итоговая)</b>" if p.is_final else ""), s["cell"]),
                Paragraph(t(p.model_version.version), s["mono"]),
                Paragraph(t(LABEL_RU.get(p.predicted_label, p.predicted_label)), s["cell"]),
                _pct(p.confidence), Paragraph(t(top), s["cell"]), f"{p.latency_ms:.1f} мс",
            ])
        story.append(KeepTogether([Paragraph(TASK_TITLE[task], s["h3"]),
                                   _table(rows, [W * 0.2, W * 0.15, W * 0.15, W * 0.12, W * 0.28, W * 0.1], zebra=True)]))
    story.append(Paragraph("«Итоговая» — модель, выбранная по validation; её ответ и пороги дают вердикт. "
                           "Семейство и категория определяются, только если файл не признан безопасным.", s["small"]))

    # 4. Индикаторы
    story.append(Paragraph("4. Подозрительные индикаторы", s["h2"]))
    if sample.source == "dataset":
        story.append(Paragraph("Не строятся: у образца из тестовой выборки нет самого файла, есть только вектор признаков.", s["base"]))
    elif not a.indicator_hits:
        story.append(Paragraph("Ни одно из правил не сработало.", s["base"]))
    else:
        order = {"high": 0, "medium": 1, "low": 2}
        rows = [["Важность", "Индикатор", "Что найдено"]]
        for h in sorted(a.indicator_hits, key=lambda h: order.get(h.severity, 3)):
            rows.append([
                SEVERITY_RU.get(h.severity, h.severity),
                Paragraph(f"<b>{t(h.rule.title)}</b><br/>{t(h.rule.description)}"
                          + (f'<br/><font color="#64748b">Оговорка: {t(h.rule.caveat)}</font>' if h.rule.caveat else ""),
                          s["cell"]),
                Paragraph(t(_evidence(h.evidence)), s["mono"]),
            ])
        story.append(_table(rows, [W * 0.12, W * 0.48, W * 0.4], zebra=True))
    story.append(Paragraph("Индикаторы объясняют, на что обратить внимание, и не влияют на вердикт моделей.", s["small"]))

    # 5. Сведения о PE
    info = a.features.static_info if a.features else None
    if info:
        story.append(Paragraph("5. Структура PE-файла", s["h2"]))
        pairs = [
            ("Формат", t(f"{info.get('format') or '—'} {info.get('kind') or ''}".strip())),
            ("Архитектура", t(info.get("machine"))),
            ("Подсистема", t(info.get("subsystem"))),
            ("Время компиляции", t(info.get("compile_time") or "0 (не указано)")),
            ("Точка входа", t(f"0x{(info.get('entry_point_rva') or 0):x} в секции {info.get('entry_point_section') or '—'}")),
            ("Энтропия файла", _num(info.get("entropy"), 3)),
            ("Цифровая подпись", "есть (цепочка не проверяется)" if info.get("has_signature") else "нет"),
            ("Overlay", f"{info['overlay_size']} байт" if info.get("overlay_size") else "нет"),
            ("Ресурсы / экспорты", f"{len(info.get('resources') or [])} / {len(info.get('exports') or [])}"),
        ]
        story.append(_kv(pairs, s, W))
        if a.sections:
            rows = [["Секция", "Вирт. адрес", "Вирт. размер", "На диске", "Энтропия", "Права"]]
            for sec in a.sections:
                perms = ("R" if sec.is_read else "-") + ("W" if sec.is_write else "-") + ("X" if sec.is_exec else "-")
                rows.append([Paragraph(t(sec.name), s["mono"]), f"0x{sec.virtual_address:x}", str(sec.virtual_size),
                             str(sec.raw_size), f"{sec.entropy:.2f}", perms])
            story += [Paragraph("Секции", s["h3"]),
                      _table(rows, [W * 0.2, W * 0.16, W * 0.16, W * 0.16, W * 0.14, W * 0.18], zebra=True)]
        if a.imports:
            by_dll: dict[str, list[str]] = {}
            for imp in a.imports:
                by_dll.setdefault(imp.dll, []).append(imp.function)
            rows = [["Библиотека", "Функций", "Примеры"]]
            for dll, funcs in sorted(by_dll.items(), key=lambda kv: -len(kv[1])):
                shown = ", ".join(funcs[:10]) + (f" … ещё {len(funcs) - 10}" if len(funcs) > 10 else "")
                rows.append([Paragraph(t(dll), s["mono"]), str(len(funcs)), Paragraph(t(shown), s["mono"])])
            story += [Paragraph(f"Импорты: {len(by_dll)} библиотек, {len(a.imports)} функций", s["h3"]),
                      _table(rows, [W * 0.22, W * 0.1, W * 0.68], zebra=True)]

    # 6. Модели и их качество
    story.append(Paragraph(f"{6 if info else 5}. Использованные модели и их качество на тесте", s["h2"]))
    rows = [["Задача", "Модель", "Версия", "Обучена", "Метрики на тесте (по времени)"]]
    seen: set[int] = set()
    for p in sorted(a.predictions, key=lambda p: (["detection", "family", "category"].index(p.task),
                                                   ["rf", "lgbm", "mlp", "ensemble"].index(p.model_version.algorithm))):
        mv = p.model_version
        if mv.id in seen:
            continue
        seen.add(mv.id)
        rows.append([TASK_TITLE[mv.task],
                     Paragraph(t(ALGO_TITLE[mv.algorithm]) + (" <b>(итоговая)</b>" if p.is_final else ""), s["cell"]),
                     Paragraph(t(mv.version), s["mono"]), mv.trained_at.strftime("%d.%m.%Y"),
                     Paragraph(t(_main_metrics(mv)), s["cell"])])
    story.append(_table(rows, [W * 0.14, W * 0.2, W * 0.15, W * 0.12, W * 0.39], zebra=True))
    ds = next((p.model_version for p in a.predictions), None)
    if ds:
        story.append(Paragraph(f"Данные: {t(ds.dataset)}, разбиение «{t(ds.split_strategy)}»: модели учились на ранних "
                               "файлах и проверялись на самых поздних, которых не видели при обучении. "
                               "Тестовая выборка использована для оценки один раз.", s["small"]))

    # 7. Ограничения
    story.append(Paragraph(f"{7 if info else 6}. Ограничения метода", s["h2"]))
    for line in LIMITATIONS:
        story.append(Paragraph(f"• {line}", s["base"]))

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("DejaVu", 7)
        canvas.setFillColor(GREY)
        canvas.drawString(16 * mm, 9 * mm, f"Malscan · анализ №{a.id} · SHA-256 {sample.sha256}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"стр. {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
