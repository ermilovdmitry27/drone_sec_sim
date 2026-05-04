# Validation Evidence

Этот каталог предназначен для файлов доказательств, на основании которых проект может
формировать проверяемый статус аппаратной валидации и повторяемости прогонов.

## Gazebo Model Specification

В проекте поддерживается локальная проверяемая спецификация модели `gz_x500`.

1. Запустите:
   ```bash
   .venv/bin/python tools/extract_gz_x500_model_spec.py
   ```
2. Скрипт создаст `validation/gz_x500_model_spec.json`.
3. Файл фиксирует:
   - соответствие make-цели `gz_x500`
   - значение `PX4_SIM_MODEL`
   - список датчиков модели
   - список моторных исполнительных каналов
   - вспомогательные плагины модели

## Hardware Validation

1. Возьмите шаблон [hardware_validation.example.json](./hardware_validation.example.json).
2. Скопируйте его в `validation/hardware_validation.json`.
3. После реальных испытаний на целевой платформе заполните:
   - `status`
   - `validated_on`
   - `operator`
   - `lab`
   - `platform`
   - `required_checks`
   - `artifacts`
4. Статус аппаратной валидации будет считаться подтвержденным только если:
   - `status == "passed"`
   - платформа в файле совпадает с `sim_stack.json`
   - все обязательные проверки отмечены как `true`

## Determinism / Repeatability

Для оценки повторяемости под тестом используйте:

```bash
.venv/bin/python tools/determinism_report.py \
  --run-dir <run_1_logs_dir> \
  --run-dir <run_2_logs_dir> \
  --scenario <scenario_name>
```

Скрипт создаст `validation/determinism_report.json`.

Важно:

- Этот отчет оценивает повторяемость последовательностей событий между повторами сценария.
- Он не является формальным доказательством полной детерминированности PX4.
- Поле `determinism_of_autopilot_proven` в архитектурном отчете по-прежнему остается `not_proven_by_code`.
