# Drone Security Simulation

Проект содержит стенд для запуска PX4 SITL с Gazebo, QGroundControl и внешним
Security Monitor, а также набор сценариев и инструментов для формирования
артефактов по покрытию угроз.

## Что есть в репозитории

- `launch_stack.py` запускает PX4 SITL, Security Monitor и, если задан путь,
  QGroundControl.
- `monitor.py` запускает Security Monitor отдельно.
- `sim_stack.json` хранит основной профиль стенда: путь к PX4-Autopilot,
  модель `gz_x500`, путь к QGroundControl, порты gateway и каталог логов.
- `security_agent/` содержит код агента мониторинга, gateway, детектора,
  risk engine, responder и state guard.
- `scenarios/` содержит сценарии атак и раннер покрытия угроз.
- `tools/` содержит генераторы отчетов и проверочных артефактов.
- `validation/` содержит README и файлы доказательств для валидации модели,
  аппаратной проверки и повторяемости прогонов.

## Подготовка окружения

Создайте виртуальное окружение Python и установите зависимости:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

`requirements.txt` фиксирует `mavsdk==3.15.3`. В текущем проверенном окружении
`pip show mavsdk` показывает, что этот пакет требует `grpcio` и `protobuf`;
они будут установлены pip как зависимости `mavsdk`.

## Ограничения перед запуском

По умолчанию `sim_stack.json` ожидает:

- PX4-Autopilot в `/home/user/PX4-Autopilot`;
- QGroundControl AppImage в `/home/user/QGroundControl.AppImage`;
- модель PX4/Gazebo `gz_x500`;
- каталог логов `logs`.

Если пути отличаются, передайте их параметрами `launch_stack.py` или измените
`sim_stack.json`.

По умолчанию в `sim_stack.json` включен строгий gateway-режим:
`gateway_enforce=true`. В этом режиме gateway блокирует запись параметров,
запись миссии и `SERIAL_CONTROL`.

`authorized_client_hosts` ограничивает хосты, от которых gateway принимает
MAVLink-клиентов. По умолчанию разрешен только `127.0.0.1`.

Gateway поддерживает опциональное AES-GCM-шифрование клиентских MAVLink datagram.
Ключ задается hex-строкой через `mavlink_encryption_key_hex` в `sim_stack.json`
или через `--mavlink-encryption-key-hex`. Режим `require_encrypted_clients=true`
отклоняет нешифрованные клиентские datagram. По умолчанию этот режим выключен,
чтобы не ломать штатный QGroundControl/MAVSDK UDP-поток.

Для операторской аутентификации gateway поддерживает authenticated encrypted
datagram wrapper `DSEC2`: клиент передает `operator_id`, `token` и MAVLink
payload внутри AES-GCM-конверта, а gateway сверяет SHA-256 hash токена с
`operator_token_hashes`. Режим `require_operator_auth=true` отклоняет клиентские
datagram без authenticated wrapper. По умолчанию этот режим выключен.

## Запуск полного стенда

Из корня проекта:

```bash
.venv/bin/python launch_stack.py
```

Переопределить путь к PX4-Autopilot:

```bash
.venv/bin/python launch_stack.py --px4-dir /path/to/PX4-Autopilot
```

Переопределить путь к QGroundControl:

```bash
.venv/bin/python launch_stack.py --qgc-path /path/to/QGroundControl.AppImage
```

Использовать альтернативный конфиг:

```bash
.venv/bin/python launch_stack.py --config /path/to/sim_stack.json
```

После старта QGroundControl launcher выводит инструкцию создать ручной UDP
Comm Link на `127.0.0.1:<gateway_gcs_client_port>`. В текущем `sim_stack.json`
значение `gateway_gcs_client_port` равно `14552`.

Остановка стенда выполняется через `Ctrl+C` в терминале, где запущен
`launch_stack.py`.

## Запуск только Security Monitor

```bash
.venv/bin/python monitor.py
```

Полезные параметры:

```bash
.venv/bin/python monitor.py --log-dir logs
.venv/bin/python monitor.py --active-response
.venv/bin/python monitor.py --enable-gateway
.venv/bin/python monitor.py --gateway-enforce
.venv/bin/python monitor.py --gateway-block-serial-control
.venv/bin/python monitor.py --siem-url http://127.0.0.1:8080/events
.venv/bin/python monitor.py --authorized-client-host 127.0.0.1
.venv/bin/python monitor.py --mavlink-encryption-key-hex <32_or_64_hex_chars>
.venv/bin/python monitor.py --require-encrypted-clients
.venv/bin/python monitor.py --operator-token-hash operator-1:<sha256_hex>
.venv/bin/python monitor.py --require-operator-auth
```

Посмотреть полный список параметров:

```bash
.venv/bin/python monitor.py --help
```

## Сценарии покрытия угроз

Smoke-прогон по первым записям каталога:

```bash
.venv/bin/python scenarios/run_threat_coverage.py \
  --all \
  --limit 5 \
  --log-dir logs/threat_coverage_smoke
```

Прогон всего каталога:

```bash
.venv/bin/python scenarios/run_threat_coverage.py \
  --all \
  --log-dir logs/threat_coverage_all
```

Прогон выбранной угрозы:

```bash
.venv/bin/python scenarios/run_threat_coverage.py \
  --threat-id <THREAT_ID> \
  --log-dir logs/threat_coverage_selected
```

Добавить события профилей в логи:

```bash
.venv/bin/python scenarios/run_threat_coverage.py \
  --all \
  --emit-profile-events \
  --log-dir logs/threat_coverage_all
```

## Отчеты и проверочные артефакты

Архитектурный отчет в Markdown:

```bash
.venv/bin/python tools/architecture_report.py --format md
```

Архитектурный отчет в JSON:

```bash
.venv/bin/python tools/architecture_report.py --format json
```

Обновить локальную спецификацию модели `gz_x500`:

```bash
.venv/bin/python tools/extract_gz_x500_model_spec.py
```

Оценить повторяемость двух прогонов сценария:

```bash
.venv/bin/python tools/determinism_report.py \
  --run-dir <run_1_logs_dir> \
  --run-dir <run_2_logs_dir> \
  --scenario <scenario_name>
```

## Проверки качества

Запустить unit-тесты:

```bash
make test
```

Проверить команды, документированные в README:

```bash
make validate-readme
```

Проверить SHA-256 hash-chain в audit-логах smoke-прогона:

```bash
make verify-smoke-logs
```

Проверить AES-GCM encrypted datagram roundtrip:

```bash
make validate-encryption
```

Пересобрать Word-отчет по методам защиты:

```bash
make protection-doc
```

## Логи

По умолчанию логи пишутся в каталог `logs`. Каталог `logs/` исключен из Git
через `.gitignore`, поэтому результаты локальных прогонов не попадают в коммиты
автоматически.

Каждая JSONL-запись audit-логов содержит `audit_hash` и `audit_prev_hash`.
Эти поля образуют SHA-256 hash-chain внутри каждого лог-файла и позволяют
выявлять изменение или удаление записей после формирования журнала.

Если в `sim_stack.json` задан `siem_url` или `monitor.py` запущен с
`--siem-url`, audit-события дополнительно отправляются HTTP POST-запросами в
указанный SIEM endpoint. Если `siem_url` пустой, локальные JSONL-логи
продолжают писаться без внешней отправки.

Для проверки формата encrypted datagram можно использовать:

```bash
.venv/bin/python tools/encrypted_mavlink_datagram.py encrypt \
  --key-hex <32_or_64_hex_chars> \
  --input mavlink.bin \
  --output mavlink.enc
```

Authenticated encrypted datagram для режима `require_operator_auth`:

```bash
.venv/bin/python tools/encrypted_mavlink_datagram.py encrypt \
  --key-hex <32_or_64_hex_chars> \
  --operator-id operator-1 \
  --operator-token <token> \
  --input mavlink.bin \
  --output mavlink.auth.enc
```

## Проверочные источники

Команды и ограничения в этом README проверяются по следующим файлам проекта:

- `launch_stack.py`: аргументы запуска, запуск PX4 SITL, Security Monitor,
  QGroundControl и обработка `Ctrl+C`.
- `monitor.py`: аргументы Security Monitor.
- `sim_stack.json`: значения `px4_dir`, `model`, `qgc_path`, gateway-портов,
  `gateway_enforce`, `active_response`, `siem_url` и `log_dir`.
- `security_agent/audit.py`: SHA-256 hash-chain audit-логов и SIEM HTTP export.
- `security_agent/gateway.py`: MAVLink gateway filtering, endpoint access
  policy, optional AES-GCM datagram encryption and operator authentication.
- `scenarios/run_threat_coverage.py`: параметры раннера покрытия угроз.
- `tools/architecture_report.py`: параметры генерации архитектурного отчета.
- `validation/README.md`: команды для `extract_gz_x500_model_spec.py` и
  `determinism_report.py`.
- `security_agent/app.py`, `security_agent/collector.py`,
  `security_agent/responder.py`, `security_agent/state_guard.py`: импорт
  `mavsdk`.
- `requirements.txt`: Python-зависимость `mavsdk==3.15.3`.
- `Makefile`: команды `test`, `validate-readme`, `protection-doc`,
  `verify-smoke-logs`, `validate-encryption`.
- `tools/encrypted_mavlink_datagram.py`: упаковка и распаковка encrypted и
  authenticated encrypted MAVLink datagram для gateway encryption mode.
- `tools/verify_audit_log.py`: проверка SHA-256 hash-chain в JSONL audit-логах.
- `.github/workflows/ci.yml`: CI-проверка unit-тестов и документированных команд.
- `SECURITY.md`: политика безопасности и известные ограничения.
- `CONTRIBUTING.md`: правила подготовки изменений и проверок.
- `.gitignore`: исключение `.venv/`, `logs/`, кэшей и IDE-служебных файлов.
