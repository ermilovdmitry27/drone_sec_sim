# Анализ методов защиты в проекте

Документ фиксирует только те методы защиты, которые подтверждаются файлами
проекта. Если метод не подтверждается кодом или конфигурацией, это указано
явно.

## 1. Системы обнаружения атак

В проекте реализована правиловая система обнаружения атак и аномалий
`ThreatDetector`. Она получает события телеметрии, управляющих MAVLink-команд и
метрик канала, после чего возвращает список `SecurityEvent`.

Источники: `security_agent/detector.py:18-43`,
`security_agent/app.py:78-90`.

### 1.1. Обнаружение аномалий телеметрии

`ThreatDetector` анализирует следующие события телеметрии:

- частую смену режима полета, если аппарат вооружен;
- частую смену состояния arm/disarm;
- резкий скачок координат или высоты;
- деградацию GPS по `fix_type` и числу спутников;
- потерю доверия к навигационному состоянию PX4;
- критически низкий заряд батареи в активном полете.

Источники: `security_agent/detector.py:25-37`,
`security_agent/detector.py:45-70`,
`security_agent/detector.py:72-95`,
`security_agent/detector.py:97-139`,
`security_agent/detector.py:141-166`,
`security_agent/detector.py:168-193`,
`security_agent/detector.py:195-218`.

### 1.2. Обнаружение подозрительных MAVLink-команд

Для управляющего потока реализовано обнаружение:

- всплеска управляющих MAVLink-команд;
- попыток изменения параметров PX4;
- попыток изменения миссии PX4;
- попыток `SERIAL_CONTROL`, включая доступ к shell-устройству;
- серии arm/disarm-команд на уровне MAVLink-потока;
- факта блокировки команды gateway-компонентом.

Источники: `security_agent/detector.py:226-346`.

### 1.3. Обнаружение проблем канала связи

Для канала связи реализованы проверки:

- повышенного уровня потерь MAVLink-сообщений;
- простоя или задержки MAVLink-канала.

Источники: `security_agent/detector.py:348-389`.

### 1.4. Контроль состояния PX4

Помимо `ThreatDetector`, в проекте реализован `StateGuard`. Он периодически
получает параметры PX4 и текущую миссию. Если параметры изменились, создается
событие `px4_param_changed`. Если изменился хэш миссии, создается событие
`mission_plan_changed`.

Источники: `security_agent/state_guard.py:26-37`,
`security_agent/state_guard.py:38-77`,
`security_agent/state_guard.py:79-106`,
`security_agent/state_guard.py:108-119`,
`security_agent/state_guard.py:121-144`.

Критичные параметры перечислены в `SecuritySettings`: `COM_OBL_RC_ACT`,
`NAV_RCL_ACT`, `GF_ACTION`, `GF_MAX_HOR_DIST`, `RTL_RETURN_ALT`,
`MPC_XY_CRUISE`.

Источники: `security_agent/config.py:32-44`.

## 2. Межсетевые экраны и фильтрация трафика

Классического сетевого firewall на уровне ОС, например правил `iptables`,
`nftables` или системного packet filter, в репозитории не обнаружено. Я не могу
подтвердить наличие такого межсетевого экрана по файлам проекта.

Вместо этого в проекте реализован прикладной MAVLink gateway/proxy, который
работает как специализированный межсетевой экран уровня протокола MAVLink:
принимает UDP-потоки от PX4, клиентов API и QGroundControl, разбирает MAVLink
frames, формирует события команд и может блокировать отдельные категории
управляющего трафика.

Источники: `security_agent/gateway.py:82-127`,
`security_agent/gateway.py:147-169`,
`security_agent/gateway.py:214-237`,
`security_agent/gateway.py:261-295`.

### 2.1. Что gateway умеет распознавать

Gateway распознает MAVLink-сообщения, связанные с:

- изменением параметров: `PARAM_SET`;
- изменением миссии: `MISSION_WRITE_PARTIAL_LIST`, `MISSION_ITEM`,
  `MISSION_COUNT`, `MISSION_CLEAR_ALL`, `MISSION_ITEM_INT`;
- командами: `COMMAND_INT`, `COMMAND_LONG`;
- сменой режима: `SET_MODE`;
- последовательным интерфейсом: `SERIAL_CONTROL`.

Источники: `security_agent/gateway.py:14-29`,
`security_agent/gateway.py:323-396`.

### 2.2. Что gateway умеет блокировать

Gateway может блокировать:

- запись параметров;
- запись миссии;
- `SERIAL_CONTROL`;
- команды с идентификаторами из `blocked_command_ids`.

Источники: `security_agent/gateway.py:311-321`.

В `monitor.py` включение `--gateway-enforce` активирует блокировку записи
параметров, записи миссии и `SERIAL_CONTROL`. Отдельный флаг
`--gateway-block-serial-control` включает блокировку только `SERIAL_CONTROL`.

Источники: `monitor.py:24-68`, `monitor.py:89-98`.

В текущем `sim_stack.json` gateway включен, `gateway_enforce` включен,
`gateway_block_serial_control` включен. Следовательно, по текущей конфигурации
подтверждается включенный gateway и блокировка записи параметров, записи миссии
и `SERIAL_CONTROL`.

Источники: `sim_stack.json:18-27`, `monitor.py:89-98`.

Gateway также поддерживает runtime-блокировку конкретного источника команд и
режим lockdown. `Responder` выполняет действия `block_command_source` и
`lockdown` через общий `GatewayControl`, а gateway маркирует такие datagram как
заблокированные политикой доступа. Дополнительно `authorized_client_hosts`
ограничивает допустимые IP-адреса MAVLink-клиентов; по умолчанию разрешен
`127.0.0.1`.

Источники: `security_agent/config.py:6-37`, `security_agent/gateway.py:82-91`,
`security_agent/gateway.py:220-251`, `security_agent/gateway.py:276-330`,
`security_agent/gateway.py:346-369`, `security_agent/responder.py:9-64`,
`security_agent/app.py:45-59`,
`sim_stack.json:23-28`, `monitor.py:64-108`.

Для клиентских MAVLink datagram реализован опциональный AES-GCM wrapper. Формат
зашифрованной datagram: magic `DSEC1`, nonce длиной 12 байт и ciphertext/tag
AES-GCM. Gateway расшифровывает входящие клиентские datagram перед разбором
MAVLink frames и шифрует обратный поток для клиентов, которые уже использовали
encrypted wrapper. Режим `require_encrypted_clients` отклоняет нешифрованные
клиентские datagram. По умолчанию он выключен, потому что штатный QGroundControl
и обычный MAVSDK UDP-клиент не используют этот wrapper.

Источники: `security_agent/gateway.py:1-23`, `security_agent/gateway.py:82-127`,
`security_agent/gateway.py:240-270`, `security_agent/gateway.py:405-446`,
`monitor.py:76-84`, `launch_stack.py:127-166`, `sim_stack.json:27-29`,
`tools/encrypted_mavlink_datagram.py:13-76`.

### 2.3. Аутентификация операторов на границе gateway

Для клиентских MAVLink datagram реализован authenticated encrypted wrapper
`DSEC2`. Внутри AES-GCM-конверта клиент передает JSON-envelope с
`operator_id`, `token` и `payload_b64`. Gateway сверяет SHA-256 hash токена с
`operator_token_hashes` и сохраняет привязку authenticated endpoint к
`operator_id`. Если включен `require_operator_auth`, gateway отклоняет raw
datagram и обычные `DSEC1` datagram без операторской аутентификации.

Источники: `security_agent/config.py:39-42`,
`security_agent/gateway.py:21`, `security_agent/gateway.py:248-263`,
`security_agent/gateway.py:405-476`, `monitor.py:86-125`,
`launch_stack.py:129-172`, `sim_stack.json:30-31`,
`tools/encrypted_mavlink_datagram.py:14-76`,
`tests/test_gateway.py:100-147`.

Ограничение: по файлам проекта подтверждается gateway-level аутентификация
оператора для клиентов, которые используют `DSEC2`. Я не могу подтвердить по
файлам проекта наличие отдельного web-интерфейса пользователей, ротации токенов
или native-интеграции логина оператора в QGroundControl.

## 3. Реагирование на инциденты

В проекте реализован `RiskEngine`, который переводит `SecurityEvent` в
`RiskAssessment`. Базовый риск зависит от severity: `LOW`, `MEDIUM`, `HIGH`,
`CRITICAL`; затем риск повышается, если аппарат вооружен или находится в
воздушной фазе.

Источники: `security_agent/risk_engine.py:6-38`,
`security_agent/risk_engine.py:40-55`.

`RiskEngine` рекомендует действия:

- `log_only` для низкого риска;
- `alert_operator` для среднего риска;
- `hold_position` для высокого риска в воздухе;
- `block_command_source` для высокого риска не в воздухе;
- `return_or_land` для критического риска в воздухе;
- `lockdown` для критического риска не в воздухе.

Источники: `security_agent/risk_engine.py:57-66`.

`Responder` выполняет только активные команды `hold_position` и
`return_or_land`. Для `return_or_land` он вызывает `return_to_launch()` в фазах
`MISSION`, `AIRBORNE`, `RETURN`, иначе вызывает `land()`. Действия
`log_only`, `alert_operator`, `block_command_source` и `lockdown` в текущем
коде не приводят к выполнению команды через MAVSDK.

Источники: `security_agent/responder.py:13-34`.

Активное реагирование зависит от флага `active_response`: если он выключен,
`Responder` работает в dry-run-режиме. В `SecurityMonitorApp` dry-run задается
как `not active_response`. В текущем `sim_stack.json` `active_response` равно
`true`.

Источники: `security_agent/app.py:26-39`, `security_agent/app.py:52-57`,
`security_agent/responder.py:8-24`, `sim_stack.json:25`.

## 4. Аудит и журналирование

В проекте реализовано журналирование:

- телеметрии в `telemetry.jsonl`;
- событий безопасности и оценок риска в `security_events.jsonl`;
- событий MAVLink-команд и метрик канала в `protocol_events.jsonl`;
- событий покрытия угроз в `threat_coverage.jsonl`.

Источники: `security_agent/audit.py:21-38`,
`security_agent/audit.py:40-68`,
`security_agent/app.py:78-99`.

Каждая запись audit-логов получает `audit_hash` и `audit_prev_hash`. Эти поля
формируют SHA-256 hash-chain внутри каждого JSONL-файла. Такой механизм
позволяет выявлять изменение или удаление уже записанных событий при последующей
проверке журнала. Для проверки добавлен инструмент `tools/verify_audit_log.py`.

Источники: `security_agent/audit.py:60-87`, `tools/verify_audit_log.py:1-72`.

Также реализован опциональный SIEM HTTP export: если задан `siem_url`, audit
события отправляются HTTP POST-запросами во внешний endpoint. Если `siem_url`
пустой, SIEM-отправка не выполняется.

Источники: `security_agent/audit.py:89-105`, `monitor.py:64-68`,
`monitor.py:101-108`, `launch_stack.py:122-137`, `sim_stack.json:25-27`.

## 5. Покрытие методов защиты по классам

| Класс защиты | Реализация в проекте | Статус |
| --- | --- | --- |
| IDS / система обнаружения атак | `ThreatDetector`, `StateGuard`, анализ телеметрии, MAVLink-команд, миссий, параметров и link metrics | Реализовано |
| Межсетевой экран | Классического firewall ОС в проекте нет; есть MAVLink gateway/proxy с фильтрацией команд | Реализовано на прикладном уровне |
| IPS / предотвращение атак | По умолчанию включена блокировка `param_write`, `mission_write`, `serial_control`; также поддерживаются `blocked_command_ids` | Реализовано |
| Реагирование | Risk-based рекомендации, `hold`, `return_to_launch`, `land`, `block_command_source`, `lockdown` при активном режиме | Реализовано |
| Аудит | JSONL-журналы телеметрии, команд, событий безопасности, оценок риска и покрытия угроз с SHA-256 hash-chain | Реализовано |
| Контроль целостности конфигурации | Сравнение снимков параметров PX4 и хэша миссии | Реализовано |
| Авторизация источников MAVLink-клиентов | `authorized_client_hosts`, runtime-блокировка endpoint и gateway lockdown | Реализовано |
| Аутентификация операторов MAVLink-клиентов | `DSEC2` authenticated encrypted wrapper, `operator_token_hashes`, `require_operator_auth` | Реализовано на уровне gateway wrapper |
| Шифрование клиентского MAVLink-канала | Опциональный AES-GCM encrypted datagram wrapper на границе gateway | Реализовано частично |
| Управление доступом на уровне ОС/сети | Не подтверждается файлами проекта | Не подтверждено |
| SIEM/SOC-интеграция | Опциональная отправка audit-событий HTTP POST в `siem_url` | Реализовано частично |

## 6. Вывод

В текущем проекте основной защитный контур состоит из четырех компонентов:

1. `ThreatDetector` обнаруживает аномалии телеметрии, подозрительные команды и
   проблемы канала.
2. `StateGuard` контролирует изменения параметров PX4 и миссии.
3. `MavlinkGateway` выполняет прикладную фильтрацию MAVLink-трафика и может
   блокировать опасные категории сообщений.
4. `RiskEngine` и `Responder` переводят событие безопасности в оценку риска и,
   при включенном активном режиме, могут отправлять PX4 команды удержания,
   возврата или посадки.

Источники: `security_agent/detector.py:18-43`,
`security_agent/state_guard.py:26-106`,
`security_agent/gateway.py:82-127`,
`security_agent/gateway.py:311-321`,
`security_agent/risk_engine.py:6-66`,
`security_agent/responder.py:13-34`,
`security_agent/app.py:43-99`.

Классический межсетевой экран уровня ОС по текущим файлам проекта не
подтверждается. Для MAVLink реализованы gateway-level AES-GCM wrapper
клиентских datagram и gateway-level операторская аутентификация через `DSEC2`,
но не подтверждается native-шифрование штатного QGroundControl/PX4
MAVLink-протокола. Для логов реализована криптографическая
hash-chain-проверяемость, но неизменяемое внешнее хранилище логов не
подтверждается.
