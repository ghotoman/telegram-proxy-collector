# 🛡️ Telegram Proxy Collector: Anti‑Censorship Edition

[![oosmetrics — Топ‑5 в категории Crypto](https://api.oosmetrics.com/api/v1/badge/achievement/21322b63-7982-4e81-99f7-ada7354f9c21.svg)](https://oosmetrics.com/repo/kort0881/telegram-proxy-collector)

**Умный комбайн** для сбора, анализа и отбора **MTProto** и **SOCKS5** прокси.  
В отличие от обычных парсеров, этот скрипт **глубоко анализирует** `Secret` каждого MTProto‑прокси, извлекает **домен‑маску** (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon, Microsoft и др.) и проверяет **устойчивость к активному DPI** (Probe Resistance).  
Это особенно важно в условиях жёстких блокировок, где **маскировка под легитимный HTTPS** или использование SOCKS5 может быть разницей между работой и полной недоступностью.

👉 [GitHub — Telegram Proxy Collector](https://github.com/kort0881/telegram-proxy-collector)

---

## 🛠️ Community Tools: утилиты от пользователей

| Инструмент | Описание | Автор |
| --- | --- | --- |
| [Parser‑telegram‑proxies](https://github.com/ComradeBingo/Parser-telegram-proxies-list/) | Удобная Windows‑утилита для парсинга и проверки MTProto‑прокси с **отображением пинга в реальном времени**. Обновлённая версия исправляет периодические блокировки запросов к TXT‑файлам на GitHub за счёт использования HTTP‑запросов вместо прямого чтения. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑Telegram‑Android](https://github.com/ComradeBingo/Proxy-Telegram-Android) | Приложение для Android, которое **парсит прокси‑списки**, проверяет их доступность и показывает пинг серверов. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑telegram‑windows](https://github.com/ComradeBingo/Proxy-telegram-windows) | Парсер прокси‑серверов для Telegram на Windows. Обновлён до версии **1.2**: переработан GUI, добавлено меню «Справка», улучшена стабильность и удобство использования. | [ComradeBingo](https://github.com/ComradeBingo) |

---

## 🔥 **Актуальные списки** (обновляются автоматически **каждые 4 часа**)

Скрипт **каждые 4 часа** запускается через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions), **собирает** свежие прокси из открытых источников, **фильтрует**, **проверяет** и **обновляет** списки.  
Итоговые списки пишутся одновременно в корень репозитория (для прямых ссылок) и в папку `verified/` (подробные версии с заголовками и JSON) — поэтому **ссылки ниже всегда ведут на свежие списки**.

📦 **Прямые ссылки** для вставки в Telegram или свои программы:

| Регион / Тип | Список | Примечание |
| --- | --- | --- |
| 🇷🇺 RU‑сегмент (MTProto) | [proxy_ru.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt) | Маскировка под **Yandex, VK, Mail.ru, Gosuslugi, Sber, Mos.ru** и др. Нацелен на **лучшую стабильность в РФ и Иране**. |
| 🇪🇺 EU / Global (MTProto) | [proxy_eu.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt) | Маскировка под **Google, Amazon, Microsoft, Cloudflare** и другие международные сервисы. Высокая скорость и стабильность, особенно вне РФ. |
| 🌍 Все MTProto прокси | [proxy_all.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt) | Полный микс всех проверенных MTProto‑серверов (RU + EU). |
| 🔒 **SOCKS5 прокси** | [socks5.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt) | Прокси протокола SOCKS5 (без маскировки, но часто сложнее блокируются). |

> ℹ️ **Что означает «проверенный».** Глубина проверки зависит от того, заданы ли в окружении `MTPROXY_API_ID` / `MTPROXY_API_HASH`:
> - **С ключами** (режим Telethon) — реальное подключение к Telegram API через прокси: подтверждается, что секрет валиден и прокси действительно работает.
> - **Без ключей** (режим TCP) — проверяется **только то, что порт открыт и отвечает**. Это *не* подтверждает корректность секрета MTProto и работоспособность как прокси — лишь доступность хоста.

---

## 📱 **Использование с телефона**

Если ты открыл репозиторий **с телефона** и не хочешь копировать прокси вручную:

1. Открой страницу:  
   [https://kort0881.github.io/telegram-proxy-collector/](https://kort0881.github.io/telegram-proxy-collector/)
2. На странице есть **три вкладки**:  
   - **MTProto RU** – прокси с маскировкой под российские сайты,  
   - **MTProto EU** – международная маскировка,  
   - **SOCKS5** – прокси без маскировки, но часто работающие там, где MTProto блокируется.
3. Нажми на любую кнопку – Telegram сам предложит подключиться.

---

## 🚀 **Как это работает?**

Скрипт **запускается каждые 4 часа** через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions) и последовательно проходит **пять главных этапов**:

### 1. Сбор (Harvesting)

- Скачивает «сырые» прокси из **двух категорий источников**:
  - **MTProto** (основные репозитории, API, TXT‑файлы)
  - **SOCKS5** (специализированные списки)
- Использует **агрессивный Regex‑парсинг** для извлечения ссылок из любого формата:
  - `tg://proxy?server=...&port=...&secret=...`
  - `tg://socks?server=...&port=...`
  - `t.me/proxy?...`
  - `host:port:secret`
  - `socks5://[user:pass@]host:port`
  - JSON‑объекты.
- «Голые» адреса вида `IP:port` трактуются как SOCKS5 **только для доверенных SOCKS‑источников**, чтобы случайные `IP:port` из HTML‑страниц не засоряли списки.

### 2. Декодирование (Deep Analysis)

- Расшифровывает **Fake‑TLS‑секреты** MTProto (начинаются на `ee...`).
- Извлекает **домен**, под который идёт маскировка трафика (например `yandex.ru`, `vk.com`, `google.com` и т.д.). Домен берётся из секрета **после 16‑байтного ключа** — корректно, без захвата байтов ключа.
- На основе домена **помечает** MTProto прокси как `ru` или `eu` (по набору ключевых слов).

### 3. Фильтрация (Smart Filter)

- ❌ **Blacklist:** прокси, маскирующиеся под **заведомо заблокированные ресурсы** (Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor и др.), **отбрасываются**.
- ✅ **RU‑маркер:** прокси, содержащие в домене `yandex`, `vk.com`, `mail.ru`, `ok.ru`, `sber`, `tinkoff`, `gosuslugi`, `ozon`, `wildberries`, `avito`, `kinopoisk` и др., помечаются как `ru`.
- ✅ **EU‑маркер:** остальные MTProto прокси считаются `eu`.

### 4. Проверка (Checking) — **включая Probe Resistance**

- Проверяет каждый прокси через **TCP‑сокет** (быстрый режим, только доступность порта) или через **Telethon** (полная проверка с подключением к Telegram API, если переданы `API_ID` и `API_HASH`).
- Для MTProto прокси с доменом (секрет `ee...`) запускается **Probe Resistance Test** — скрипт открывает TLS‑соединение к домену‑маске и отправляет обычный HTTPS‑запрос `GET /`. Если в ответ приходит правдоподобная HTML‑страница, прокси получает флаг `probe_resistant: true`.
- ⚠️ **Важно:** это **эвристика**, а не гарантия. Тест подтверждает, что SNI‑домен правдоподобен и сам по себе отвечает как веб‑сервер, но **не** проверяет поведение прокси под реальным активным зондированием DPI.
- SOCKS5 прокси проверяются только на возможность подключения к Telegram API (без маскировки).
- Результат сохраняется в `verified/proxy_all_verified.json` с полями `probe_resistant` и `type`.

### 5. Сборка итоговых списков

- Все прокси **сортируются по приоритету**:
  1. MTProto с `probe_resistant: true` (самые живучие)
  2. Обычные MTProto
  3. SOCKS5
- Внутри каждой группы – по возрастанию пинга.
- MTProto прокси разделяются на **RU** и **EU**.
- SOCKS5 прокси выносятся в отдельный файл `socks5.txt`.

---

## 📁 **Итоговые файлы**

После каждого запуска вы получите:

- **Корень репозитория** (удобно для прямых ссылок):
  - `proxy_ru.txt`, `proxy_eu.txt`, `proxy_all.txt` — MTProto `tg://proxy?...`
  - `socks5.txt` — SOCKS5 `tg://socks?...`
- **Папка `verified/`** (подробные версии):
  - `proxy_ru_verified.txt`, `proxy_eu_verified.txt`, `proxy_all_verified.txt` — с заголовками и статистикой.
  - `socks5_proxies.txt` — SOCKS5 с комментариями.
  - `proxy_all_verified.json` — полный JSON с полями: `type`, `host`, `port`, `ping`, `region`, `domain`, `method`, `probe_resistant`.

---

## 🔗 **Мои проекты**

| Проект | Описание | Ссылка |
| --- | --- | --- |
| [VPN KEY VLESS](https://t.me/vlesstrojan) | Основной канал с конфигами, инструкциями и новостями по VLESS‑конфигам и прокси‑сети. | [Telegram](https://t.me/vlesstrojan) |
| [KiberSos New](https://t.me/kibersosnew) | Резервный канал для связи, обновлений и техподдержки. | [Telegram](https://t.me/kibersosnew) |
| [VlessBots](https://t.me/vlessbots_bot) | Бот для **автоматической выдачи ключей** и прокси‑ссылок по запросу. | [Bot](https://t.me/vlessbots_bot) |
| [Internet Access](https://kort0881.github.io/internet-access-site/) | Сайт проекта с подробной документацией, FAQ и примерами использования. | [Website](https://kort0881.github.io/internet-access-site/) |
| [VPN Key Repo](https://github.com/kort0881/vpn-key-vless) | Репозиторий скриптов, конфигураций и утилит для работы с VLESS‑сервисами и прокси‑сетями. | [GitHub](https://github.com/kort0881/vpn-key-vless) |

---

## 🛠️ **Локальный запуск (для разработчиков)**

Если хочешь запустить сборщик **на своём ПК**, а не только на GitHub Actions:

```bash
# 1. Клонировать репозиторий
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить базовую проверку (только TCP‑пинг, без подтверждения секрета)
python main.py

# 4. Запустить полную проверку (Telethon, Probe Resistance и SOCKS5)
python main.py --api-id YOUR_API_ID --api-hash YOUR_API_HASH --top 200 --output-dir verified

# 5. Подробный лог (для отладки) и справка по аргументам
python main.py -v
python main.py --help
```

Для полной проверки (Telethon) необходимы `API_ID` и `API_HASH`. Их можно получить на [my.telegram.org](https://my.telegram.org).

---

## ⚠️ **Дисклеймер и безопасность**

- Этот репозиторий **не гарантирует** анонимность, невозможность слежки или защищённость от компрометации.
- Все прокси‑серверы предоставляются на условиях «как есть»; их качество и доступность зависят от внешних источников и могут меняться в любой момент.
- Прокси собираются из **открытых публичных списков**. Среди них могут быть случайно открытые или чужие серверы — оператор такого прокси технически способен видеть метаданные соединений. **SOCKS5 без TLS особенно не предназначен для передачи чувствительных данных.** Для приватности используйте сквозное шифрование (Telegram использует MTProto/TLS поверх прокси) и не доверяйте прокси больше, чем транспорту.
- Использование средств обхода блокировок регулируется законодательством конкретной страны. **Ответственность за соблюдение применимых законов лежит на пользователе.**
