#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MTProto & SOCKS5 Proxy Collector v3.1

Изменения относительно v3.0:
  * Нормальное логирование (модуль logging) вместо немых `except: pass`.
  * Корректный разбор Fake-TLS (ee) секрета: домен берётся со смещения 16 байт
    ключа, а не с начала (в v3.0 в домен попадал мусор из ключа).
  * URL-декодирование секрета (tg:// ссылки часто содержат %2B/%2F/%3D).
  * Разбор секрета в bytes поддерживает hex, base64 и base64url.
  * Парсинг "голого" IP:port как SOCKS5 включается только для SOCKS-источников,
    чтобы не засорять список мусором из HTML-страниц.
  * Удалён мёртвый self-referencing источник.
  * Файлы результата приведены в соответствие с тем, что ожидает workflow.
"""

import argparse
import asyncio
import base64
import binascii
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import requests

try:
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError
    from telethon.network import ConnectionTcpMTProxyRandomizedIntermediate
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

# --------------------------------------------------------------------------- #
# Логирование
# --------------------------------------------------------------------------- #
log = logging.getLogger("collector")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )
    if not TELETHON_AVAILABLE:
        log.warning("⚠️ Telethon не установлен. Полная проверка недоступна: pip install telethon")
    # Telethon очень шумный на INFO — глушим до WARNING.
    logging.getLogger("telethon").setLevel(logging.WARNING)


# --------------------------------------------------------------------------- #
# Конфигурация
# --------------------------------------------------------------------------- #
API_ID = os.environ.get("MTPROXY_API_ID")
API_HASH = os.environ.get("MTPROXY_API_HASH")

SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-projects/main/proxies/mtproto.txt",
    "https://mtpro.xyz/api/?type=mtproto",
    "https://mtpro.xyz/api/?type=mtproto-ru",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.txt",
    "https://raw.githubusercontent.com/Freedom-Guard/Proxy/main/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/securemanager/MTPROTO/main/proxies.txt",
    "https://raw.githubusercontent.com/seriyps/mtproto_proxy/master/proxies.txt",
    "https://raw.githubusercontent.com/MTProto/MTProtoProxy/master/proxies/mtproto.txt",
    "https://raw.githubusercontent.com/mtProtoProxy/MTProxy-official/master/proxies.txt",
]

SOCKS_SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
]

TIMEOUT = 2.0
RU_DOMAINS = [
    ".ru", "yandex", "vk.com", "mail.ru", "ok.ru", "dzen", "rutube", "sber",
    "tinkoff", "vtb", "gosuslugi", "nalog", "mos.ru", "ozon", "wildberries",
    "avito", "kinopoisk", "mts", "beeline",
]
BLOCKED = ["instagram", "facebook", "twitter", "bbc", "meduza", "linkedin", "torproject"]


# --------------------------------------------------------------------------- #
# Утилиты
# --------------------------------------------------------------------------- #
def _valid_port(p) -> bool:
    try:
        return 1 <= int(p) <= 65535
    except (TypeError, ValueError):
        return False


def _is_blocked(secret: str, domain) -> bool:
    return len(secret) < 16 or (domain is not None and any(b in domain for b in BLOCKED))


def _detect_region(domain) -> str:
    return "ru" if domain and any(m in domain for m in RU_DOMAINS) else "eu"


def _cleanup_session(host: str, port: int, delay: float = 0.5) -> None:
    time.sleep(delay)
    for f in Path(".").glob(f"test_{host.replace('.', '_')}_{port}*"):
        try:
            f.unlink()
        except OSError as e:
            log.debug("cleanup: не удалось удалить %s: %s", f, e)


def _prepare_secret(s: str) -> bytes:
    """
    Преобразует секрет (hex / base64 / base64url, возможно URL-кодированный) в bytes.
    Возвращает полные байты включая префикс dd/ee — telethon разбирает их сам.
    """
    s = unquote(s).strip()
    # Чистый hex?
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return bytes.fromhex(s)
    # base64url -> base64
    s_b64 = s.replace("-", "+").replace("_", "/")
    pad = len(s_b64) % 4
    if pad:
        s_b64 += "=" * (4 - pad)
    return base64.b64decode(s_b64)


def decode_domain(secret: str):
    """
    Извлекает SNI домен из Fake-TLS (ee) секрета.

    Формат: 'ee' (1 байт-маркер) + 16 байт ключа (32 hex) + домен (hex).
    Домен начинается со смещения 2 + 32 = 34 hex-символа — в v3.0 этот сдвиг
    отсутствовал, из-за чего в домен попадали байты ключа.
    """
    secret = unquote(secret).strip().lower()
    if not secret.startswith("ee"):
        return None
    domain_hex = secret[34:]
    if not domain_hex:
        return None
    try:
        raw = bytes.fromhex(domain_hex)
    except ValueError:
        log.debug("decode_domain: невалидный hex домена в секрете %.20s...", secret)
        return None
    try:
        domain = raw.decode("utf-8")
    except UnicodeDecodeError:
        domain = raw.decode("latin-1", errors="ignore")
    domain = "".join(ch for ch in domain if 32 <= ord(ch) <= 126).lower()
    return domain or None


# --------------------------------------------------------------------------- #
# Парсинг источников
# --------------------------------------------------------------------------- #
def get_proxies_from_text(text: str, allow_bare_ip: bool = False) -> set:
    """
    Извлекает прокси из произвольного текста.

    allow_bare_ip: если True, "голые" IP:port трактуются как SOCKS5.
                   Включать только для доверенных SOCKS-источников — иначе
                   HTML-страницы засоряют список ложными адресами.
    """
    proxies = set()

    # --- MTProto ---
    for h, p, s in re.findall(
        r"tg://proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)", text, re.I
    ):
        if _valid_port(p):
            proxies.add(("mtproto", h, int(p), s))
    for h, p, s in re.findall(
        r"t\.me/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)", text, re.I
    ):
        if _valid_port(p):
            proxies.add(("mtproto", h, int(p), s))
    for h, p, s in re.findall(r"([A-Za-z0-9\.-]+):(\d+):([A-Fa-f0-9]{16,})", text):
        if _valid_port(p):
            proxies.add(("mtproto", h, int(p), s))

    # --- SOCKS5 (явные ссылки — всегда) ---
    for h, p in re.findall(r"tg://socks\?server=([^&\s]+)&port=(\d+)", text, re.I):
        if _valid_port(p):
            proxies.add(("socks5", h, int(p), (None, None)))
    for u, pw, h, p in re.findall(
        r"socks5://(?:([^:@]+):([^@]+)@)?([A-Za-z0-9\.-]+):(\d+)", text, re.I
    ):
        if _valid_port(p):
            proxies.add(("socks5", h, int(p), (u or None, pw or None)))

    # --- SOCKS5 (голый IP:port — только для SOCKS-источников) ---
    if allow_bare_ip:
        mt_hosts = {(x[1], x[2]) for x in proxies if x[0] == "mtproto"}
        for h, p in re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", text):
            if _valid_port(p) and (h, int(p)) not in mt_hosts:
                proxies.add(("socks5", h, int(p), (None, None)))

    # --- JSON ---
    txt = text.strip()
    if txt.startswith("[") or txt.startswith("{"):
        try:
            data = json.loads(txt)
        except json.JSONDecodeError as e:
            log.debug("JSON parse failed: %s", e)
            data = None
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                if {"host", "port", "secret"} <= item.keys() and _valid_port(item["port"]):
                    proxies.add(("mtproto", item["host"], int(item["port"]), str(item["secret"])))
                elif "socks5" in str(item).lower() and ("ip" in item or "host" in item) and _valid_port(item.get("port")):
                    host = item.get("ip") or item.get("host")
                    proxies.add(("socks5", host, int(item["port"]), (None, None)))

    return proxies


def fetch_source(url: str, timeout: int = 15, retries: int = 3) -> str:
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.text
            log.debug("fetch %s: HTTP %s", url, r.status_code)
        except requests.RequestException as e:
            log.debug("fetch %s (попытка %d): %s", url, attempt + 1, e)
        time.sleep(0.5)
    return ""


# --------------------------------------------------------------------------- #
# Telegram-канал (опционально)
# --------------------------------------------------------------------------- #
async def fetch_proxies_from_channel(channel: str, limit: int = 50) -> set:
    if not (TELETHON_AVAILABLE and API_ID and API_HASH):
        return set()
    proxies = set()
    client = TelegramClient("channel_reader_session", API_ID, API_HASH)
    try:
        await client.start()
        entity = channel.lstrip("@")
        chan = await client.get_entity(entity)
        log.info("📡 Читаем канал @%s (последние %d)...", entity, limit)
        async for msg in client.iter_messages(chan, limit=limit):
            if msg.text:
                proxies.update(get_proxies_from_text(msg.text))
        log.info("  → Извлечено %d прокси", len(proxies))
    except FloodWaitError as e:
        log.warning("  ⏳ FloodWait %d сек", e.seconds)
        await asyncio.sleep(e.seconds)
    except Exception as e:  # noqa: BLE001 — внешний API, логируем явно
        log.warning("  ✗ Ошибка канала: %s", e)
    finally:
        await client.disconnect()
        for f in Path(".").glob("channel_reader_session*"):
            try:
                f.unlink()
            except OSError:
                pass
    return proxies


# --------------------------------------------------------------------------- #
# Проверка прокси
# --------------------------------------------------------------------------- #
def check_probe_resistance(host: str, port: int, expected_domain, timeout: float = 5.0) -> bool:
    """
    Грубая эвристика: домен маскировки реально отвечает по TLS как веб-сервер.
    Это НЕ доказывает устойчивость к DPI-пробам — лишь то, что SNI правдоподобен.
    """
    if not expected_domain:
        return False
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=expected_domain) as ssock:
                req = (
                    f"GET / HTTP/1.1\r\nHost: {expected_domain}\r\n"
                    f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                )
                ssock.sendall(req.encode())
                resp = ssock.recv(4096).decode(errors="ignore")
                return resp.startswith("HTTP/1.1") and ("Content-Length" in resp or "text/html" in resp)
    except (OSError, ssl.SSLError) as e:
        log.debug("probe %s:%s (%s): %s", host, port, expected_domain, e)
        return False


async def check_mtproto(p, timeout_sec: float = 10.0):
    _, host, port, secret = p
    domain = decode_domain(secret)
    if _is_blocked(secret, domain):
        return None
    try:
        secret_bytes = _prepare_secret(secret)
    except (ValueError, binascii.Error) as e:
        log.debug("secret parse %s:%s: %s", host, port, e)
        return None

    client = TelegramClient(
        f"test_{host.replace('.', '_')}_{port}", API_ID, API_HASH,
        connection=ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=(host, int(port), secret_bytes), timeout=timeout_sec,
    )
    try:
        start = time.time()
        await asyncio.wait_for(client.connect(), timeout=timeout_sec)
        await asyncio.wait_for(client.get_config(), timeout=timeout_sec)
        ping = round(time.time() - start, 3)
        probe = check_probe_resistance(host, port, domain) if domain else False
        return {
            "type": "mtproto", "host": host, "port": port, "secret": secret,
            "link": f"tg://proxy?server={host}&port={port}&secret={secret}",
            "ping": ping, "region": _detect_region(domain), "domain": domain or "",
            "method": "Telethon_OK", "probe_resistant": probe,
        }
    except (asyncio.TimeoutError, OSError, ConnectionError) as e:
        log.debug("mtproto %s:%s не отвечает: %s", host, port, e)
        return None
    except Exception as e:  # noqa: BLE001 — telethon бросает разнородное
        log.debug("mtproto %s:%s ошибка: %s", host, port, e)
        return None
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        _cleanup_session(host, port)


async def check_socks5(p, timeout_sec: float = 10.0):
    _, host, port, auth = p
    username, password = auth if auth else (None, None)
    proxy = (5, host, port, username, password)
    client = TelegramClient(
        f"test_{host.replace('.', '_')}_{port}", API_ID, API_HASH,
        connection=ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=proxy, timeout=timeout_sec,
    )
    try:
        start = time.time()
        await asyncio.wait_for(client.connect(), timeout=timeout_sec)
        await asyncio.wait_for(client.get_config(), timeout=timeout_sec)
        ping = round(time.time() - start, 3)
        return {
            "type": "socks5", "host": host, "port": port,
            "link": f"tg://socks?server={host}&port={port}",
            "ping": ping, "region": "eu", "domain": "",
            "method": "Telethon_SOCKS5", "probe_resistant": False,
        }
    except (asyncio.TimeoutError, OSError, ConnectionError) as e:
        log.debug("socks5 %s:%s не отвечает: %s", host, port, e)
        return None
    except Exception as e:  # noqa: BLE001
        log.debug("socks5 %s:%s ошибка: %s", host, port, e)
        return None
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        _cleanup_session(host, port)


def check_proxy_tcp(p):
    """
    Лёгкая проверка: только TCP-connect (порт открыт).
    ВНИМАНИЕ: для MTProto это НЕ подтверждает корректность секрета —
    лишь доступность порта. Полная проверка требует Telethon + API-ключей.
    """
    typ, host, port, extra = p
    if typ == "mtproto":
        secret = extra
        domain = decode_domain(secret)
        if _is_blocked(secret, domain):
            return None
        link = f"tg://proxy?server={host}&port={port}&secret={secret}"
        region = _detect_region(domain)
        domain_str = domain or ""
    else:
        link = f"tg://socks?server={host}&port={port}"
        region = "eu"
        domain_str = ""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            start = time.time()
            s.connect((host, port))
            ping = round(time.time() - start, 3)
        return {
            "type": typ, "host": host, "port": port,
            "secret": extra if typ == "mtproto" else None,
            "link": link, "ping": ping, "region": region, "domain": domain_str,
            "method": "TCP_OK", "probe_resistant": False,
        }
    except OSError as e:
        log.debug("tcp %s:%s закрыт: %s", host, port, e)
        return None


# --------------------------------------------------------------------------- #
# Постобработка и вывод
# --------------------------------------------------------------------------- #
def deduplicate_and_sort(proxies):
    seen = set()
    unique = []
    for p in proxies:
        key = (p["type"], p["host"], p["port"], p.get("secret"))
        if key not in seen:
            seen.add(key)
            unique.append(p)

    def rank(x):
        if x["type"] == "mtproto" and x.get("probe_resistant"):
            return 0
        if x["type"] == "mtproto":
            return 1
        return 2

    unique.sort(key=lambda x: (rank(x), x["ping"]))
    return unique


def make_socks5_link(host, port):
    return f"tg://socks?server={host}&port={port}"


def load_local_proxies(file_path):
    proxies = set()
    if not os.path.isfile(file_path):
        log.warning("✗ Файл не найден: %s", file_path)
        return proxies
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            proxies = get_proxies_from_text(f.read())
        log.info("✓ Загружено %d прокси из %s", len(proxies), file_path)
    except OSError as e:
        log.warning("✗ Ошибка чтения %s: %s", file_path, e)
    return proxies


def _write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# --------------------------------------------------------------------------- #
# Основной поток
# --------------------------------------------------------------------------- #
async def main_async(args):
    global TIMEOUT, API_ID, API_HASH
    TIMEOUT = args.timeout
    if args.api_id:
        API_ID = args.api_id
    if args.api_hash:
        API_HASH = args.api_hash

    start = time.time()
    log.info("🚀 MTProxy Collector v3.1")
    log.info("=" * 48)
    os.makedirs(args.output_dir, exist_ok=True)

    all_raw = set()

    log.info("\n📥 Сбор MTProto...")
    for url in SOURCES:
        name = (url.split("/")[-1] or url.split("/")[-2])[:42]
        text = fetch_source(url)
        if text:
            ext = get_proxies_from_text(text)
            cnt = sum(1 for x in ext if x[0] == "mtproto")
            all_raw.update(ext)
            log.info("  ✓ %-42s +%d MTProto", name, cnt)
        else:
            log.info("  ✗ %-42s недоступен", name)

    log.info("\n📥 Сбор SOCKS5...")
    for url in SOCKS_SOURCES:
        name = (url.split("/")[-1] or url.split("/")[-2])[:42]
        text = fetch_source(url)
        if text:
            ext = get_proxies_from_text(text, allow_bare_ip=True)
            cnt = sum(1 for x in ext if x[0] == "socks5")
            all_raw.update(ext)
            log.info("  ✓ %-42s +%d SOCKS5", name, cnt)
        else:
            log.info("  ✗ %-42s недоступен", name)

    if args.manual:
        all_raw.update(load_local_proxies(args.manual))
    if args.channel:
        all_raw.update(await fetch_proxies_from_channel(args.channel, args.channel_limit))

    log.info("\n🧩 Уникальных прокси всего: %d", len(all_raw))
    if not all_raw:
        log.warning("\n⚠️ Нет прокси. Завершение.")
        return

    log.info("\n⚡ Проверка %d прокси...\n", len(all_raw))
    valid = []
    checked = 0
    total = len(all_raw)
    use_telethon = TELETHON_AVAILABLE and API_ID and API_HASH

    if use_telethon:
        log.info("🔥 Режим: Telethon (полная проверка)\n")
        sem = asyncio.Semaphore(args.workers)

        async def check_one(p):
            async with sem:
                if p[0] == "mtproto":
                    return await check_mtproto(p, args.timeout)
                return await check_socks5(p, args.timeout)

        tasks = [asyncio.create_task(check_one(p)) for p in all_raw]
        for task in asyncio.as_completed(tasks):
            res = await task
            checked += 1
            if res:
                valid.append(res)
            if checked % 100 == 0 or checked == total:
                log.info("  [%d/%d] %.0f%% | найдено: %d", checked, total, checked / total * 100, len(valid))
    else:
        log.info("📡 Режим: TCP ping (только доступность порта)\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(check_proxy_tcp, p): p for p in all_raw}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                checked += 1
                if res:
                    valid.append(res)
                if checked % 100 == 0 or checked == total:
                    log.info("  [%d/%d] %.0f%% | найдено: %d", checked, total, checked / total * 100, len(valid))

    if not valid:
        log.warning("\n⚠️ Рабочих прокси не найдено.")
        return

    valid = deduplicate_and_sort(valid)
    mtproto_ru = [x for x in valid if x["type"] == "mtproto" and x["region"] == "ru"]
    mtproto_eu = [x for x in valid if x["type"] == "mtproto" and x["region"] == "eu"]
    socks5 = [x for x in valid if x["type"] == "socks5"]
    top = args.top if args.top > 0 else None
    utc = datetime.now(timezone.utc)
    od = args.output_dir

    log.info("\n💾 Сохранение в %s/...", od)
    _write(f"{od}/proxy_ru_verified.txt",
           f"# MTProto RU ({len(mtproto_ru[:top])})\n# Updated: {utc}\n\n"
           + "\n".join(x["link"] for x in mtproto_ru[:top]))
    _write(f"{od}/proxy_eu_verified.txt",
           f"# MTProto EU ({len(mtproto_eu[:top])})\n# Updated: {utc}\n\n"
           + "\n".join(x["link"] for x in mtproto_eu[:top]))
    _write(f"{od}/socks5_proxies.txt",
           f"# SOCKS5 ({len(socks5[:top])})\n# Updated: {utc}\n\n"
           + "\n".join(make_socks5_link(x["host"], x["port"]) for x in socks5[:top]))
    # all_verified теперь и в .txt (его ждёт workflow), и в .json
    _write(f"{od}/proxy_all_verified.txt",
           f"# All MTProto ({len((mtproto_ru + mtproto_eu)[:top])})\n# Updated: {utc}\n\n"
           + "\n".join(x["link"] for x in (mtproto_ru + mtproto_eu)[:top]))
    with open(f"{od}/proxy_all_verified.json", "w", encoding="utf-8") as f:
        json.dump(valid[:top], f, indent=2, ensure_ascii=False)

    # Корневые файлы
    _write("proxy_ru.txt", "\n".join(x["link"] for x in mtproto_ru[:top]))
    _write("proxy_eu.txt", "\n".join(x["link"] for x in mtproto_eu[:top]))
    _write("proxy_all.txt", "\n".join(x["link"] for x in (mtproto_ru + mtproto_eu)[:top]))
    _write("socks5.txt", "\n".join(make_socks5_link(x["host"], x["port"]) for x in socks5[:top]))

    elapsed = round(time.time() - start, 1)
    log.info("=" * 48)
    log.info("✅ MTProto RU: %d  EU: %d  SOCKS5: %d", len(mtproto_ru), len(mtproto_eu), len(socks5))
    if mtproto_ru:
        log.info("🏆 Лучший RU: %s:%s (%ss)", mtproto_ru[0]["host"], mtproto_ru[0]["port"], mtproto_ru[0]["ping"])
    if mtproto_eu:
        log.info("🏆 Лучший EU: %s:%s (%ss)", mtproto_eu[0]["host"], mtproto_eu[0]["port"], mtproto_eu[0]["ping"])
    if socks5:
        log.info("🏆 Лучший SOCKS5: %s:%s (%ss)", socks5[0]["host"], socks5[0]["port"], socks5[0]["ping"])
    log.info("⏱️ Время: %ss", elapsed)
    log.info("=" * 48)


def main():
    p = argparse.ArgumentParser(description="MTProto & SOCKS5 Proxy Collector v3.1")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--top", type=int, default=0, help="0 = без ограничения")
    p.add_argument("--output-dir", default="verified")
    p.add_argument("--manual", help="Локальный файл с прокси")
    p.add_argument("--channel", help="Telegram-канал для парсинга")
    p.add_argument("--channel-limit", type=int, default=50)
    p.add_argument("--api-id", type=int)
    p.add_argument("--api-hash")
    p.add_argument("-v", "--verbose", action="store_true", help="Подробный лог (DEBUG)")
    args = p.parse_args()

    _setup_logging(args.verbose)

    if TELETHON_AVAILABLE and not (args.api_id or API_ID) and not (args.api_hash or API_HASH):
        log.warning("⚠️ Без --api-id/--api-hash работает только TCP-проверка (порт открыт), "
                    "без подтверждения секрета.")

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
