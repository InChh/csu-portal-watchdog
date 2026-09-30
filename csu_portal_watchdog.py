#!/usr/bin/env python3
"""CSU campus portal monitor. Python 3.10+, Windows, no extra packages.

The scheduled task runs `once` every five minutes. Authentication is permitted
only after failed Internet probes and two explicit offline portal observations.
No redirects are followed, and portal requests use a fixed endpoint allowlist.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
import getpass
import gzip
import http.cookiejar
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


PORTAL = "https://portal.csu.edu.cn"
API = PORTAL + ":802/eportal/portal/"
LOGIN_URL = API + "login"
TASK_NAME = "CSU-Portal-Watchdog"
SCRIPT = Path(__file__).resolve()
STATE = SCRIPT.parent / "state"
CONFIG = STATE / "credentials.json"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
ALLOWED_PORTAL_URLS = frozenset((
    PORTAL + "/", PORTAL + "/drcom/chkstatus", PORTAL + "/a40.js",
    API + "page/loadConfig", LOGIN_URL,
))
PROBES = (
    ("http://www.msftconnecttest.com/connecttest.txt", b"Microsoft Connect Test"),
    ("https://www.baidu.com/robots.txt", b"User-agent:"),
)


class RequestError(Exception):
    """An intentionally URL-free error: login query strings contain secrets."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_jsonp(text: str) -> dict:
    text = text.lstrip("\ufeff").strip()
    if not text.startswith("{"):
        match = re.fullmatch(
            r"[A-Za-z_$][\w$]*\s*\(\s*(\{.*\})\s*\)\s*;?", text, re.S
        )
        if not match:
            raise RequestError("认证服务器返回了无法识别的数据")
        text = match.group(1)
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        raise RequestError("认证服务器返回了无效 JSON") from None
    if not isinstance(value, dict):
        raise RequestError("认证服务器数据格式不符")
    return value


class HttpClient:
    def __init__(self, timeout: float = 8):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def fetch(self, url: str) -> tuple[bytes, str]:
        request = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CSU-Watchdog/1.0",
            "Cache-Control": "no-cache", "Accept-Encoding": "gzip",
        })
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise RequestError("HTTP 状态异常")
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise RequestError("响应超过读取上限")
                charset = response.headers.get_content_charset() or "utf-8"
                if body.startswith(b"\x1f\x8b"):
                    body = gzip.decompress(body)
                return body, charset
        except urllib.error.HTTPError as exc:
            raise RequestError(f"HTTP {exc.code}（重定向不会被跟随）") from None
        except (urllib.error.URLError, OSError, ValueError, EOFError):
            raise RequestError("连接超时、网络不可达或 HTTPS 校验失败") from None

    def portal_text(self, url: str, params: dict | None = None) -> str:
        if url not in ALLOWED_PORTAL_URLS:
            raise RequestError("请求地址不在认证接口白名单内")
        if params:
            # Match the portal's encodeURIComponent encoding; no shell commands.
            url += "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        body, charset = self.fetch(url)
        try:
            return body.decode(charset)
        except (UnicodeError, LookupError):
            return body.decode("gbk", errors="replace")

    def portal_json(self, url: str, params: dict) -> dict:
        return parse_jsonp(self.portal_text(url, params))


def jsonp_params(data: dict | None = None) -> dict:
    return {**(data or {}), "callback": "csuWatchdog",
            "jsVersion": (data or {}).get("jsVersion", "4.1.3"),
            "v": secrets.randbelow(10000) + 500, "lang": "zh"}


def js_string(html: str, name: str, default: str = "") -> str:
    match = re.search(r"\b" + re.escape(name) + r"\s*=\s*(['\"])(.*?)\1", html)
    return match.group(2) if match else default


@dataclass
class Context:
    online: bool | None
    ip: str = ""
    mac: str = "000000000000"
    username: str = ""
    vlan: str = "1"


@dataclass
class Credentials:
    username: str
    password: str


class InternetProbe:
    def __init__(self, client: HttpClient):
        self.client = client

    def healthy(self) -> bool:
        # One validated response suffices; failure of a single site is not an outage.
        for url, expected in PROBES:
            try:
                body, _ = self.client.fetch(url)
                if url.startswith("http:"):
                    if body.strip() == expected:
                        return True
                elif body.lstrip().startswith(expected):
                    return True
            except RequestError:
                pass
        return False


class Portal:
    def __init__(self, client: HttpClient):
        self.client = client

    def context(self) -> Context:
        html, status = "", {}
        try:
            html = self.client.portal_text(PORTAL + "/")
        except RequestError:
            pass
        try:
            status = self.client.portal_json(PORTAL + "/drcom/chkstatus", jsonp_params())
        except RequestError:
            pass
        marker = re.search(r"<!--\s*Dr\.COMWebLoginID_([013])\.htm\s*-->", html)
        page_online = None if not marker else marker.group(1) in ("1", "3")
        result = str(status.get("result", ""))
        status_online = {"1": True, "0": False}.get(result)
        # Any positive online observation wins. Ambiguity never permits login.
        if page_online is True or status_online is True:
            online = True
        elif page_online is False and status_online is False:
            online = False
        else:
            online = None
        raw_ip = js_string(html, "v4ip") or status.get("v4ip") or status.get("ss5", "")
        try:
            ip = ipaddress.IPv4Address(raw_ip)
            valid_ip = str(ip) if not (ip.is_unspecified or ip.is_loopback) else ""
        except (ipaddress.AddressValueError, TypeError):
            valid_ip = ""
        raw_mac = js_string(html, "ss4") or status.get("ss4", "000000000000")
        mac = re.sub(r"[-:]", "", str(raw_mac)).upper()
        if not re.fullmatch(r"[0-9A-F]{12}", mac):
            mac = "000000000000"
        return Context(online, valid_ip, mac, str(status.get("uid", "")))

    def login_parameters(self, credentials: Credentials, ctx: Context) -> dict:
        if not ctx.ip:
            raise RequestError("未能从认证服务器取得当前终端 IPv4")
        b64 = lambda value: base64.b64encode(value.encode("ascii")).decode("ascii")
        query = jsonp_params({
            "program_index": "", "wlan_vlan_id": ctx.vlan,
            "wlan_user_ip": b64(ctx.ip), "wlan_user_ipv6": "",
            "wlan_user_ssid": "", "wlan_user_areaid": "", "wlan_ac_ip": "",
            "wlan_ap_mac": "000000000000", "gw_id": "000000000000",
        })
        info = self.client.portal_json(API + "page/loadConfig", query).get("data")
        if not isinstance(info, dict) or str(info.get("login_method")) != "1":
            raise RequestError("当前认证方式与已确认的 Portal 协议不一致")
        if str(info.get("en_md5", "0")) != "0" or str(info.get("password_cut", "0")) != "0":
            raise RequestError("认证页密码处理规则已改变，需要重新核对接口")
        script = self.client.portal_text(PORTAL + "/a40.js")
        version = re.search(r"\bjsVersion\s*=\s*(['\"])([\d.]+)\1", script)
        if not version:
            raise RequestError("未能取得认证页脚本版本")
        prefix = ""
        if str(info.get("account_prefix", "1")) == "1":
            prefix = ",b," if str(info.get("custom_perceive", "0")) == "1" else ",0,"
        suffix = str(info.get("account_suffix") or "")
        return jsonp_params({
            "login_method": "1", "user_account": prefix + credentials.username + suffix,
            "user_password": credentials.password, "wlan_user_ip": ctx.ip,
            "wlan_user_ipv6": "", "wlan_user_mac": ctx.mac,
            "wlan_ac_ip": "", "wlan_ac_name": "", "jsVersion": version.group(2),
            "terminal_type": "1",
        })

    def authenticate(self, parameters: dict) -> dict:
        return self.client.portal_json(LOGIN_URL, parameters)


def cycle(portal, probe, load, log, *, read_only=False, pause=time.sleep) -> str:
    if probe.healthy():
        log.info("网络正常，跳过认证。")
        return "healthy"
    pause(5)
    if probe.healthy():
        log.info("复测时网络已恢复，跳过认证。")
        return "healthy"
    ctx = portal.context()
    if ctx.online is True:
        log.warning("外网探测失败，但认证仍在线；保留当前登录，等待下次检查。")
        return "still_online"
    if ctx.online is not False:
        log.warning("无法明确确认认证离线；本轮不提交登录请求。")
        return "unknown"
    if read_only:
        log.info("外网不可用且认证离线；只读检查结束，可以在正常模式下尝试认证。")
        return "dry_run"
    try:
        credentials = load()
        parameters = portal.login_parameters(credentials, ctx)
    except FileNotFoundError:
        log.error("尚未配置账号密码，请先运行 setup.cmd。")
        return "no_credentials"
    except (RequestError, ValueError, OSError):
        log.error("读取凭据或认证参数失败，请检查配置；本轮不提交登录请求。")
        return "configuration_error"
    current = portal.context()
    if current.online is not False or current.ip != ctx.ip or current.mac != ctx.mac:
        log.info("提交前发现认证状态或终端地址发生变化，本轮停止认证。")
        return "state_changed"
    if probe.healthy():
        log.info("提交前网络已恢复，跳过认证。")
        return "healthy"
    log.info("确认当前终端离线，尝试一次 HTTPS Portal 登录。")
    reply = {}
    try:
        reply = portal.authenticate(parameters)
    except RequestError:
        log.warning("登录请求未得到有效响应，将独立复测网络。")
    pause(5)
    if probe.healthy():
        log.info("外网复测通过，网络已恢复。")
        return "recovered"
    accepted = str(reply.get("result")) in ("1", "ok")
    # Do not log raw responses, account names, passwords, or request URLs.
    log.warning("认证接口%s，外网仍未恢复；等待下个五分钟周期。",
                "报告成功" if accepted else "未确认登录成功")
    return "not_recovered"


def dpapi(data: bytes, *, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise ValueError("凭据存储需要 Windows DPAPI")

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        operation = crypt.CryptUnprotectData
        operation.argtypes = [ctypes.POINTER(Blob), ctypes.POINTER(wintypes.LPWSTR),
                             ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                             wintypes.DWORD, ctypes.POINTER(Blob)]
    else:
        operation = crypt.CryptProtectData
        operation.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob),
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(Blob)]
    operation.restype = wintypes.BOOL
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ValueError("Windows 凭据加密或解密失败，请在同一 Windows 用户下重新配置")
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel.LocalFree(ctypes.cast(target.pbData, ctypes.c_void_p))


def load_credentials() -> Credentials:
    value = json.loads(CONFIG.read_text(encoding="utf-8"))
    username = value["username"]
    password = dpapi(base64.b64decode(value["password_dpapi"], validate=True), decrypt=True)
    if not isinstance(username, str) or not username or not password:
        raise ValueError("凭据不完整")
    return Credentials(username, password.decode("utf-8"))


def configure(portal: Portal) -> None:
    ctx = portal.context()
    default = ctx.username if ctx.online is True else ""
    if CONFIG.exists():
        # Reconfiguration must work even if the old Windows user cannot decrypt
        # the previous password. Only use the non-secret account name as a hint.
        try:
            previous = json.loads(CONFIG.read_text(encoding="utf-8")).get("username", "")
            if isinstance(previous, str):
                default = previous
        except (OSError, ValueError, AttributeError):
            pass
    username = input(f"校园网账号{' [' + default + ']' if default else ''}：").strip() or default
    if not re.fullmatch(r"[A-Za-z0-9@_.-]{1,80}", username):
        raise ValueError("请输入有效的校园网账号")
    password = getpass.getpass("校园网密码（输入时不显示）：")
    confirm = getpass.getpass("再次输入密码：")
    if not password or password != confirm:
        raise ValueError("两次密码不一致或密码为空")
    encrypted = dpapi(password.encode("utf-8"))
    if dpapi(encrypted, decrypt=True).decode("utf-8") != password:
        raise ValueError("凭据存储自检失败")
    STATE.mkdir(exist_ok=True)
    value = {"username": username, "password_dpapi": base64.b64encode(encrypted).decode("ascii")}
    temporary = CONFIG.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(CONFIG)
    print("账号已配置，密码由当前 Windows 用户的 DPAPI 加密保存。")


def scheduled_task_xml(user_sid: str, pythonw: Path) -> bytes:
    ET.register_namespace("", TASK_NS)
    root = ET.Element("{" + TASK_NS + "}Task", {"version": "1.4"})

    def add(parent, tag, text=None, **attributes):
        child = ET.SubElement(parent, "{" + TASK_NS + "}" + tag, attributes)
        child.text = text
        return child

    registration = add(root, "RegistrationInfo")
    add(registration, "Description", "中南大学校园网：每五分钟探测；明确离线时才登录。")
    triggers = add(root, "Triggers")
    trigger = add(triggers, "TimeTrigger")
    repetition = add(trigger, "Repetition")
    add(repetition, "Interval", "PT5M")
    add(repetition, "StopAtDurationEnd", "false")
    start = datetime.now().astimezone() + timedelta(minutes=1)
    add(trigger, "StartBoundary", start.isoformat(timespec="seconds"))
    add(trigger, "Enabled", "true")
    logon = add(triggers, "LogonTrigger")
    add(logon, "Enabled", "true")
    add(logon, "UserId", user_sid)
    principal = add(add(root, "Principals"), "Principal", id="Author")
    add(principal, "UserId", user_sid)
    add(principal, "LogonType", "InteractiveToken")
    add(principal, "RunLevel", "LeastPrivilege")
    settings = add(root, "Settings")
    for key, value in (("MultipleInstancesPolicy", "IgnoreNew"),
                       ("DisallowStartIfOnBatteries", "false"),
                       ("StopIfGoingOnBatteries", "false"),
                       ("StartWhenAvailable", "true"), ("AllowStartOnDemand", "true"),
                       ("Enabled", "true"), ("Hidden", "true"),
                       ("ExecutionTimeLimit", "PT3M"), ("Priority", "7")):
        add(settings, key, value)
    action = add(add(root, "Actions", Context="Author"), "Exec")
    add(action, "Command", str(pythonw))
    add(action, "Arguments", subprocess.list2cmdline([str(SCRIPT), "once"]))
    add(action, "WorkingDirectory", str(SCRIPT.parent))
    # Native Task Scheduler uses UTF-16 XML, including its COM BSTR interface.
    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def windows_command(arguments: list[str]) -> subprocess.CompletedProcess:
    if os.name != "nt":
        raise ValueError("计划任务需要 Windows")
    return subprocess.run(arguments, capture_output=True, creationflags=0x08000000,
                          timeout=30, check=False)


def parse_task_xml(data: bytes) -> ET.Element:
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        # schtasks stdout can declare UTF-16 while emitting UTF-8/ANSI bytes.
        # A task file and the subprocess text output use different encodings.
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("mbcs")
        text = re.sub(r"^\s*<\?xml[^?]*\?>\s*", "", text)
        return ET.fromstring(text)


def install_task() -> None:
    load_credentials()  # Verify that this user can decrypt the configured password.
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        raise ValueError("找不到 pythonw.exe，请使用 Windows 原生 Python")
    who = windows_command(["whoami.exe", "/user", "/fo", "csv", "/nh"])
    rows = list(csv.reader(who.stdout.decode("utf-8", errors="replace").strip().splitlines()))
    if who.returncode or not rows or not re.fullmatch(r"S-1-[\d-]+", rows[-1][-1]):
        raise ValueError("无法取得当前 Windows 用户标识")
    existing = windows_command(["schtasks.exe", "/Query", "/TN", TASK_NAME, "/XML"])
    if existing.returncode == 0:
        try:
            tree = parse_task_xml(existing.stdout)
            old_args = tree.findtext(".//{" + TASK_NS + "}Arguments")
        except (ET.ParseError, UnicodeError, LookupError):
            raise ValueError("同名计划任务无法核对，请先在任务计划程序中检查") from None
        if old_args != subprocess.list2cmdline([str(SCRIPT), "once"]):
            raise ValueError("同名计划任务指向其他文件，本脚本不会覆盖它")
    xml_file = STATE / "scheduled-task.xml"
    xml_file.write_bytes(scheduled_task_xml(rows[-1][-1], pythonw))
    created = windows_command(["schtasks.exe", "/Create", "/TN", TASK_NAME,
                               "/XML", str(xml_file), "/F"])
    if created.returncode:
        raise ValueError("计划任务安装失败，请在任务计划程序中检查当前用户的创建权限")
    started = windows_command(["schtasks.exe", "/Run", "/TN", TASK_NAME])
    print(f"已启用计划任务 {TASK_NAME}：每五分钟检查，登录 Windows 时也检查。")
    print("首次检查已启动。" if started.returncode == 0 else "首次检查将在一分钟内启动。")
    print("运行日志：" + str(STATE / "watchdog.log"))


def make_logger() -> logging.Logger:
    STATE.mkdir(exist_ok=True)
    log = logging.getLogger("csu-watchdog")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = RotatingFileHandler(STATE / "watchdog.log", maxBytes=512 * 1024,
                                      backupCount=2, encoding="utf-8")
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    if sys.stdout is not None:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        log.addHandler(console)
    return log


def main() -> int:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup", help="在本机配置账号密码")
    setup.add_argument("--install", action="store_true", help="配置完成后启用五分钟计划任务")
    commands.add_parser("install", help="使用已有配置启用计划任务")
    commands.add_parser("disable", help="停止定时检查，保留校园网连接和登录")
    commands.add_parser("status", help="只读查看网络和认证状态")
    once = commands.add_parser("once", help="探测一次；必要时认证一次")
    once.add_argument("--dry-run", action="store_true", help="只读检查，不提交认证请求")
    args = parser.parse_args()
    log = make_logger()
    client = HttpClient()
    portal, probe = Portal(client), InternetProbe(client)
    try:
        if args.command == "setup":
            configure(portal)
            if args.install:
                install_task()
        elif args.command == "install":
            install_task()
        elif args.command == "disable":
            result = windows_command(["schtasks.exe", "/Change", "/TN", TASK_NAME, "/DISABLE"])
            if result.returncode:
                raise ValueError("停用失败，请在任务计划程序中检查该任务")
            print("定时检查已停用；当前校园网连接和认证保持原状。")
        elif args.command == "status":
            healthy = probe.healthy()
            ctx = portal.context()
            state = {True: "已登录", False: "明确离线", None: "状态不确定"}[ctx.online]
            log.info("外网：%s；校园网认证：%s；终端 IPv4：%s。",
                     "正常" if healthy else "探测失败", state, ctx.ip or "未知")
        else:
            # Windows byte-range locks prevent manual and scheduled overlap.
            if os.name != "nt":
                raise ValueError("请用 Windows 原生 Python 运行，不要在 WSL 中运行")
            import msvcrt
            with (STATE / "run.lock").open("a+b") as lock:
                if lock.seek(0, os.SEEK_END) == 0:
                    lock.write(b"0")
                    lock.flush()
                lock.seek(0)
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    log.info("已有检查正在执行，跳过重复运行。")
                    return 0
                try:
                    outcome = cycle(portal, probe, load_credentials, log, read_only=args.dry_run)
                finally:
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                return 0 if outcome in ("healthy", "recovered", "dry_run") else 1
        return 0
    except RequestError as error:
        log.error("操作未完成：%s", error)
        return 2
    except ValueError as error:
        # Our configuration/task errors contain no credentials or request URLs.
        # Decoder exceptions use the generic message instead of their payload.
        if isinstance(error, (UnicodeError, json.JSONDecodeError)):
            log.error("配置文件无法读取，请重新运行 setup.cmd。")
        else:
            log.error("操作未完成：%s", error)
        return 2
    except (OSError, KeyError, subprocess.TimeoutExpired):
        # Avoid printing exception text that might contain a login URL or secret.
        log.error("操作未完成：请检查网络、当前 Windows 用户或重新运行 setup.cmd。")
        return 2
    except (KeyboardInterrupt, EOFError):
        log.info("操作已取消。")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
