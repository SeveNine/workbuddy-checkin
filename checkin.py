#!/usr/bin/env python3
"""
WorkBuddy 每日签到脚本
支持本地运行和 GitHub Actions 云端定时运行。

新版 WorkBuddy (5.6.2+) 的 accessToken 是 AES-256-GCM 加密信封，
密钥不落盘、只驻留在客户端进程内存中。本地运行时，本脚本会调用本机
WorkBuddy 自带的 Electron 运行时，在隐藏子进程里解密（明文不出本机）。

云端 GitHub Actions 用的是从本机导出的明文 token（GitHub Secrets），
不需要、也无法在 runner 上解密。

用法：
    python checkin.py                 # 签到（本地/云端自动判断凭证来源）
    python checkin.py --export-token  # 仅本机：解密并导出明文 token，供粘贴到 GitHub Secrets
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

API_BASE = "https://www.codebuddy.cn"
CHECKIN_STATUS_URL = f"{API_BASE}/v2/billing/meter/checkin-status"
DAILY_CHECKIN_URL = f"{API_BASE}/v2/billing/meter/daily-checkin"
REQUEST_TIMEOUT = 20

_WIN_AUTH_FILE = (
    Path(os.environ.get("LOCALAPPDATA", ""))
    / "CodeBuddyExtension"
    / "Data/Public/auth/workbuddy-desktop.info"
)
_MAC_AUTH_FILE = (
    Path.home()
    / "Library/Application Support/CodeBuddyExtension"
    / "Data/Public/auth/workbuddy-desktop.info"
)
_CLOUD_CONFIG_FILE = Path(__file__).resolve().parent / "config.json"

# 解密助手：固定代码在命令行参数里，加密字段只走 stdin，密钥材料不出子进程。
# 仅支持 sym-v1 / suite 1 信封（与 WorkBuddy 客户端内部实现一致）。
_AUTH_HELPER_JS = r"""
'use strict';
const crypto = require('crypto');
const inputLimit = 65536;
const failure = reason => { throw {reason}; };
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
function base64(value, length) {
  if (typeof value !== 'string' || value.length > inputLimit) failure('INVALID_FORMAT');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || (length !== undefined && bytes.length !== length))
    failure('INVALID_FORMAT');
  return bytes;
}
function utf8(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) failure('INVALID_FORMAT');
  return text;
}
function decode(value) {
  if (!object(value) || Object.keys(value).sort().join(',') !== '$wbEncrypted,envelope' || value.$wbEncrypted !== 1)
    failure('UNSUPPORTED_ENVELOPE');
  let envelope;
  try { envelope = JSON.parse(utf8(base64(value.envelope))); }
  catch (e) { failure(e.reason || 'INVALID_FORMAT'); }
  if (!object(envelope) || !Number.isInteger(envelope.suite)) failure('INVALID_FORMAT');
  if (envelope.suite !== 1) failure('UNSUPPORTED_ENVELOPE');
  if (Object.keys(envelope).sort().join(',') !== 'authTag,ciphertext,keyId,nonce,suite' ||
      typeof envelope.keyId !== 'string' || !/^[0-9a-f]{16}$/.test(envelope.keyId)) failure('INVALID_FORMAT');
  return {keyId: envelope.keyId, nonce: base64(envelope.nonce, 12),
    tag: base64(envelope.authTag, 16), ciphertext: base64(envelope.ciphertext)};
}
function nativeStorage() {
  try {
    const storage = process._linkedBinding('electron_browser_workbuddy_storage');
    if (typeof storage.loggerGet !== 'function') failure('RUNTIME_UNAVAILABLE');
    return storage;
  } catch (_) { failure('RUNTIME_UNAVAILABLE'); }
}
function decrypt(envelope) {
  let payload;
  try { payload = JSON.parse(nativeStorage().loggerGet()); }
  catch (_) { failure('RUNTIME_UNAVAILABLE'); }
  let key;
  let plaintext;
  try {
    if (!object(payload) || payload.version !== 1) failure('RUNTIME_UNAVAILABLE');
    let secret;
    try { secret = base64(payload.atRestSecretKey, 32); }
    catch (_) { failure('RUNTIME_UNAVAILABLE'); }
    const empty = secret.every(b => b === 0);
    secret.fill(0);
    if (empty) failure('RUNTIME_UNAVAILABLE');
    key = crypto.createHash('sha256').update(payload.atRestSecretKey, 'utf8').digest();
    payload = null;
    if (crypto.createHash('sha256').update(key).digest('hex').slice(0, 16) !== envelope.keyId)
      failure('KEY_MISMATCH');
    const lp = s => {
      const bytes = Buffer.from(s, 'utf8');
      const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
      return Buffer.concat([length, bytes]);
    };
    const aad = Buffer.concat([Buffer.from('WB-AAD\0', 'ascii'), Buffer.from([1]),
      lp('WBEV1'), lp('sym-v1'), Buffer.from([0, 0, 0, 1]), lp(envelope.keyId), Buffer.from([2, 0, 0])]);
    try {
      const cipher = crypto.createDecipheriv('aes-256-gcm', key, envelope.nonce, {authTagLength: 16});
      cipher.setAAD(aad); cipher.setAuthTag(envelope.tag);
      plaintext = Buffer.concat([cipher.update(envelope.ciphertext), cipher.final()]);
    } catch (_) { failure('DECRYPT_FAILED'); }
    const text = utf8(plaintext);
    if (!text.length || text.length > 32768) failure('INVALID_FORMAT');
    return text;
  } finally {
    if (key) key.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}
let chunks = [], size = 0;
function reply(value) {
  process.stdout.write(JSON.stringify({version: 1, ...value}), () => process.exit(value.ok ? 0 : 1));
}
process.stdin.on('data', chunk => {
  size += chunk.length;
  if (size > inputLimit) reply({ok: false, reason: 'INVALID_FORMAT'});
  else chunks.push(chunk);
});
process.stdin.on('error', () => reply({ok: false, reason: 'HELPER_PROTOCOL'}));
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(utf8(Buffer.concat(chunks))); chunks = [];
    if (!object(request) || request.version !== 1) failure('HELPER_PROTOCOL');
    if (request.operation === 'probe') {
      nativeStorage();
      if (!crypto.getCiphers().includes('aes-256-gcm')) failure('RUNTIME_UNAVAILABLE');
      reply({ok: true, electron: process.versions.electron || 'unknown'});
    } else if (request.operation === 'decrypt') {
      reply({ok: true, plaintext: decrypt(decode(request.value))});
    } else failure('HELPER_PROTOCOL');
  } catch (e) {
    const reasons = ['INVALID_FORMAT','UNSUPPORTED_ENVELOPE','RUNTIME_UNAVAILABLE',
      'KEY_MISMATCH','DECRYPT_FAILED','HELPER_PROTOCOL'];
    reply({ok: false, reason: reasons.includes(e.reason) ? e.reason : 'HELPER_PROTOCOL'});
  }
});
"""

_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/-]+=*")


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        print(line.encode("utf-8", errors="replace").decode("utf-8", errors="replace"), flush=True)


def _valid_token(token) -> bool:
    return (isinstance(token, str) and 0 < len(token) <= 32768
            and _TOKEN_RE.fullmatch(token) is not None)


def _token_expired(token: str) -> bool:
    """解析 JWT 的 exp 判断令牌是否过期；非 JWT 或无法解析时返回 False（不误判）。"""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return False
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            return exp < datetime.now().timestamp()
    except Exception:
        pass
    return False


def _is_envelope(value) -> bool:
    """新版加密信封: {"$wbEncrypted":1, "envelope":"..."}"""
    return (isinstance(value, dict) and value.get("$wbEncrypted") == 1
            and isinstance(value.get("envelope"), str))


# ---------------------------------------------------------------------------
# 本地 Electron 运行时解密
# ---------------------------------------------------------------------------

def _win_registry_runtimes():
    """从注册表卸载信息里找 WorkBuddy.exe（安装目录可能在 D: 等非默认盘）。"""
    if sys.platform != "win32":
        return
    try:
        import winreg
    except ImportError:
        return
    roots = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    for hive, sub in roots:
        try:
            key = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        i = 0
        while True:
            try:
                child_name = winreg.EnumKey(key, i)
                i += 1
            except OSError:
                break
            try:
                child = winreg.OpenKey(key, child_name)
                name = winreg.QueryValueEx(child, "DisplayName")[0]
                if "workbuddy" not in str(name).lower():
                    winreg.CloseKey(child)
                    continue
                for field in ("DisplayIcon", "InstallLocation"):
                    try:
                        raw = winreg.QueryValueEx(child, field)[0]
                    except OSError:
                        continue
                    if not isinstance(raw, str) or not raw:
                        continue
                    candidate = raw.split(",")[0].strip().strip('"')
                    if candidate.lower().endswith(".exe"):
                        yield os.path.abspath(os.path.expanduser(candidate))
                    elif os.path.isdir(candidate):
                        yield os.path.abspath(os.path.join(candidate, "WorkBuddy.exe"))
                winreg.CloseKey(child)
            except OSError:
                continue
        winreg.CloseKey(key)


def find_workbuddy_runtime() -> str | None:
    override = os.environ.get("WORKBUDDY_EXE", "").strip()
    if override:
        path = os.path.abspath(os.path.expanduser(override))
        if os.path.isfile(path):
            return path
        return None

    candidates = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData/Local")
        candidates.append(os.path.join(local, "Programs", "WorkBuddy", "WorkBuddy.exe"))
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(os.path.join(base, "WorkBuddy", "WorkBuddy.exe"))
    elif sys.platform == "darwin":
        for root in ("/Applications", str(Path.home() / "Applications")):
            candidates.append(os.path.join(root, "WorkBuddy.app", "Contents", "MacOS", "WorkBuddy"))
    for path in candidates:
        if path and os.path.isfile(path):
            return os.path.abspath(path)
    for path in _win_registry_runtimes():
        if path and os.path.isfile(path):
            return path
    return None


def _run_auth_helper(exe: str, request: dict) -> dict:
    """在隐藏的 Electron 子进程里运行解密助手，明文 token 只经内存管道返回。"""
    data = json.dumps(dict(request, version=1), ensure_ascii=True).encode("ascii")
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("NODE_", "ELECTRON_", "WORKBUDDY_"))}
    env["ELECTRON_RUN_AS_NODE"] = "1"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            [exe, "-e", _AUTH_HELPER_JS], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, creationflags=flags, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("无法启动 WorkBuddy 运行时（解密失败）") from None
    try:
        reply = json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise RuntimeError("解密助手返回了无效响应") from None
    if reply.get("ok") is not True or proc.returncode != 0:
        raise RuntimeError(f"令牌解密失败: {reply.get('reason', '未知原因')}")
    return reply


def decrypt_field(value: dict, *, expect_token: bool = True) -> str:
    """解密单个加密信封字段；expect_token=True 时校验令牌格式。"""
    exe = find_workbuddy_runtime()
    if not exe:
        raise RuntimeError(
            "找不到 WorkBuddy 客户端，无法解密加密字段。"
            "请确认本机已安装并登录 WorkBuddy，或用 WORKBUDDY_EXE 指定 WorkBuddy.exe 路径。"
        )
    text = _run_auth_helper(exe, {"operation": "decrypt", "value": value})["plaintext"]
    if expect_token and not _valid_token(text):
        raise RuntimeError("解密得到的令牌格式无效")
    return text


def decrypt_access_token(value: dict) -> str:
    return decrypt_field(value, expect_token=True)


def _plain_or_decrypted(value, *, expect_token: bool = False) -> str:
    """字段可能是明文字符串，也可能是新版加密信封。"""
    if _is_envelope(value):
        try:
            return decrypt_field(value, expect_token=expect_token)
        except RuntimeError as e:
            log(f"[!] 字段解密失败: {e}")
            return ""
    if isinstance(value, str):
        return value.strip()
    return ""


# ---------------------------------------------------------------------------
# 凭证读取
# ---------------------------------------------------------------------------

def _read_local_auth(auth_file: Path) -> dict | None:
    if not auth_file.exists():
        return None
    try:
        return json.loads(auth_file.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"[!] 读取 auth 文件失败 ({auth_file}): {e}")
        return None


def _creds_from_env() -> dict | None:
    token = os.environ.get("WORKBUDDY_ACCESS_TOKEN", "").strip()
    if not token:
        return None
    return {
        "access_token": token,
        "account_name": os.environ.get("WORKBUDDY_ACCOUNT_NAME", "环境变量账号"),
        "uid": os.environ.get("WORKBUDDY_UID", "").strip() or None,
        "domain": os.environ.get("WORKBUDDY_DOMAIN", "www.codebuddy.cn").strip(),
        "enterprise_id": os.environ.get("WORKBUDDY_ENTERPRISE_ID", "").strip() or None,
    }


def _creds_from_config() -> dict | None:
    if not _CLOUD_CONFIG_FILE.exists():
        return None
    try:
        data = json.loads(_CLOUD_CONFIG_FILE.read_text(encoding="utf-8"))
        token = (data.get("access_token") or "").strip()
        if not token:
            return None
        return {
            "access_token": token,
            "account_name": data.get("account_name") or "云端账号",
            "uid": (data.get("uid") or "").strip() or None,
            "domain": (data.get("domain") or "www.codebuddy.cn").strip(),
            "enterprise_id": (data.get("enterprise_id") or "").strip() or None,
        }
    except Exception as e:
        log(f"[!] 读取 config.json 失败: {e}")
        return None


def _creds_from_local_auth() -> dict | None:
    """从本地客户端认证文件读取；如果是加密信封，则调用 Electron 运行时解密。"""
    for auth_file, label in ((_WIN_AUTH_FILE, "Windows"), (_MAC_AUTH_FILE, "macOS")):
        data = _read_local_auth(auth_file)
        if not data:
            continue
        raw_token = (data.get("auth", {}).get("accessToken") or "")
        if not raw_token:
            log(f"[x] {label} auth 中未找到 accessToken")
            continue

        if _is_envelope(raw_token):
            log(f"   检测到 {label} 客户端加密令牌 (sym-v1)，正在调用本机运行时解密...")
            try:
                token = decrypt_access_token(raw_token)
            except RuntimeError as e:
                log(f"[x] {e}")
                continue
            log("   令牌解密成功（明文仅在本机内存中使用）")
        elif isinstance(raw_token, str) and raw_token.strip():
            token = raw_token.strip()
        else:
            log(f"[x] {label} accessToken 格式不受支持")
            continue

        account = data.get("account") or {}
        nickname = _plain_or_decrypted(account.get("nickname")) or f"{label}账号"
        return {
            "access_token": token,
            "account_name": nickname,
            "uid": (account.get("uid") or "").strip() or None,
            "domain": (data.get("auth", {}).get("domain") or "www.codebuddy.cn").strip(),
            "enterprise_id": (
                (account.get("enterpriseId") or account.get("enterprise_id") or "").strip() or None
            ),
        }
    return None


def load_credentials() -> dict | None:
    # CI 优先读 Secrets 注入的环境变量（云端 runner 上没有客户端，不能解密）
    if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI"):
        creds = _creds_from_env()
        if creds:
            if _token_expired(creds["access_token"]):
                log("[x] GitHub Secret 中的 token 已过期，请在本机运行 "
                    "`python checkin.py --export-token` 后更新 Secret")
            else:
                log(f"   使用环境变量 (账号: {creds['account_name']})")
                return creds
        else:
            log("[x] CI 环境未检测到 WORKBUDDY_ACCESS_TOKEN，请检查 GitHub Secrets 配置")
        return None

    creds = _creds_from_config()
    if creds:
        if _token_expired(creds["access_token"]):
            log("[!] config.json 中的 token 已过期，跳过")
        else:
            log(f"   使用 config.json (账号: {creds['account_name']})")
            return creds

    creds = _creds_from_env()
    if creds:
        if _token_expired(creds["access_token"]):
            log("[!] 环境变量中的 token 已过期，跳过")
        else:
            log(f"   使用环境变量 (账号: {creds['account_name']})")
            return creds

    creds = _creds_from_local_auth()
    if creds:
        log(f"   使用本地客户端 (账号: {creds['account_name']})")
        return creds

    log("[x] 未找到任何可用凭证，请配置 config.json / 环境变量，或登录本地 WorkBuddy")
    return None


# ---------------------------------------------------------------------------
# 签到请求
# ---------------------------------------------------------------------------

def _build_headers(creds: dict) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {creds['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "WorkBuddy-Checkin/1.1",
    }
    if creds.get("uid"):
        headers["X-User-Id"] = creds["uid"]
    if creds.get("domain"):
        headers["X-Domain"] = creds["domain"]
    eid = creds.get("enterprise_id")
    if eid:
        headers["X-Enterprise-Id"] = eid
        headers["X-Tenant-Id"] = eid
    return headers


def _request_json(url: str, creds: dict, method: str = "POST") -> dict | None:
    req = urllib.request.Request(
        url,
        data=b"{}",
        method=method.upper(),
        headers=_build_headers(creds),
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        log(f"   HTTP {e.code}: {e.reason} {err_body[:300]}")
        try:
            return json.loads(err_body) if err_body else None
        except Exception:
            return None
    except Exception as e:
        log(f"   请求失败: {e}")
        return None


def _msg_of(payload: dict | None) -> str:
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("message") or payload.get("msg") or "")


def already_checked_in(payload: dict | None) -> bool:
    if not isinstance(payload, dict):
        return False
    code = payload.get("code")
    msg = _msg_of(payload)
    if code == 10001 or "已签到" in msg or "已经签到" in msg:
        return True
    data = payload.get("data")
    if isinstance(data, dict) and (data.get("today_checked_in") or data.get("checked_in")):
        return True
    return bool(payload.get("today_checked_in") or payload.get("checked_in"))


def unwrap_data(payload: dict | None) -> dict | None:
    if not isinstance(payload, dict):
        return None
    code = payload.get("code")
    if code is not None and code not in (0, 200):
        msg = _msg_of(payload) or "unknown"
        log(f"   业务错误 code={code}: {msg}")
        return None
    data = payload.get("data")
    return data if isinstance(data, dict) else payload


def checkin() -> bool:
    log("=" * 56)
    log(f"  WorkBuddy 每日签到 --- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 56)

    log("步骤 1/3: 获取凭证...")
    creds = load_credentials()
    if not creds:
        return False

    log("步骤 2/3: 查询签到状态...")
    status_raw = _request_json(CHECKIN_STATUS_URL, creds, method="POST")
    if already_checked_in(status_raw):
        log("[ok] 今日已签到，无需重复领取。")
        return True
    status = unwrap_data(status_raw)
    if status is None:
        log("[!] 签到状态查询失败，继续尝试领取...")
    else:
        log(
            f"   active={status.get('active')}, "
            f"today_checked_in={status.get('today_checked_in')}, "
            f"streak_days={status.get('streak_days')}"
        )

    log("步骤 3/3: 领取签到积分...")
    result_raw = _request_json(DAILY_CHECKIN_URL, creds, method="POST")
    if already_checked_in(result_raw):
        log("[ok] 今日已签到。")
        return True

    result = unwrap_data(result_raw)
    if result is None:
        log("[x] 签到失败，请检查 token 是否过期。")
        return False

    success = result.get("success", True)
    credit = result.get("credit", result.get("today_credit", result.get("points")))
    streak = result.get("streak_days")
    message = result.get("message") or ""
    if success is False:
        log(f"[!] 领取未成功: {message or result}")
        return False

    log(f"[ok] 签到成功! credit={credit}, streak_days={streak} {message}")
    return True


# ---------------------------------------------------------------------------
# 导出明文 token（本机专用，供粘贴到 GitHub Secrets）
# ---------------------------------------------------------------------------

def export_token() -> int:
    """解密本地加密令牌并输出可粘贴到 GitHub Secrets 的凭证信息。"""
    log("开始导出 token（仅本机运行，明文不会写入文件）")

    data = None
    for auth_file in (_WIN_AUTH_FILE, _MAC_AUTH_FILE):
        data = _read_local_auth(auth_file)
        if data:
            break
    if not data:
        log("[x] 未找到本地认证文件，请先登录 WorkBuddy 桌面端")
        return 1

    raw_token = (data.get("auth", {}).get("accessToken") or "")
    if _is_envelope(raw_token):
        log("   检测到加密信封，正在调用本机 WorkBuddy 运行时解密...")
        try:
            token = decrypt_access_token(raw_token)
        except RuntimeError as e:
            log(f"[x] {e}")
            return 1
    elif isinstance(raw_token, str) and _valid_token(raw_token.strip()):
        token = raw_token.strip()
        log("   本地令牌为明文，无需解密")
    else:
        log("[x] accessToken 格式无法识别")
        return 1

    account = data.get("account") or {}
    auth = data.get("auth", {})
    nickname = _plain_or_decrypted(account.get("nickname")) or "账号"
    result = {
        "WORKBUDDY_ACCESS_TOKEN": token,
        "WORKBUDDY_ACCOUNT_NAME": nickname,
        "WORKBUDDY_UID": (account.get("uid") or "").strip(),
        "WORKBUDDY_DOMAIN": (auth.get("domain") or "www.codebuddy.cn").strip(),
        "WORKBUDDY_ENTERPRISE_ID": (
            account.get("enterpriseId") or account.get("enterprise_id") or ""
        ),
    }
    print("\n" + "=" * 56)
    print("请把下面各项的值分别填入 GitHub 仓库 Settings > Secrets and variables > Actions：")
    print("(WORKBUDDY_ACCESS_TOKEN 通常很长，注意完整复制，不要带引号或空格)")
    print("=" * 56)
    for key, value in result.items():
        print(f"{key}={value}")
    print("=" * 56)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="WorkBuddy 每日签到")
    parser.add_argument("--export-token", action="store_true",
                        help="仅本机：解密本地令牌并输出供 GitHub Secrets 使用的值")
    args = parser.parse_args()

    if args.export_token:
        sys.exit(export_token())
    sys.exit(0 if checkin() else 1)
