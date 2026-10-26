#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xshell 会话密码解密工具（支持 Xshell 8）
==========================================
解密 Xshell 导出的 .xsh 会话文件中保存的密码。纯标准库实现，无需安装第三方依赖。

原理（基于 HyperSine 的逆向分析与 SharpXDecrypt / Xpass 的实现）：
    Xshell 用 RC4 流密码加密密码，密钥随会话文件版本不同而变化：

        版本             密钥（RC4 key）
        ---------------- ------------------------------------------------
        < 5.1            MD5("!X@s#h$e%l^l&")            （固定密钥，无校验和）
        5.1 / 5.2        SHA256(用户 SID)
        5.3 ~ 7.0        SHA256(用户名 + SID)
        >= 7.1 (含 8.x)  SHA256(反转(SID) + 用户名)

    版本 >= 5.1 时，加密后的密码末尾还会附加 32 字节的 SHA256(明文) 校验和，
    整体再做 Base64 编码，写入 .xsh 文件的 `Password=` 字段。
    解密时去掉末尾 32 字节校验和，用对应密钥做 RC4 解密，并用校验和验证结果。

⚠️ 重要提示：
    “用户名”和“SID”指的是【运行 Xshell 的 Windows 操作系统账户】的用户名和 SID，
    不是会话文件里的登录用户名（UserName= 字段）。
    在 Windows 上查询方法：
        whoami /user        # 得到 SID
        echo %USERNAME%     # 得到用户名
        （或） wmic useraccount get name,sid

用法示例：
    # 解密单个会话文件
    python3 xshell_decrypt.py session.xsh -u hp -s S-1-5-21-...-1000

    # 批量解密整个 Sessions 目录（递归）
    python3 xshell_decrypt.py ./Sessions -u hp -s S-1-5-21-...-1000

    # JSON 输出
    python3 xshell_decrypt.py ./Sessions -u hp -s S-1-5-21-...-1000 --json

    # 自检（用公开测试向量验证算法是否正确）
    python3 xshell_decrypt.py --self-test

    # 若会话启用了主密码
    python3 xshell_decrypt.py session.xsh --master-password "你的主密码"

仅用于恢复你自己的密码。请勿用于非法用途。
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys

# Xshell 固定密钥串（注意是 'h'；Xftp 用的是 'c'）
XSH_FIXED_KEY = b"!X@s#h$e%l^l&"

# 尝试的字符串编码。Windows 用户名可能含中文等非 ASCII 字符，
# .NET 的 Encoding.Default 对应系统 ANSI 代码页，这里依次尝试常见代码页。
CANDIDATE_ENCODINGS = [
    "ascii", "utf-8", "gb18030", "gbk", "big5",
    "cp1252", "cp932", "cp949", "shift_jis", "latin-1",
]


def rc4(key: bytes, data: bytes) -> bytes:
    """标准 RC4 流密码（与 Xshell / SharpXDecrypt 实现一致）。"""
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for idx, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[idx] = byte ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def read_text_file(path: str) -> str:
    """读取文本文件，自动处理 UTF-8/UTF-16 BOM 及常见编码。"""
    with open(path, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for enc in ("gb18030", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")


def parse_xsh(path: str) -> dict:
    """解析 .xsh 文件，提取关键字段。"""
    info = {
        "path": path,
        "host": None,
        "port": None,
        "username": None,   # 会话登录用户名（UserName= 字段）
        "password": None,   # Base64 密文
        "version": None,
        "description": None,
    }
    text = read_text_file(path)
    for line in text.splitlines():
        line = line.strip("\ufeff").strip()
        if line.startswith("Host="):
            info["host"] = line[len("Host="):]
        elif line.startswith("Port="):
            info["port"] = line[len("Port="):]
        elif line.startswith("UserName="):
            info["username"] = line[len("UserName="):]
        elif line.startswith("Password="):
            info["password"] = line[len("Password="):].strip('"\' \t')
        elif line.startswith("Version="):
            info["version"] = line[len("Version="):]
        elif line.startswith("Description="):
            info["description"] = line[len("Description="):]
    return info


def parse_version(version_str) -> tuple:
    """把 '8.0' / '8.0.0' 之类的版本号解析为 (major, minor)，失败返回 None。"""
    m = re.search(r"(\d+)\.(\d+)", version_str or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def classify_version(version_str) -> str:
    """根据版本号判断密钥模式。"""
    v = parse_version(version_str)
    if v is None:
        return None
    major, minor = v
    if major < 5 or (major == 5 and minor == 0):
        return "md5_fixed"           # < 5.1
    if major == 5 and minor in (1, 2):
        return "sha256_sid"          # 5.1 / 5.2
    if (major == 5 and minor >= 3) or major == 6 or (major == 7 and minor == 0):
        return "sha256_user_sid"     # 5.3 ~ 7.0
    return "sha256_rev_sid_user"     # >= 7.1，含 8.x


def required_params(mode: str) -> list:
    """返回该模式需要的命令行参数名。"""
    if mode == "md5_fixed":
        return []
    if mode == "sha256_sid":
        return ["sid"]
    if mode in ("sha256_user_sid", "sha256_rev_sid_user"):
        return ["username", "sid"]
    return ["username", "sid"]


def _encode_with(text: str, enc: str):
    try:
        return text.encode(enc)
    except (UnicodeEncodeError, LookupError):
        return None


def _dedupe(entries):
    seen = {}
    for key_bytes, enc in entries:
        if key_bytes not in seen:
            seen[key_bytes] = enc
    return list(seen.items())


def candidate_keys(mode: str, username: str, sid: str, master_password):
    """生成候选 (RC4 密钥, 使用的编码) 列表，按可能性排序并去重。"""
    if master_password is not None:
        results = []
        for enc in CANDIDATE_ENCODINGS:
            b = _encode_with(master_password, enc)
            if b is None:
                continue
            results.append((hashlib.sha256(b).digest(), enc))
        return _dedupe(results)

    if mode == "md5_fixed":
        return [(hashlib.md5(XSH_FIXED_KEY).digest(), "ascii")]

    if mode == "sha256_sid":
        b = _encode_with(sid, "ascii")
        return [(hashlib.sha256(b).digest(), "ascii")] if b is not None else []

    if mode == "sha256_user_sid":
        results = []
        for enc in CANDIDATE_ENCODINGS:
            b = _encode_with(username + sid, enc)
            if b is None:
                continue
            results.append((hashlib.sha256(b).digest(), enc))
        return _dedupe(results)

    if mode == "sha256_rev_sid_user":
        results = []
        for enc in CANDIDATE_ENCODINGS:
            b = _encode_with(sid[::-1] + username, enc)
            if b is None:
                continue
            results.append((hashlib.sha256(b).digest(), enc))
        return _dedupe(results)

    raise ValueError("未知密钥模式: %s" % mode)


ALL_SCHEMES = ["md5_fixed", "sha256_sid", "sha256_user_sid", "sha256_rev_sid_user"]

SCHEME_LABELS = {
    "md5_fixed": "< 5.1：MD5(固定密钥)",
    "sha256_sid": "5.1/5.2：SHA256(SID)",
    "sha256_user_sid": "5.3~7.0：SHA256(用户名+SID)",
    "sha256_rev_sid_user": ">= 7.1/8.x：SHA256(反转SID+用户名)",
}


def try_all_schemes(encrypted_b64, username, sid, master_password=None):
    """用给定的用户名/SID 依次尝试所有版本方案，返回带命中的结果列表。"""
    out = []
    for mode in ALL_SCHEMES:
        mp = master_password if mode != "md5_fixed" else None
        plain, enc = decrypt_password(encrypted_b64, mode, username, sid, mp)
        out.append({
            "mode": mode,
            "label": SCHEME_LABELS[mode],
            "password": plain,
            "encoding": enc if plain is not None else None,
        })
    return out


def decode_plain(plain: bytes, hint_enc=None) -> str:
    """把解密出的字节转成字符串，优先按匹配到的编码提示尝试。"""
    attempts = []
    if hint_enc and hint_enc not in ("ascii", "utf-8", "utf8", "latin-1"):
        attempts.append(hint_enc)
    attempts += ["utf-8", "gb18030", "cp1252"]
    for enc in attempts:
        try:
            return plain.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return plain.decode("latin-1")


def decrypt_password(encrypted_b64, mode, username="", sid="", master_password=None):
    """解密密码。返回 (明文字符串, 匹配编码) 或 (None, 错误说明)。"""
    if not encrypted_b64:
        return None, "未找到 Password 字段或字段为空"

    try:
        data = base64.b64decode(encrypted_b64.strip(), validate=False)
    except (binascii.Error, ValueError) as e:
        return None, "Base64 解码失败: %s" % e

    # 主密码模式与版本 >= 5.1 一样，密文末尾都带 32 字节校验和；
    # 仅 < 5.1 的固定密钥模式不带校验和。
    if master_password is None and mode == "md5_fixed":
        cipher, checksum = data, None
    else:
        if len(data) < 32:
            return None, "密文长度不足 32 字节（缺少校验和），版本判断可能有误"
        cipher, checksum = data[:-32], data[-32:]

    keys = candidate_keys(mode, username, sid, master_password)
    if not keys:
        return None, "无法生成密钥：请提供正确的 --username / --sid"

    for key, enc in keys:
        plain = rc4(key, cipher)
        if checksum is None or hashlib.sha256(plain).digest() == checksum:
            return decode_plain(plain, enc), enc

    return None, ("密钥不匹配。常见原因：① 启用了主密码（改用 --master-password 重试）；"
                  "② 用户名/SID 不对（是 Windows 系统账户，whoami /user 可查）；"
                  "③ 版本判断有误。可用 --try-all 诊断到底命中了哪种方案。")


def iter_xsh_files(target: str):
    """展开目标：单个文件直接返回；目录递归收集所有 .xsh 文件。"""
    if os.path.isfile(target):
        return [target]
    if os.path.isdir(target):
        result = []
        for root, _dirs, files in os.walk(target):
            for name in files:
                if name.lower().endswith(".xsh"):
                    result.append(os.path.join(root, name))
        return sorted(result)
    return []


def process_file(path, args):
    """处理单个 .xsh 文件，返回结果字典。"""
    info = parse_xsh(path)
    version_str = args.version or info["version"]

    result = {
        "path": path,
        "host": info["host"],
        "port": info["port"],
        "session_username": info["username"],
        "version": version_str or info["version"],
        "password": None,
        "status": "ok",
        "error": None,
    }

    if not info["password"]:
        result["status"] = "skipped"
        result["error"] = "无 Password 字段（可能未保存密码或使用密钥认证）"
        return result

    mode = classify_version(version_str)
    if mode is None:
        result["status"] = "error"
        result["error"] = "无法识别版本号，请用 --version 指定（例如 --version 8.0）"
        return result

    if args.master_password is not None:
        username = sid = ""
    else:
        username = args.username or ""
        sid = args.sid or ""
        missing = [p for p in required_params(mode) if not (args.username if p == "username" else args.sid)]
        if missing:
            result["status"] = "error"
            result["error"] = ("该版本需要参数: %s（Windows 系统账户的用户名/SID，"
                               "用 whoami /user 查询）" % ", ".join("--" + m for m in missing))
            return result

    plain, enc = decrypt_password(info["password"], mode, username, sid, args.master_password)
    if plain is None:
        result["status"] = "error"
        result["error"] = enc
        return result

    result["password"] = plain
    result["mode"] = mode
    result["key_encoding"] = enc
    return result


def _run_try_all(files, args):
    """诊断模式：对每个文件尝试所有版本方案。"""
    for f in files:
        info = parse_xsh(f)
        print("文件: %s" % f)
        if args.version or info["version"]:
            print("  版本: %s" % (args.version or info["version"]))
        if info["host"]:
            print("  主机: %s" % info["host"])
        if not info["password"]:
            print("  [skipped] 无 Password 字段（可能未保存密码或使用密钥认证）")
            print()
            continue
        schemes = try_all_schemes(info["password"],
                                  args.username or "",
                                  args.sid or "",
                                  args.master_password)
        matched = [s for s in schemes if s["mode"] != "md5_fixed" and s["password"] is not None]
        print("  尝试所有密钥方案（用户名=%s，SID=%s）：" % (
            args.username or "(未提供)", args.sid or "(未提供)"))
        for s in schemes:
            if s["mode"] == "md5_fixed":
                mark, detail = "-", "(无校验和，仅供参考) " + repr(s["password"])
            elif s["password"] is not None:
                mark, detail = "✓", "密码: %s (编码: %s)" % (s["password"], s["encoding"])
            else:
                mark, detail = "✗", "不匹配"
            print("    [%s] %-36s %s" % (mark, s["label"], detail))
        if matched:
            print("  结论: 命中 -> %s，密码: %s" % (matched[0]["label"], matched[0]["password"]))
        else:
            print("  结论: 没有任何方案通过校验和，极可能是启用了【主密码】。")
            print("        → Xshell 菜单「工具 → 选项 → 安全」查看主密码是否已设置；")
            print("        → 若已设置，用 --master-password \"你的主密码\" 重试；")
            print("        → 否则确认 --username / --sid 与 whoami /user 输出完全一致。")
        print()
    return 0


def self_test():
    """用公开测试向量验证算法正确性。"""
    cases = [
        # (mode, username, sid, master_password, ciphertext, expected_plaintext)
        ("md5_fixed", "", "", None,
         "/6KaTrKwm0cmhr0yAWQ=", "This is a test"),
        ("sha256_user_sid", "Administrator",
         "S-1-5-21-917267712-1342860078-1792151419-512", None,
         "zv21O1x43qRs3c5NckDHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==",
         "This is a test"),
        ("sha256_rev_sid_user", "hp",
         "S-1-5-21-2029295174-2268103727-2717561949-1000", None,
         "6WgMEKQvz4Y/PqCczXcPOXyCXJ0lwQZaHeRKIzPV7P6xvfaw2sUscA==",
         "test@!@#"),
        # 主密码模式：密钥 = SHA256(主密码)，与用户名/SID 无关
        ("sha256_rev_sid_user", "", "", "123123",
         "Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==",
         "This is a test"),
    ]
    ok = True
    for mode, user, sid, mp, cipher, expected in cases:
        plain, enc = decrypt_password(cipher, mode, user, sid, mp)
        good = (plain == expected)
        ok = ok and good
        print("[%s] mode=%-18s -> %s%s" % (
            "PASS" if good else "FAIL", mode, repr(plain),
            "" if good else "（期望 %r）" % expected))
    print("\n自检结果:", "全部通过 ✓" if ok else "存在失败 ✗")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="解密 Xshell .xsh 会话文件中的密码（支持 Xshell 8）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法示例")[0],
    )
    parser.add_argument("target", nargs="?", help=".xsh 文件或包含 .xsh 的目录")
    parser.add_argument("-u", "--username", help="Windows 系统账户名（运行 Xshell 的账户）")
    parser.add_argument("-s", "--sid", help="Windows 用户 SID，形如 S-1-5-21-...（whoami /user 可查）")
    parser.add_argument("-v", "--version", help="覆盖 .xsh 中的版本号，例如 8.0")
    parser.add_argument("-m", "--master-password", help="若启用了主密码，请提供主密码")
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出")
    parser.add_argument("--try-all", action="store_true",
                        help="诊断模式：用给定用户名/SID 尝试所有版本方案，找出命中的方案")
    parser.add_argument("--self-test", action="store_true", help="运行自检后退出")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.target:
        parser.error("请提供 .xsh 文件或目录路径，或使用 --self-test 自检")

    files = iter_xsh_files(args.target)
    if not files:
        print("未找到任何 .xsh 文件: %s" % args.target, file=sys.stderr)
        return 1

    if args.try_all:
        return _run_try_all(files, args)

    results = [process_file(f, args) for f in files]

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0

    for r in results:
        print("文件: %s" % r["path"])
        if r["version"]:
            print("  版本: %s" % r["version"])
        if r["host"]:
            print("  主机: %s" % r["host"])
        if r["port"]:
            print("  端口: %s" % r["port"])
        if r["session_username"]:
            print("  登录用户名: %s" % r["session_username"])
        if r["status"] == "ok":
            print("  密码: %s" % r["password"])
        else:
            print("  [%s] %s" % (r["status"], r["error"]))
        print()

    failed = sum(1 for r in results if r["status"] == "error")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
