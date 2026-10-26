# xpassword

解密 Xshell 会话文件（`.xsh`）中保存的密码的命令行工具，支持 **Xshell 8**，以及 5 / 6 / 7 全系列。纯 Python 标准库实现，零第三方依赖。

## 功能

- 解密单个 `.xsh` 文件或整个 Sessions 目录（递归）
- 自动识别会话版本并选用对应的密钥派生方案
- 支持主密码（master password）模式
- 支持非 ASCII 的 Windows 用户名（如中文账户名，自动尝试 GBK/Big5/Shift-JIS 等编码）
- 用 SHA-256 校验和验证解密结果，密钥错误时给出明确提示
- 支持 JSON 输出，便于脚本化

## 使用

```bash
# 解密单个会话文件
python3 xshell_decrypt.py session.xsh -u <Windows用户名> -s <Windows SID>

# 批量解密整个 Sessions 目录（递归）
python3 xshell_decrypt.py ./Sessions -u <Windows用户名> -s <Windows SID>

# JSON 输出
python3 xshell_decrypt.py ./Sessions -u <Windows用户名> -s <Windows SID> --json

# 自检（用公开测试向量验证算法）
python3 xshell_decrypt.py --self-test

# 若启用了主密码
python3 xshell_decrypt.py session.xsh --master-password "你的主密码"
```

> 启用主密码（每次打开 Xshell 都要先输一次密码）时，密钥是 `SHA256(主密码)`，
> 与 Windows 用户名/SID 无关，此时**不要**再加 `-u` / `-s`。

### 获取用户名与 SID

`-u` / `-s` 指的是**运行 Xshell 的 Windows 系统账户**的用户名和 SID，不是会话里的登录用户名（`UserName=` 字段）。

在 Windows 上执行：

```bat
whoami /user        :: 得到 SID，形如 S-1-5-21-...-1001
echo %USERNAME%     :: 得到用户名
```

也可以用 `wmic useraccount get name,sid` 一次性查看。

## 原理

Xshell 用 RC4 流密码加密密码，密钥随会话文件版本不同而变化；版本 ≥ 5.1 时，密文末尾还会附加 32 字节的 `SHA256(明文)` 校验和，整体再 Base64 编码。

| 版本 | RC4 密钥 | 校验和 |
|---|---|---|
| < 5.1 | `MD5("!X@s#h$e%l^l&")` | 无 |
| 5.1 / 5.2 | `SHA256(SID)` | 32 字节 |
| 5.3 ~ 7.0 | `SHA256(用户名 + SID)` | 32 字节 |
| ≥ 7.1（含 8.x） | `SHA256(反转(SID) + 用户名)` | 32 字节 |

解密流程：Base64 解码 → 去掉末尾 32 字节校验和 → 用对应密钥 RC4 解密 → 校验和验证。

## 免责声明

本工具仅用于恢复**你自己**的密码。请勿用于任何非法用途，由此产生的一切后果由使用者自行承担。

## 参考

- [HyperSine / how-does-Xmanager-encrypt-password](https://github.com/HyperSine/how-does-Xmanager-encrypt-password)
- [JDArmy / SharpXDecrypt](https://github.com/JDArmy/SharpXDecrypt)
- [ssmmtt / Xpass](https://github.com/ssmmtt/Xpass)
