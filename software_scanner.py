#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
软件资产扫描工具 v1.0
扫描系统已安装软件及编程语言第三方依赖包，输出 CSV 报告。
纯 Python 标准库实现，零第三方依赖。
"""

import csv
import datetime
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

# ============================================================
# 常量与配置
# ============================================================
VERSION = "1.0"
COMMAND_TIMEOUT = 30  # 子命令超时（秒）
CSV_BOM = "\ufeff"    # UTF-8 BOM，确保 Excel 正确显示中文


# ============================================================
# 工具函数
# ============================================================

def run_cmd(cmd, timeout=COMMAND_TIMEOUT, shell=False, encoding=None):
    """安全执行系统命令，返回 (stdout, stderr, returncode)"""
    if encoding is None:
        encoding = "utf-8"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=shell, encoding=encoding, errors="replace"
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"命令未找到: {cmd}", -1
    except subprocess.TimeoutExpired:
        return "", f"命令超时({timeout}s): {cmd}", -2
    except Exception as e:
        return "", f"执行异常: {e}", -3


def cmd_exists(name):
    """检测命令是否可用"""
    return shutil.which(name) is not None


def get_os_info():
    """获取操作系统信息"""
    sys_name = platform.system()  # Windows / Linux / Darwin
    if sys_name == "Linux":
        try:
            # 尝试读取 /etc/os-release
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                lines = f.readlines()
            info = {}
            for line in lines:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v.strip('"')
            os_ver = info.get("PRETTY_NAME", f"Linux {platform.release()}")
        except Exception:
            os_ver = f"Linux {platform.release()}"
    elif sys_name == "Windows":
        os_ver = f"Windows {platform.version()}"
    elif sys_name == "Darwin":
        os_ver = f"macOS {platform.mac_ver()[0]}"
    else:
        os_ver = f"{sys_name} {platform.release()}"
    return sys_name, os_ver


def print_banner(hostname, os_ver, scan_time):
    """打印启动横幅"""
    print("=" * 50)
    print(f"  软件资产扫描工具 v{VERSION}")
    print(f"  主机: {hostname}")
    print(f"  系统: {os_ver}")
    print(f"  扫描时间: {scan_time}")
    print("=" * 50)
    print()


def print_result(name, count, skipped=False, reason=""):
    """打印单项扫描结果"""
    if skipped:
        print(f"  [—] {name} {'.' * (30 - len(name))} 跳过 ({reason})")
    else:
        print(f"  [✓] {name} {'.' * (30 - len(name))} {count} 个")


# ============================================================
# OS 软件扫描器
# ============================================================

def scan_windows_software():
    """扫描 Windows 已安装软件（注册表）"""
    items = []
    try:
        import winreg
    except ImportError:
        return items

    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in uninstall_paths:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    i += 1
                    try:
                        subkey = winreg.OpenKey(key, subkey_name)
                        name = _winreg_value(subkey, "DisplayName")
                        if not name:
                            continue
                        version = _winreg_value(subkey, "DisplayVersion") or "未知"
                        publisher = _winreg_value(subkey, "Publisher") or ""
                        install_path = _winreg_value(subkey, "InstallLocation") or ""
                        install_date = _winreg_value(subkey, "InstallDate") or ""
                        # 格式化安装日期 YYYYMMDD -> YYYY-MM-DD
                        if install_date and len(install_date) == 8:
                            install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:]}"
                        items.append({
                            "name": name, "version": version,
                            "source": "registry", "install_path": install_path,
                            "publisher": publisher, "install_date": install_date,
                        })
                        winreg.CloseKey(subkey)
                    except OSError:
                        continue
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

    # 去重（按名称+版本）
    seen = set()
    unique = []
    for item in items:
        key = (item["name"], item["version"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return sorted(unique, key=lambda x: x["name"].lower())


def _winreg_value(key, name):
    """安全读取注册表值"""
    try:
        import winreg
        value, _ = winreg.QueryValueEx(key, name)
        return str(value).strip() if value else ""
    except (OSError, Exception):
        return ""


def scan_windows_appx():
    """扫描 Windows Store 应用"""
    items = []
    if not cmd_exists("powershell"):
        return items
    stdout, _, rc = run_cmd(
        ["powershell", "-Command",
         "Get-AppxPackage | Select-Object Name, Version | ConvertTo-Json"],
        timeout=30
    )
    if rc != 0 or not stdout:
        return items
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            name = pkg.get("Name", "")
            version = pkg.get("Version", "")
            if name:
                items.append({
                    "name": name, "version": version,
                    "source": "appx", "install_path": "",
                    "publisher": "", "install_date": "",
                })
    except (json.JSONDecodeError, TypeError):
        pass
    return items


def scan_linux_software():
    """扫描 Linux 已安装软件（自动检测包管理器）"""
    items = []

    # dpkg (Debian/Ubuntu)
    if cmd_exists("dpkg-query"):
        stdout, _, rc = run_cmd(
            ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n"]
        )
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    status = parts[2] if len(parts) > 2 else ""
                    if "installed" not in status.lower() and status:
                        continue
                    items.append({
                        "name": parts[0], "version": parts[1],
                        "source": "dpkg", "install_path": "",
                        "publisher": "", "install_date": "",
                    })

    # rpm (RHEL/CentOS/Fedora)
    elif cmd_exists("rpm"):
        stdout, _, rc = run_cmd(
            ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"]
        )
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    items.append({
                        "name": parts[0], "version": parts[1],
                        "source": "rpm", "install_path": "",
                        "publisher": parts[2] if len(parts) > 2 else "",
                        "install_date": "",
                    })

    # pacman (Arch Linux)
    elif cmd_exists("pacman"):
        stdout, _, rc = run_cmd(["pacman", "-Q"])
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    items.append({
                        "name": parts[0], "version": parts[1],
                        "source": "pacman", "install_path": "",
                        "publisher": "", "install_date": "",
                    })

    # snap
    if cmd_exists("snap"):
        stdout, _, rc = run_cmd(["snap", "list"])
        if rc == 0 and stdout:
            for line in stdout.splitlines()[1:]:  # 跳过表头
                parts = line.split()
                if len(parts) >= 2:
                    items.append({
                        "name": parts[0], "version": parts[1],
                        "source": "snap", "install_path": "",
                        "publisher": "", "install_date": "",
                    })

    # flatpak
    if cmd_exists("flatpak"):
        stdout, _, rc = run_cmd(
            ["flatpak", "list", "--columns=application,version"]
        )
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 1:
                    items.append({
                        "name": parts[0],
                        "version": parts[1] if len(parts) > 1 else "未知",
                        "source": "flatpak", "install_path": "",
                        "publisher": "", "install_date": "",
                    })

    return sorted(items, key=lambda x: x["name"].lower())


def scan_macos_software():
    """扫描 macOS 已安装软件"""
    items = []

    # Homebrew
    if cmd_exists("brew"):
        stdout, _, rc = run_cmd(["brew", "list", "--versions"])
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    items.append({
                        "name": parts[0], "version": " ".join(parts[1:]),
                        "source": "brew", "install_path": "",
                        "publisher": "", "install_date": "",
                    })
        # Homebrew cask
        stdout, _, rc = run_cmd(["brew", "list", "--cask", "--versions"])
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    items.append({
                        "name": parts[0], "version": " ".join(parts[1:]),
                        "source": "brew-cask", "install_path": "",
                        "publisher": "", "install_date": "",
                    })

    # /Applications 目录
    app_dir = Path("/Applications")
    if app_dir.exists():
        for app in app_dir.glob("*.app"):
            plist = app / "Contents" / "Info.plist"
            version = ""
            if plist.exists():
                try:
                    stdout, _, rc = run_cmd(
                        ["defaults", "read", str(plist), "CFBundleShortVersionString"]
                    )
                    if rc == 0:
                        version = stdout
                except Exception:
                    pass
            items.append({
                "name": app.stem, "version": version or "未知",
                "source": "applications", "install_path": str(app),
                "publisher": "", "install_date": "",
            })

    return sorted(items, key=lambda x: x["name"].lower())


def scan_os_software():
    """根据操作系统调用对应扫描器"""
    sys_name = platform.system()
    if sys_name == "Windows":
        items = scan_windows_software()
        items.extend(scan_windows_appx())
        return items
    elif sys_name == "Linux":
        return scan_linux_software()
    elif sys_name == "Darwin":
        return scan_macos_software()
    return []


# ============================================================
# Python 包扫描器
# ============================================================

def scan_python_packages():
    """扫描 Python pip 安装的包"""
    items = []
    # 查找所有可能的 python 命令
    python_cmds = []
    for name in ["python3", "python", "python3.8", "python3.9",
                  "python3.10", "python3.11", "python3.12", "python3.13"]:
        if cmd_exists(name):
            # 获取真实路径去重
            real_path = shutil.which(name)
            if real_path and real_path not in [shutil.which(c) for c in python_cmds]:
                python_cmds.append(name)

    seen_envs = set()
    for py_cmd in python_cmds:
        # 获取 Python 版本
        stdout, _, rc = run_cmd([py_cmd, "--version"])
        if rc != 0:
            continue
        py_version = stdout.strip().replace("Python ", "")

        # 获取 pip list
        stdout, _, rc = run_cmd([py_cmd, "-m", "pip", "list", "--format=json"])
        if rc != 0:
            continue

        env_key = f"{py_cmd}_{py_version}"
        if env_key in seen_envs:
            continue
        seen_envs.add(env_key)

        try:
            pkgs = json.loads(stdout)
            for pkg in pkgs:
                items.append({
                    "language": "Python",
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "source": "pip",
                    "environment": f"system (python {py_version})",
                })
        except (json.JSONDecodeError, TypeError):
            pass

    # conda 环境
    if cmd_exists("conda"):
        stdout, _, rc = run_cmd(["conda", "list", "--json"])
        if rc == 0 and stdout:
            try:
                pkgs = json.loads(stdout)
                for pkg in pkgs:
                    items.append({
                        "language": "Python",
                        "name": pkg.get("name", ""),
                        "version": pkg.get("version", ""),
                        "source": "conda",
                        "environment": f"conda ({pkg.get('channel', 'default')})",
                    })
            except (json.JSONDecodeError, TypeError):
                pass

    return items


# ============================================================
# Java 依赖扫描器
# ============================================================

def scan_java_dependencies():
    """扫描 Java 相关依赖"""
    items = []

    # JDK/JRE 版本信息
    if cmd_exists("java"):
        stdout, stderr, rc = run_cmd(["java", "-version"])
        # java -version 输出到 stderr
        ver_text = stderr if stderr else stdout
        if ver_text:
            match = re.search(r'version "(.+?)"', ver_text)
            if match:
                items.append({
                    "language": "Java",
                    "name": "JDK/JRE",
                    "version": match.group(1),
                    "source": "java -version",
                    "environment": "system",
                })

    # Maven 本地仓库扫描
    m2_repo = Path.home() / ".m2" / "repository"
    if m2_repo.exists():
        items.extend(_scan_maven_repo(m2_repo))

    return items


def _scan_maven_repo(repo_path, max_items=5000):
    """遍历 Maven 本地仓库目录结构，解析 GAV 坐标"""
    items = []
    count = 0
    try:
        for pom in repo_path.rglob("*.pom"):
            if count >= max_items:
                break
            try:
                # 目录结构: groupId_path/artifactId/version/artifactId-version.pom
                version_dir = pom.parent
                version = version_dir.name
                artifact_dir = version_dir.parent
                artifact_id = artifact_dir.name

                # groupId 是 artifact_dir 之上到 repo_path 的路径
                rel = artifact_dir.parent.relative_to(repo_path)
                group_id = str(rel).replace(os.sep, ".")

                items.append({
                    "language": "Java",
                    "name": f"{group_id}:{artifact_id}",
                    "version": version,
                    "source": "maven-local-repo",
                    "environment": str(repo_path),
                })
                count += 1
            except (ValueError, IndexError):
                continue
    except PermissionError:
        pass
    return items


# ============================================================
# Node.js 包扫描器
# ============================================================

def scan_nodejs_packages():
    """扫描 Node.js 全局安装的包"""
    items = []

    if not cmd_exists("npm"):
        return items

    # Node.js 版本
    if cmd_exists("node"):
        stdout, _, rc = run_cmd(["node", "--version"])
        if rc == 0 and stdout:
            items.append({
                "language": "Node.js",
                "name": "node",
                "version": stdout.strip().lstrip("v"),
                "source": "node --version",
                "environment": "system",
            })

    # npm 全局包
    stdout, _, rc = run_cmd(["npm", "list", "-g", "--json", "--depth=0"])
    if rc in (0, 1) and stdout:  # npm list 有警告时返回 1
        try:
            data = json.loads(stdout)
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                items.append({
                    "language": "Node.js",
                    "name": name,
                    "version": info.get("version", "未知"),
                    "source": "npm-global",
                    "environment": "global",
                })
        except (json.JSONDecodeError, TypeError):
            pass

    # yarn 全局包
    if cmd_exists("yarn"):
        stdout, _, rc = run_cmd(["yarn", "global", "list", "--depth=0"])
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                match = re.match(r'info "(.+?)@(.+?)"', line)
                if match:
                    items.append({
                        "language": "Node.js",
                        "name": match.group(1),
                        "version": match.group(2),
                        "source": "yarn-global",
                        "environment": "global",
                    })

    return items


# ============================================================
# Go 模块扫描器
# ============================================================

def scan_go_modules():
    """扫描 Go 模块缓存"""
    items = []

    if not cmd_exists("go"):
        return items

    # Go 版本
    stdout, _, rc = run_cmd(["go", "version"])
    if rc == 0 and stdout:
        match = re.search(r'go(\d+\.\d+\.?\d*)', stdout)
        if match:
            items.append({
                "language": "Go",
                "name": "go",
                "version": match.group(1),
                "source": "go version",
                "environment": "system",
            })

    # 模块缓存目录
    gopath = os.environ.get("GOPATH", str(Path.home() / "go"))
    mod_cache = Path(gopath) / "pkg" / "mod"
    if mod_cache.exists():
        try:
            # 遍历模块缓存，查找顶级模块目录
            count = 0
            for d in sorted(mod_cache.rglob("*")):
                if count >= 3000:
                    break
                if d.is_dir() and "@v" in d.name:
                    # 目录名格式: module@vX.Y.Z
                    parts = d.name.rsplit("@", 1)
                    if len(parts) == 2:
                        mod_name = parts[0]
                        mod_ver = parts[1]
                        rel_path = str(d.parent.relative_to(mod_cache))
                        full_name = f"{rel_path}/{mod_name}".replace(os.sep, "/")
                        items.append({
                            "language": "Go",
                            "name": full_name,
                            "version": mod_ver,
                            "source": "go-mod-cache",
                            "environment": str(mod_cache),
                        })
                        count += 1
        except (PermissionError, ValueError):
            pass

    return items


# ============================================================
# Rust 包扫描器
# ============================================================

def scan_rust_packages():
    """扫描 Rust cargo 安装的包"""
    items = []

    if not cmd_exists("cargo"):
        return items

    # Rust 版本
    if cmd_exists("rustc"):
        stdout, _, rc = run_cmd(["rustc", "--version"])
        if rc == 0 and stdout:
            match = re.search(r'rustc (\S+)', stdout)
            if match:
                items.append({
                    "language": "Rust",
                    "name": "rustc",
                    "version": match.group(1),
                    "source": "rustc --version",
                    "environment": "system",
                })

    # cargo install 的包
    stdout, _, rc = run_cmd(["cargo", "install", "--list"])
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            # 格式: package_name vX.Y.Z:
            match = re.match(r'^(\S+)\s+v(\S+):?$', line)
            if match:
                items.append({
                    "language": "Rust",
                    "name": match.group(1),
                    "version": match.group(2),
                    "source": "cargo-install",
                    "environment": "global",
                })

    return items


# ============================================================
# CSV 报告生成器
# ============================================================

def write_os_csv(filepath, items):
    """写入系统软件 CSV"""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        f.write(CSV_BOM)
        writer = csv.writer(f)
        writer.writerow(["序号", "软件名称", "版本", "来源", "安装路径", "发布者", "安装日期"])
        for idx, item in enumerate(items, 1):
            writer.writerow([
                idx, item["name"], item["version"], item["source"],
                item["install_path"], item["publisher"], item["install_date"],
            ])


def write_deps_csv(filepath, items):
    """写入语言依赖包 CSV"""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        f.write(CSV_BOM)
        writer = csv.writer(f)
        writer.writerow(["序号", "语言", "包名称", "版本", "来源", "所属环境"])
        for idx, item in enumerate(items, 1):
            writer.writerow([
                idx, item["language"], item["name"],
                item["version"], item["source"], item["environment"],
            ])


# ============================================================
# 主函数
# ============================================================

def main():
    # 基本信息
    hostname = socket.gethostname()
    sys_name, os_ver = get_os_info()
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    print_banner(hostname, os_ver, scan_time)

    # 获取程序所在的物理目录（兼容打包后的 .exe）
    if getattr(sys, 'frozen', False):
        # 如果是打包后的环境 (.exe)
        current_dir = Path(sys.executable).parent.resolve()
    else:
        # 如果是直接运行脚本
        current_dir = Path(sys.argv[0]).parent.resolve()
    
    report_dir = current_dir / "reports"
    report_dir.mkdir(exist_ok=True)

    # ---- 系统软件扫描 ----
    print("  正在扫描系统软件...")
    os_items = scan_os_software()
    print_result("系统软件扫描完成", len(os_items))

    # ---- 语言依赖包扫描 ----
    all_deps = []

    # Python
    print("  正在扫描 Python 包...")
    py_items = scan_python_packages()
    all_deps.extend(py_items)
    if py_items:
        print_result("Python 包扫描完成", len(py_items))
    else:
        print_result("Python 包扫描", 0, skipped=not cmd_exists("python3") and not cmd_exists("python"),
                     reason="未安装 Python" if not cmd_exists("python3") and not cmd_exists("python") else "无包")

    # Java
    print("  正在扫描 Java 依赖...")
    java_items = scan_java_dependencies()
    all_deps.extend(java_items)
    if java_items:
        print_result("Java 依赖扫描完成", len(java_items))
    else:
        has_java = cmd_exists("java")
        print_result("Java 依赖扫描", 0, skipped=not has_java, reason="未安装 Java")

    # Node.js
    print("  正在扫描 Node.js 包...")
    node_items = scan_nodejs_packages()
    all_deps.extend(node_items)
    if node_items:
        print_result("Node.js 包扫描完成", len(node_items))
    else:
        print_result("Node.js 包扫描", 0, skipped=not cmd_exists("npm"), reason="未安装 npm")

    # Go
    print("  正在扫描 Go 模块...")
    go_items = scan_go_modules()
    all_deps.extend(go_items)
    if go_items:
        print_result("Go 模块扫描完成", len(go_items))
    else:
        print_result("Go 模块扫描", 0, skipped=not cmd_exists("go"), reason="未安装 Go")

    # Rust
    print("  正在扫描 Rust 包...")
    rust_items = scan_rust_packages()
    all_deps.extend(rust_items)
    if rust_items:
        print_result("Rust 包扫描完成", len(rust_items))
    else:
        print_result("Rust 包扫描", 0, skipped=not cmd_exists("cargo"), reason="未安装 Cargo")

    # ---- 生成 CSV 报告 ----
    os_csv = report_dir / f"{hostname}_系统软件_{date_tag}.csv"
    deps_csv = report_dir / f"{hostname}_语言依赖包_{date_tag}.csv"

    if os_items:
        write_os_csv(str(os_csv), os_items)
    if all_deps:
        write_deps_csv(str(deps_csv), all_deps)

    # ---- 打印摘要 ----
    total = len(os_items) + len(all_deps)
    print()
    print("=" * 50)
    print(f"  扫描完成！共发现 {total} 个软件/依赖")
    if os_items:
        print(f"  → {os_csv}")
    if all_deps:
        print(f"  → {deps_csv}")
    if total == 0:
        print("  （未发现任何软件信息）")
    print("=" * 50)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n已取消扫描。")
        sys.exit(1)
    except Exception as e:
        print(f"\n[错误] 扫描过程中发生异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
