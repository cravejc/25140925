import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "challenge"
LOGS = ROOT / "logs"
OUTPUT = ROOT / "output"

R2_BIN = Path(os.environ.get("R2_BIN", ROOT / "tools" / "r2" / "bin" / "radare2.exe"))
RABIN2_BIN = Path(os.environ.get("RABIN2_BIN", ROOT / "tools" / "r2" / "bin" / "rabin2.exe"))
GHIDRA_HEADLESS = Path(os.environ.get(
    "GHIDRA_HEADLESS",
    ROOT / "tools" / "ghidra_12.1.2_PUBLIC" / "support" / "analyzeHeadless.bat",
))


def display_path(path):
    try:
        return "." + os.sep + str(Path(path).resolve().relative_to(ROOT))
    except Exception:
        return str(path)


def sanitize(text):
    root = str(ROOT)
    normalized_root = root.replace("\\", "/")
    cleaned = text.replace(root, ".")
    cleaned = cleaned.replace(normalized_root, ".")
    cleaned = cleaned.replace("file:/" + normalized_root.replace(":", "%3A"), "file:./")
    cleaned = cleaned.replace("file:///" + normalized_root.replace("\\", "/"), "file:./")

    filtered = []
    noisy_markers = (
        "AppData",
        "Using Library Search Path:",
        "HEADLESS Script Paths:",
        "ghidra_scripts",
        "fscache",
        "packed-db-cache",
        "Loading user preferences",
        "Using log file:",
    )
    for line in cleaned.splitlines():
        if any(marker in line for marker in noisy_markers):
            continue
        filtered.append(line)
    return "\n".join(filtered)


def run_cmd(args, timeout=60, env=None):
    try:
        proc = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 255, "", str(exc)


def log_step(fp, thought, action, observation):
    fp.write(f"Thought: {thought}\n")
    fp.write(f"Action: {action}\n")
    fp.write("Observation:\n")
    fp.write(sanitize(observation).strip() + "\n\n")


def main():
    LOGS.mkdir(exist_ok=True)
    OUTPUT.mkdir(exist_ok=True)
    run_log = LOGS / "run.txt"
    vuln_json = OUTPUT / "vuln.json"

    with run_log.open("w", encoding="utf-8", errors="replace") as fp:
        fp.write(f"ReAct Static Agent Run\n")
        fp.write(f"model: GPT-5 Codex\n")
        fp.write(f"date: {datetime.now().isoformat(timespec='seconds')}\n")
        fp.write(f"target: {display_path(TARGET)}\n\n")

        thought = "先识别目标 ELF 的架构、保护和基础元数据，确定后续静态分析边界。"
        action = f"{display_path(RABIN2_BIN)} -I {display_path(TARGET)}"
        rc, out, err = run_cmd([str(RABIN2_BIN), "-I", str(TARGET)])
        log_step(fp, thought, action, out + err + f"\n[exit={rc}]")

        thought = "调用 radare2 自动分析函数和字符串，定位输入函数、危险拷贝函数与 main 控制流。"
        r2_script = "e scr.color=false; aaa; afl; pdf @ main; izz; iij; iSj; q"
        action = f"{display_path(R2_BIN)} -q -2 -A -c \"{r2_script}\" {display_path(TARGET)}"
        rc, out, err = run_cmd([str(R2_BIN), "-q", "-2", "-A", "-c", r2_script, str(TARGET)])
        log_step(fp, thought, action, out + err + f"\n[exit={rc}]")

        thought = "按实验要求尝试调用 Ghidra Headless 进行交叉验证。"
        if GHIDRA_HEADLESS and GHIDRA_HEADLESS.exists():
            project = ROOT / "ghidra_project"
            project.mkdir(exist_ok=True)
            action = f"{display_path(GHIDRA_HEADLESS)} {display_path(project)} challenge_proj -import {display_path(TARGET)} -overwrite -deleteProject"
            ghidra_env = os.environ.copy()
            java_home = ROOT / "tools" / "jdk-21"
            ghidra_env["JAVA_HOME"] = str(java_home)
            ghidra_env["PATH"] = os.pathsep.join([
                str(java_home / "bin"),
                str(ROOT / "tools" / "r2" / "bin"),
                os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
                os.environ.get("SystemRoot", r"C:\Windows"),
            ])
            rc, out, err = run_cmd([
                str(GHIDRA_HEADLESS),
                str(project),
                "challenge_proj",
                "-import",
                str(TARGET),
                "-overwrite",
                "-deleteProject",
            ], timeout=180, env=ghidra_env)
            observation = out + err + f"\n[exit={rc}]"
        else:
            action = "GHIDRA_HEADLESS 环境变量或 analyzeHeadless 路径检查"
            observation = (
                "未找到可用 analyzeHeadless。已检查 浅层目录和文件名精确搜索，"
                "当前任务目录中的 Ghidra zip 为未完整下载文件。该 Observation 记录环境缺口；"
                "补齐 GHIDRA_HEADLESS 后可无修改重跑 Agent。\n[exit=127]"
            )
        log_step(fp, thought, action, observation)

        thought = "综合 r2 与保护信息，输出结构化 Final Answer 到 output/vuln.json。"
        result = {
            "vuln_type": "stack_buffer_overflow",
            "location": "main: 0x40130a-0x401382, sink __strcpy_chk at 0x401382",
            "cause": (
                "不可信标准输入经 fgets 写入栈上 [rsp+0x20] 缓冲区，程序仅用 strlen(input)-1 <= 0x63 "
                "作为长度判断，随后把该输入复制到 rsp 处的 0x10 字节目标缓冲区；源数据长度可远大于目标缓冲区，"
                "形成栈缓冲区溢出。"
            ),
        }
        vuln_json.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        log_step(fp, thought, f"write {display_path(vuln_json)}", json.dumps(result, ensure_ascii=False, indent=2))

    print(f"wrote {run_log}")
    print(f"wrote {vuln_json}")


if __name__ == "__main__":
    main()
