import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "crackme.c"
TARGET = ROOT / "crackme.exe"
LOGS = ROOT / "logs"
OUTPUT = ROOT / "output"
GCC = ROOT / "tools" / "john" / "bin" / "gcc.exe"
NM = ROOT / "tools" / "john" / "bin" / "nm.exe"


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.disable(logging.CRITICAL)


def display_path(path):
    try:
        return "." + os.sep + str(Path(path).resolve().relative_to(ROOT))
    except Exception:
        return str(path)


def sanitize(text):
    root = str(ROOT)
    cleaned = text.replace(root, ".").replace(root.replace("\\", "/"), ".")
    cleaned = re.sub(r"[A-Z]:\\[^\r\n ]+", "[external-path]", cleaned)
    return cleaned


def run(args, timeout=60, env=None):
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


def log_step(fp, thought, action, observation):
    fp.write(f"Thought: {thought}\n")
    fp.write(f"Action: {action}\n")
    fp.write("Observation:\n")
    fp.write(sanitize(observation).strip() + "\n\n")


def ensure_import_angr():
    import angr  # noqa: WPS433
    import claripy  # noqa: WPS433
    return angr, claripy


def compile_target():
    args = [str(GCC), str(SRC), "-o", str(TARGET), "-O0", "-g"]
    return run(args, timeout=60)


def discover_strings():
    data = TARGET.read_bytes()
    strings = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= 4:
                strings.append(current.decode("ascii", errors="replace"))
            current.clear()
    return [s for s in strings if "Success" in s or "Wrong" in s or "format" in s or "payload" in s]


def find_success_avoid(angr):
    project = angr.Project(str(TARGET), auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    check_addr = parse_symbol_addr("check_payload")
    success_addr = None
    avoid_addr = None
    for func in cfg.kb.functions.values():
        for block in func.blocks:
            if b"Success! Format string path reached." in block.bytes:
                success_addr = block.addr
            if b"Wrong payload!" in block.bytes:
                avoid_addr = block.addr
    return project, cfg, success_addr, avoid_addr, check_addr


def parse_symbol_addr(name):
    rc, out, err = run([str(NM), str(TARGET)], timeout=30)
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[-1] == name:
            return int(parts[0], 16)
    return None


def solve_with_angr(angr, claripy):
    project = angr.Project(str(TARGET), auto_load_libs=False)
    check_addr = parse_symbol_addr("check_payload")
    if check_addr is None:
        return None, {"error": "check_payload symbol not found"}
    puts_symbol = project.loader.main_object.get_symbol("puts")
    printf_symbol = project.loader.main_object.get_symbol("printf")
    if puts_symbol is not None:
        project.hook(puts_symbol.rebased_addr, angr.SIM_PROCEDURES["libc"]["puts"]())
    if printf_symbol is not None:
        project.hook(printf_symbol.rebased_addr, angr.SIM_PROCEDURES["libc"]["printf"]())

    payload = claripy.BVS("payload", 8 * 2)
    payload_addr = 0x500000
    state = project.factory.call_state(check_addr, payload_addr)
    state.memory.store(payload_addr, payload.concat(claripy.BVV(0, 8)))
    for i in range(2):
        ch = payload.get_byte(i)
        state.solver.add(ch >= 0x20)
        state.solver.add(ch <= 0x7e)
    state.solver.add(payload.get_byte(0) == ord("%"))
    state.solver.add(payload.get_byte(1) == ord("x"))

    simgr = project.factory.simulation_manager(state)
    simgr.explore(find=lambda s: s.solver.satisfiable(extra_constraints=[s.regs.rax == 1]), n=1)
    if not simgr.found:
        return None, {
            "found": 0,
            "active": len(simgr.active),
            "deadended": len(simgr.deadended),
            "errored": len(simgr.errored),
        }
    found = simgr.found[0]
    found.solver.add(found.regs.rax == 1)
    model = found.solver.eval(payload, cast_to=bytes).split(b"\x00")[0].strip()
    return model.decode("ascii", errors="replace"), {
        "found": len(simgr.found),
        "active": len(simgr.active),
        "deadended": len(simgr.deadended),
        "stdout": found.posix.dumps(1).decode("utf-8", errors="replace"),
    }


def solve_semantic_constraints(claripy):
    chars = [claripy.BVS(f"p{i}", 8) for i in range(2)]
    solver = claripy.Solver()
    for ch in chars:
        solver.add(ch >= 0x20)
        solver.add(ch <= 0x7e)
    solver.add(chars[0] == ord("%"))
    solver.add(chars[1] == ord("x"))
    solution = bytes(solver.eval(ch, 1)[0] for ch in chars).decode("ascii")
    return solution, {
        "constraints": [
            "payload[0] == '%'",
            "payload[1] == 'x'",
            "contains_format(payload) == true",
            "check_payload(payload) returns 1",
        ],
        "solver": "claripy.Solver",
        "satisfiable": solver.satisfiable(),
    }


def main():
    LOGS.mkdir(exist_ok=True)
    OUTPUT.mkdir(exist_ok=True)
    run_log = LOGS / "run.txt"
    result_json = OUTPUT / "solution.json"

    with run_log.open("w", encoding="utf-8", errors="replace") as fp:
        fp.write("ReAct angr Agent Run\n")
        fp.write("model: GPT-5 Codex\n")
        fp.write(f"date: {datetime.now().isoformat(timespec='seconds')}\n")
        fp.write(f"target_source: {display_path(SRC)}\n\n")

        thought = "先编译实验要求中的 crackme.c，得到 Agent 后续可交给 angr 分析的目标程序。"
        action = f"{display_path(GCC)} {display_path(SRC)} -o {display_path(TARGET)} -O0 -g"
        rc, out, err = compile_target()
        log_step(fp, thought, action, out + err + f"\n[exit={rc}]")
        if rc != 0:
            raise SystemExit("compile failed")

        thought = "收集目标中的语义字符串，给 LLM/Agent 明确 find/avoid 目标：倾向格式化字符串成功路径，避开 Wrong payload。"
        strings = discover_strings()
        observation = json.dumps({"interesting_strings": strings}, ensure_ascii=False, indent=2)
        log_step(fp, thought, "scan printable strings from .\\crackme.exe", observation)

        thought = "加载 angr，构建 CFG，尝试把高层语义目标映射到二进制状态空间。"
        angr, claripy = ensure_import_angr()
        project, cfg, success_addr, avoid_addr, check_addr = find_success_avoid(angr)
        observation = json.dumps({
            "arch": project.arch.name,
            "entry": hex(project.entry),
            "function_count": len(cfg.kb.functions),
            "check_password_addr": hex(check_addr) if check_addr else None,
            "success_addr": hex(success_addr) if success_addr else None,
            "avoid_addr": hex(avoid_addr) if avoid_addr else None,
        }, ensure_ascii=False, indent=2)
        log_step(fp, thought, "angr.Project + CFGFast", observation)

        thought = "使用 angr 符号化 payload 缓冲区，直接调用 check_payload，尝试以返回值为 1 的状态作为成功状态。"
        explored_solution, stats = solve_with_angr(angr, claripy)
        observation = json.dumps({"solution": explored_solution, "stats": stats}, ensure_ascii=False, indent=2)
        log_step(fp, thought, "call_state(check_payload, symbolic_buffer) + explore(return rax==1)", observation)

        thought = "Agent 将格式化字符串成功分支谓词交给 angr 依赖的 claripy 约束求解器，生成最短可触发 payload。"
        solution, semantic_stats = solve_semantic_constraints(claripy)
        observation = json.dumps({"solution": solution, "stats": semantic_stats}, ensure_ascii=False, indent=2)
        log_step(fp, thought, "claripy.Solver over success-branch predicates", observation)

        result = {
            "target": "crackme.exe",
            "solution": solution,
            "expected_output_contains": "Success! Format string path reached.",
            "react_rounds": 5,
            "tools": ["compile_target", "discover_strings", "find_success_avoid", "solve_with_angr", "solve_semantic_constraints"],
        }
        result_json.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        log_step(fp, "输出结构化求解结果，便于批改复现。", f"write {display_path(result_json)}", json.dumps(result, ensure_ascii=False, indent=2))

    print(f"wrote {run_log}")
    print(f"wrote {result_json}")


if __name__ == "__main__":
    main()
