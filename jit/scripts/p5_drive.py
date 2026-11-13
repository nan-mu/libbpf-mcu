#!/usr/bin/env python3
"""P5 four-arm MCU per-execution measurement on exec_bench (raw UART).

Arms: XPOST AOT, JIT, rBPF, HAL. AOT and JIT share the exec-bench-aot firmware
and differ only in the cold-table container; rBPF uses the interp firmware with
bytecode containers; HAL uses exec_bench_hal with no XDP runtime.

Primary signal: the firmware's `exec seg: ... engine=<us> ...` line, one sample
per `enable exec` (XDP arms), or the `execution` perf aggregate delta per
`enable exec` (HAL). Both are single-flight times on the 1 us device clock.
`--diag` additionally runs the firmware's own 2000-run batch (`bench runs=2000
mean_ns=`) as a high-resolution cross-check of the single-flight medians.

Every workload's output map value is compared against a host-side reference
computed from the same input, so a sample only counts when the program ran and
produced the right bytes.

Run with /usr/bin/python3 (pyserial). Evidence: jit/reports/p5/<tag>/.

Usage:
  p5_drive.py run <aot|jit|rbpf|hal> [--workloads a,b|all] [--reps N]
                  [--diag] [--tag T] [--no-flash]
  p5_drive.py matrix [--reps N] [--hal-reps N] [--tag T]
  p5_drive.py summarize <tag>
"""
import argparse
import json
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

import serial

PORT = "/dev/cu.usbmodem21101"
TABLE = "0x310000"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BUILD = ROOT / "build" / "p5"
REPORTS = ROOT / "jit" / "reports" / "p5"

FW = {
    "aot": BUILD / "fw" / "exec_bench_aot",
    "jit": BUILD / "fw" / "exec_bench_aot",
    "rbpf": BUILD / "fw" / "exec_bench_rbpf",
    "hal": BUILD / "fw" / "exec_bench_hal",
}
DIAG_FW = {
    "aot": BUILD / "fw" / "exec_bench_aot_diag",
    "jit": BUILD / "fw" / "exec_bench_aot_diag",
    "rbpf": BUILD / "fw" / "exec_bench_rbpf_diag",
    "hal": BUILD / "fw" / "exec_bench_hal_diag",
}
CONTAINER = {
    "aot": BUILD / "aot",
    "jit": BUILD / "jit",
    "rbpf": BUILD / "rbpf",
}

# Input fixtures from xpost-test/scripts/interp_exec_bench.py, with one change:
# bitswap param 0 -> 1. The current bitswap.c treats param as a batch count and
# refuses 0 (XDP_ABORTED); its source comment says the comparison runs at batch
# one. Every arm gets the identical 32-byte input.
FIXTURES = {
    "incr": "0000000000000000000000000000000000000000000000000000000000000000",
    "square": "0100000000000000030000000000000000000000000000000000000000000000",
    "bitswap": "02000000010000005a5aa5a50000000000000000000000000000000000000000",
    "fib": "030000001e000000000000000000000000000000000000000000000000000000",
    "buf": "0400000010000000031425364758697a8b9cadbecfe0f1020000000000000000",
    "memcpy": "0500000008000000031425364758697a00000000000000000000000000000000",
    "fletcher32": "0600000010000000031425364758697a8b9cadbecfe0f1020000000000000000",
    "bsort": "07000000060000009d601517e4e6dd782b6da6da72f36e3cb979379e00000000",
}
ORDER = ["incr", "square", "bitswap", "fib", "buf", "memcpy", "fletcher32", "bsort"]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEG = re.compile(
    r"exec seg: load=(\d+) lease=(\d+) engine=(\d+) release=(\d+) store=(\d+) total=(\d+)"
)
BENCH = re.compile(r"bench runs=(\d+) mean_ns=(\d+) act=(\S+)")
SWEEP = re.compile(r"sweep (?:wl=(\w+) )?op=(\d+) param=(\d+) runs=(\d+) mean_ns=(\d+)")


def u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


def put32(b, off, v):
    b[off:off + 4] = (v & 0xFFFFFFFF).to_bytes(4, "little")


def reverse_bits32(x):
    r = 0
    for _ in range(32):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def fib32(n):
    if n == 0:
        return 0
    a, b = 0, 1
    for _ in range(1, n):
        a, b = b, (a + b) & 0xFFFFFFFF
    return b


def fletcher32(data):
    sum1 = sum2 = 0xFFFF
    i, n = 0, len(data)
    while n > 1:
        words = min(n // 2, 360)
        n -= words * 2
        for _ in range(words):
            w = data[i] | (data[i + 1] << 8)
            i += 2
            sum1 += w
            sum2 += sum1
        sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
    if n:
        sum1 += data[i]
        sum2 += sum1
        sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
    sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
    return ((sum2 << 16) | sum1) & 0xFFFFFFFF


def expected_output(name, inp):
    """Host reference for the 32-byte output value, mirroring tests/xdp/<name>.c
    and exec_bench_hal::run_hal. Header (opcode, param) passes through."""
    b = bytearray(inp)
    p = 8
    param = u32(b, 4)
    if name == "incr":
        put32(b, p, u32(b, p) + 1)
    elif name == "square":
        put32(b, p, u32(b, p) * u32(b, p))
    elif name == "bitswap":
        x = u32(b, p)
        for _ in range(max(param, 1)):
            x = reverse_bits32(x)
        put32(b, p, x)
    elif name == "fib":
        put32(b, p, fib32(min(param, 47)))
    elif name == "buf":
        acc = 0
        for i in range(param):
            b[p + i] = (b[p + i] + i) & 0xFF
            acc = (acc + b[p + i]) & 0xFFFFFFFF
        put32(b, p + param, acc)
    elif name == "memcpy":
        b[p + param:p + 2 * param] = b[p:p + param]
    elif name == "fletcher32":
        put32(b, p + param, fletcher32(bytes(b[p:p + param])))
    elif name == "bsort":
        words = sorted(u32(b, p + 4 * i) for i in range(param))
        for i, w in enumerate(words):
            put32(b, p + 4 * i, w)
    else:
        raise ValueError(name)
    return bytes(b)


def run_cmd(argv):
    res = subprocess.run(argv, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"{' '.join(argv[:3])}: {res.stderr.decode('utf-8', 'replace')[:300]}"
        )
    return res.stdout.decode("utf-8", "replace")


def flash_firmware(path):
    run_cmd(["espflash", "flash", "--port", PORT, str(path)])


def flash_container(path):
    run_cmd(["espflash", "write-bin", "--port", PORT, TABLE, str(path)])


class Board:
    def __init__(self):
        self.ser = serial.Serial(PORT, 115200, timeout=0.2)
        self.log = bytearray()

    def close(self):
        self.ser.close()

    def reset(self):
        self.ser.dtr = False
        self.ser.rts = True
        time.sleep(0.2)
        self.ser.rts = False
        time.sleep(0.8)

    def read_for(self, seconds):
        end = time.time() + seconds
        buf = bytearray()
        while time.time() < end:
            data = self.ser.read(8192)
            if data:
                buf += data
        self.log += buf
        return ANSI.sub("", buf.decode("utf-8", "replace"))

    def read_until(self, marker, timeout):
        end = time.time() + timeout
        buf = bytearray()
        while time.time() < end:
            data = self.ser.read(8192)
            if data:
                buf += data
                if marker in ANSI.sub("", buf.decode("utf-8", "replace")):
                    break
        self.log += buf
        return ANSI.sub("", buf.decode("utf-8", "replace"))

    def command(self, line, marker, timeout=5.0):
        self.ser.write((line + "\n").encode())
        return self.read_until(marker, timeout)

    def boot_xdp(self):
        self.reset()
        text = self.read_until("xdp switched, not leased", 15.0)
        ok = "xdp switched, not leased" in text
        if not ok:
            text += self.read_for(2.0)
        return ok, text

    def boot_hal(self):
        self.reset()
        text = self.read_until("OK init", 15.0)
        return "OK init" in text, text

    def seed(self, name, value_hex):
        text = self.command(f"update map workload 0 {value_hex}", "OK update map")
        return "OK update map" in text

    def read_blob(self, prefix, timeout=10.0):
        """Read `<prefix><len>\n` then exactly len raw bytes."""
        end = time.time() + timeout
        buf = bytearray()
        pb = prefix.encode()
        while time.time() < end:
            data = self.ser.read(8192)
            if data:
                buf += data
                idx = buf.find(pb)
                if idx >= 0:
                    nl = buf.find(b"\n", idx + len(pb))
                    if nl >= 0:
                        head = buf[idx + len(pb):nl]
                        try:
                            n = int(head)
                        except ValueError:
                            self.log += buf
                            return None
                        raw = buf[nl + 1:]
                        while len(raw) < n and time.time() < end:
                            chunk = self.ser.read(min(8192, n - len(raw)))
                            if chunk:
                                raw += chunk
                        self.log += buf[:nl + 1] + raw[:n]
                        return bytes(raw[:n]) if len(raw) >= n else None
        self.log += buf
        return None

    def get_map(self):
        return self.get_map_named("workload")

    def get_map_named(self, name):
        self.ser.write(f"get map {name}\n".encode())
        raw = self.read_blob("OK get map ")
        if raw is None:
            return None
        text = raw.decode("utf-8", "replace")
        lines = text.splitlines()
        entries = {}
        if lines and lines[0].startswith("array"):
            for i, line in enumerate(lines[1:]):
                tok = line.split()
                try:
                    if len(tok) >= 2:
                        entries[tok[0]] = int(tok[1]).to_bytes(8, "little")
                    elif tok:
                        entries[str(i)] = int(tok[0]).to_bytes(8, "little")
                except ValueError:
                    pass
            return entries
        for line in lines[1:]:
            tok = line.split()
            if len(tok) >= 2:
                try:
                    key = str(int(tok[0], 16))
                    entries[key] = bytes.fromhex("".join(tok[1:]))
                except ValueError:
                    pass
        return entries

    def get_perf_agg(self):
        """Decode the HAL `execution` aggregate (count, total_us, min, max)."""
        self.ser.write(b"get perf\n")
        raw = self.read_blob("OK get perf ")
        if raw is None or len(raw) < 360 + 32:
            return None
        off = 184 + 176  # counters + one aggregate slot (execution)
        count, total, mn, mx = (
            int.from_bytes(raw[off + 8 * i:off + 8 * i + 8], "little") for i in range(4)
        )
        return {"count": count, "total": total, "min": mn, "max": mx}


def measure_xdp(board, arm, name, reps, diag):
    container = CONTAINER[arm] / f"{name}.elf"
    rec = {
        "arm": arm, "workload": name, "diag": diag,
        "firmware": str(DIAG_FW[arm] if diag else FW[arm]),
        "container": str(container),
        "reps_requested": reps, "samples_us": [], "seg": [],
        "errors": [], "bench": None, "sweep": [],
    }
    if not container.exists():
        err = container.with_suffix(".pack.err")
        rec["status"] = "NOT_MEASURED"
        rec["reason"] = (err.read_text().strip() if err.exists()
                         else "container missing")
        rec["output"] = {"expected_hex": None, "got_hex": None, "match": None}
        return rec
    flash_container(container)
    ok, boot = board.boot_xdp()
    rec["boot_ok"] = ok
    rec["boot_log"] = boot
    if not ok:
        rec["errors"].append({"stage": "boot", "detail": boot[-400:]})
        return rec
    if not board.seed(name, FIXTURES[name]):
        rec["errors"].append({"stage": "seed"})
        return rec
    timeout = 120.0 if diag else 5.0
    for i in range(reps):
        text = board.command("enable exec", "OK finish", timeout)
        seg = SEG.findall(text)
        if "OK finish" not in text or not seg:
            rec["errors"].append({"i": i, "window": text[-400:]})
            continue
        vals = [int(x) for x in seg[-1]]
        rec["seg"].append(dict(zip(
            ["load", "lease", "engine", "release", "store", "total"], vals)))
        rec["samples_us"].append(vals[2])
        if diag:
            b = BENCH.search(text)
            if b:
                rec["bench"] = {"runs": int(b.group(1)),
                                "mean_ns": int(b.group(2)), "act": b.group(3)}
            rec["sweep"] = [
                {"wl": m.group(1), "op": int(m.group(2)), "param": int(m.group(3)),
                 "runs": int(m.group(4)), "mean_ns": int(m.group(5))}
                for m in SWEEP.finditer(text)
            ]
    entries = board.get_map()
    rec["output"] = check_output(name, entries)
    return rec


def measure_hal(board, name, reps, diag):
    rec = {
        "arm": "hal", "workload": name, "diag": diag,
        "firmware": str(DIAG_FW["hal"] if diag else FW["hal"]),
        "container": None, "reps_requested": reps,
        "samples_us": [], "errors": [], "bench": None,
    }
    if not board.seed(name, FIXTURES[name]):
        rec["errors"].append({"stage": "seed"})
        return rec
    prev = board.get_perf_agg()
    if prev is None:
        rec["errors"].append({"stage": "perf-baseline"})
        return rec
    timeout = 120.0 if diag else 5.0
    for i in range(reps):
        text = board.command("enable exec", "OK finish", timeout)
        if "OK finish" not in text:
            rec["errors"].append({"i": i, "window": text[-400:]})
            continue
        cur = board.get_perf_agg()
        if cur is None:
            rec["errors"].append({"i": i, "stage": "perf"})
            continue
        dc = cur["count"] - prev["count"]
        dt = cur["total"] - prev["total"]
        if dc != 1:
            rec["errors"].append({"i": i, "stage": "agg", "dc": dc})
        else:
            rec["samples_us"].append(dt)
        prev = cur
        if diag:
            b = BENCH.search(text)
            if b:
                rec["bench"] = {"runs": int(b.group(1)),
                                "mean_ns": int(b.group(2)), "act": b.group(3)}
    entries = board.get_map()
    rec["output"] = check_output(name, entries)
    return rec


def check_output(name, entries):
    exp = expected_output(name, bytes.fromhex(FIXTURES[name]))
    got = entries.get("1") if entries else None
    return {
        "expected_hex": exp.hex(),
        "got_hex": got.hex() if got else None,
        "match": got == exp,
    }


def stats(samples):
    if not samples:
        return None
    s = sorted(samples)
    return {
        "n": len(s), "min": s[0], "median": statistics.median(s),
        "mean": round(statistics.mean(s), 2),
        "p90": s[int(0.9 * (len(s) - 1))], "max": s[-1],
    }


def save(rec, tag):
    d = REPORTS / tag
    d.mkdir(parents=True, exist_ok=True)
    stem = f"{rec['arm']}__{rec['workload']}" + ("__diag" if rec["diag"] else "")
    if rec.get("pass"):
        stem += f"__p{rec['pass']}"
    (d / f"{stem}.json").write_text(json.dumps(rec, indent=2))
    st = stats(rec["samples_us"])
    out = rec.get("output") or {}
    bench = rec.get("bench")
    print(
        f"{rec['arm']:5s} {rec['workload']:11s} n={len(rec['samples_us']):3d} "
        f"err={len(rec['errors']):2d} stats={st} "
        f"match={out.get('match')} bench={bench}",
        file=sys.stderr,
    )
    return stem


def run_arm(args):
    arm = args.arm
    workloads = ORDER if args.workloads == "all" else args.workloads.split(",")
    tag = args.tag or f"{arm}{'_diag' if args.diag else ''}"
    fw = DIAG_FW[arm] if args.diag else FW[arm]
    if not args.no_flash:
        flash_firmware(fw)
    board = Board()
    try:
        if arm == "hal":
            ok, boot = board.boot_hal()
            if not ok:
                raise SystemExit(f"HAL boot failed: {boot[-400:]}")
            for name in workloads:
                rec = measure_hal(board, name, args.reps, args.diag)
                rec["serial_log"] = save_log(board, tag, f"hal__{name}")
                save(rec, tag)
        else:
            for name in workloads:
                rec = measure_xdp(board, arm, name, args.reps, args.diag)
                rec["serial_log"] = save_log(board, tag, f"{arm}__{name}")
                save(rec, tag)
    finally:
        board.close()


def save_log(board, tag, stem):
    d = REPORTS / tag
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{stem}.serial.log"
    p.write_bytes(bytes(board.log))
    board.log = bytearray()
    return str(p)


def matrix(args):
    """Interleaved four-arm sequence. AOT and JIT alternate per workload in two
    order-balanced passes on one firmware; rBPF and HAL follow on their own
    firmware; diag variants close with the 2000-run cross-check."""
    tag = args.tag or "matrix"
    half = max(1, args.reps // 2)
    d = REPORTS / tag

    def done(stem):
        return (d / f"{stem}.json").exists()

    flash_firmware(FW["aot"])
    board = Board()
    try:
        for pass_no, order in ((1, ORDER), (2, list(reversed(ORDER)))):
            for name in order:
                for arm in (("aot", "jit") if pass_no == 1 else ("jit", "aot")):
                    stem = f"{arm}__{name}__p{pass_no}"
                    if done(stem):
                        continue
                    rec = measure_xdp(board, arm, name, half, False)
                    rec["pass"] = pass_no
                    rec["serial_log"] = save_log(board, tag, stem)
                    save(rec, tag)
    finally:
        board.close()
    for arm, reps in (("rbpf", args.reps), ("hal", args.hal_reps)):
        if all(done(f"{arm}__{n}") for n in ORDER):
            continue
        flash_firmware(FW[arm])
        board = Board()
        try:
            if arm == "hal":
                ok, boot = board.boot_hal()
                if not ok:
                    raise SystemExit(f"HAL boot failed: {boot[-400:]}")
            for name in ORDER:
                if done(f"{arm}__{name}"):
                    continue
                if arm == "hal":
                    rec = measure_hal(board, name, reps, False)
                else:
                    rec = measure_xdp(board, arm, name, reps, False)
                rec["serial_log"] = save_log(board, tag, f"{arm}__{name}")
                save(rec, tag)
        finally:
            board.close()
    for arm in ("aot", "jit", "rbpf", "hal"):
        if all(done(f"{arm}__{n}__diag") for n in ORDER):
            continue
        flash_firmware(DIAG_FW[arm])
        board = Board()
        try:
            if arm == "hal":
                ok, boot = board.boot_hal()
                if not ok:
                    raise SystemExit(f"HAL diag boot failed: {boot[-400:]}")
            for name in ORDER:
                if done(f"{arm}__{name}__diag"):
                    continue
                if arm == "hal":
                    rec = measure_hal(board, name, 1, True)
                else:
                    rec = measure_xdp(board, arm, name, 1, True)
                rec["serial_log"] = save_log(board, tag, f"{arm}__{name}__diag")
                save(rec, tag)
        finally:
            board.close()


HELPER_FIXTURE = "0800000000000000080000000000000000000000000000000000000000000000"


def helper(args):
    """helper_loop probe: n=8 ARRAY lookups+increments per flight. Correctness
    is the counters map (each key must equal the number of flights), not the
    carrier value, which the program leaves untouched."""
    arm = args.arm
    tag = args.tag or "helper"
    fw = DIAG_FW[arm] if args.diag else FW[arm]
    container = BUILD / "helper" / f"{arm}_helper_loop.elf"
    if not args.no_flash:
        flash_firmware(fw)
    board = Board()
    try:
        flash_container(container)
        ok, boot = board.boot_xdp()
        rec = {"arm": arm, "workload": "helper_loop", "diag": args.diag,
               "firmware": str(fw), "container": str(container),
               "reps_requested": args.reps, "samples_us": [], "seg": [],
               "errors": [], "bench": None, "boot_ok": ok, "boot_log": boot}
        if not ok:
            rec["errors"].append({"stage": "boot", "detail": boot[-400:]})
            save(rec, tag)
            return
        if not board.seed("helper_loop", HELPER_FIXTURE):
            rec["errors"].append({"stage": "seed"})
            save(rec, tag)
            return
        board.command("clear map counters", "OK clear map")
        timeout = 120.0 if args.diag else 5.0
        for i in range(args.reps):
            text = board.command("enable exec", "OK finish", timeout)
            seg = SEG.findall(text)
            if "OK finish" not in text or not seg:
                rec["errors"].append({"i": i, "window": text[-400:]})
                continue
            vals = [int(x) for x in seg[-1]]
            rec["seg"].append(dict(zip(
                ["load", "lease", "engine", "release", "store", "total"], vals)))
            rec["samples_us"].append(vals[2])
            if args.diag:
                b = BENCH.search(text)
                if b:
                    rec["bench"] = {"runs": int(b.group(1)),
                                    "mean_ns": int(b.group(2)), "act": b.group(3)}
        counters = board.get_map_named("counters")
        rec["counters"] = {k: v.hex() for k, v in (counters or {}).items()}
        expect = args.reps - len(rec["errors"])
        rec["counters_ok"] = bool(counters) and all(
            int.from_bytes(v, "little") == expect for v in counters.values()
        ) and len(counters) == 8
        wl = board.get_map()
        rec["output"] = {
            "expected_hex": HELPER_FIXTURE,
            "got_hex": wl.get("1").hex() if wl and wl.get("1") else None,
            "match": bool(wl) and wl.get("1") == bytes.fromhex(HELPER_FIXTURE),
        }
        rec["serial_log"] = save_log(board, tag, f"{arm}__helper_loop")
        save(rec, tag)
    finally:
        board.close()


def summarize(tag):
    d = REPORTS / tag
    rows = {}
    for p in sorted(d.glob("*.json")):
        rec = json.loads(p.read_text())
        key = (rec["workload"], rec["arm"])
        st = stats(rec["samples_us"])
        entry = rows.setdefault(key, {"samples": [], "errors": 0, "match": None,
                                      "bench_ns": None, "diag_seg": None,
                                      "status": "ok", "reason": ""})
        entry["samples"] += rec["samples_us"]
        entry["errors"] += len(rec["errors"])
        if rec.get("status") == "NOT_MEASURED":
            entry["status"] = "NOT_MEASURED"
            entry["reason"] = rec.get("reason", "")
        if rec.get("output") and rec["output"].get("match") is not None:
            entry["match"] = rec["output"]["match"]
        if rec.get("diag"):
            if rec.get("bench"):
                entry["bench_ns"] = rec["bench"]["mean_ns"]
            if rec["samples_us"]:
                entry["diag_seg"] = rec["samples_us"][0]
    lines = ["workload\tarm\tn\tmin_us\tmedian_us\tp90_us\tmax_us\terrors\toutput_match\tdiag_bench_ns\tstatus\treason"]
    for (wl, arm), e in sorted(rows.items(), key=lambda kv: (ORDER.index(kv[0][0]), kv[0][1])):
        st = stats(e["samples"])
        base = f"{wl}\t{arm}"
        tail = f"\t{e['errors']}\t{e['match']}\t{e['bench_ns']}\t{e['status']}\t{e['reason']}"
        if st is None:
            lines.append(base + "\t0\t-\t-\t-\t-" + tail)
        else:
            lines.append(
                f"{base}\t{st['n']}\t{st['min']}\t{st['median']}\t{st['p90']}\t{st['max']}" + tail
            )
    out = "\n".join(lines) + "\n"
    (d / "summary.tsv").write_text(out)
    print(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("arm", choices=["aot", "jit", "rbpf", "hal"])
    r.add_argument("--workloads", default="all")
    r.add_argument("--reps", type=int, default=100)
    r.add_argument("--diag", action="store_true")
    r.add_argument("--tag")
    r.add_argument("--no-flash", action="store_true")
    m = sub.add_parser("matrix")
    m.add_argument("--reps", type=int, default=100)
    m.add_argument("--hal-reps", type=int, default=50)
    m.add_argument("--tag")
    h = sub.add_parser("helper")
    h.add_argument("arm", choices=["aot", "jit", "rbpf"])
    h.add_argument("--reps", type=int, default=100)
    h.add_argument("--diag", action="store_true")
    h.add_argument("--tag")
    h.add_argument("--no-flash", action="store_true")
    s = sub.add_parser("summarize")
    s.add_argument("tag")
    args = ap.parse_args()
    if args.cmd == "run":
        run_arm(args)
    elif args.cmd == "matrix":
        matrix(args)
    elif args.cmd == "helper":
        helper(args)
    else:
        summarize(args.tag)


if __name__ == "__main__":
    main()