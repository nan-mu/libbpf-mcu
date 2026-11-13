#!/usr/bin/env python3
"""P4 exec-ingress demonstration on examples/exec_bench (NOT the RX path).

exec_bench leases an image and runs it on a 32-byte carrier map (`workload`):
opcode u32 @0, param u32 @4, payload 24 bytes @8. `enable exec` runs the program
once; the host waits for `OK finish`. This is the map-driven function-call
datapath, used here for the bitswap exec workload, which is not an RX program.

Limitation recorded honestly: the agent's update/map writes only a u64 into an
ARRAY slot, so bytes 8..32 (the payload) seed to zero. bitswap then bit-reverses
0 -> 0; this proves the JIT exec image leases and executes through the carrier
and returns PASS, but it cannot distinguish a correct bit-reverse from a no-op.
Bit-reverse correctness was verified host-side by the independent oracle
(jit/oracle), not here.

Requires exec_bench firmware + the image installed:
  POST /v1/flash/fw {"name":"exec-bench-aot"}
  POST /v1/clear/xdp {"name":"*"}
  POST /v1/flash/xdp {"name":"jit_bitswap"}   (or "bitswap" for the AOT control)

Usage: p4_exec.py <image> <tag> [param]
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4_drive as d


def main():
    image, tag = sys.argv[1], sys.argv[2]
    param = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    out = os.path.join(d.REPORTS, tag)
    os.makedirs(out, exist_ok=True)
    t0 = d.now_ms()
    rec = {"image": image, "tag": tag, "param": param,
           "path": "exec-ingress (exec_bench), NOT RX"}

    # opcode=0, param=param -> u64 LE = param << 32. Payload bytes 8..32 = 0.
    carrier = param << 32
    rec["seed"] = d.map_op("/v1/update/map/workload",
                           {"key": "0", "value": str(carrier)}).get("message")
    rec["workload_before"] = d.map_get("workload")
    d.post("/v1/clear/perf")
    perf_before = d.perf_counters()

    rec["enable_exec"] = d.post("/v1/enable/exec").get("message")
    rec["get_finish"] = d.post("/v1/get/finish").get("message")
    time.sleep(0.3)
    rec["workload_after"] = d.map_get("workload")
    perf_after = d.perf_counters()
    if ("error" not in perf_before and "error" not in perf_after
            and isinstance(perf_before, dict) and isinstance(perf_after, dict)):
        rec["perf_delta"] = {k: perf_after.get(k, 0) - perf_before.get(k, 0)
                             for k in perf_after
                             if perf_after.get(k, 0) != perf_before.get(k, 0)}
    else:
        rec["perf"] = "unavailable (exec_bench built without perf features)"
    rec["serial"] = d.serial(t0)
    open(os.path.join(out, "serial.log"), "w").write(rec["serial"])
    json.dump(rec, open(os.path.join(out, "exec.json"), "w"), indent=2)

    print(f"=== {tag} ({image}) exec-ingress ===")
    print("seed:", rec["seed"])
    print("enable_exec:", rec["enable_exec"])
    print("get_finish:", rec["get_finish"])
    print("workload_after:", rec["workload_after"])
    pd = rec.get("perf_delta", {})
    print("perf delta:", {k: pd[k] for k in
                          ["xdp_invocations", "xdp_pass", "xdp_aborted",
                           "runtime_errors", "bad_md", "helper_unresolved"] if k in pd})


if __name__ == "__main__":
    main()