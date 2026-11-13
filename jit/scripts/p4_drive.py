#!/usr/bin/env python3
"""P4 real-device case driver for the XPOST RX path (examples/just_xdp).

Drives one case end to end against the xpost-agent HTTP API and a real ESP32-C3
board, and records what actually happened. A reviewer reruns this file; it is
the artifact, not a transcript of manual commands.

Firmware facts this driver relies on (established on silicon, see jit/reports/p4):
- just_xdp is the RX firmware: one primary IRAM slot, cold image auto-leased at
  boot. It registers NO `xdp flash`/`xdp switch`/`get xdp status` serial handlers,
  so the slot lifecycle here is cold-install -> reset -> boot lease. The
  `/v1/xdp/switch` route is exercised separately and its rejection recorded.
- Map reads/writes return `ERR busy` while XDP is enabled (the RX path holds the
  map lock). Every map op is therefore done with XDP disabled.
- RX stimulus is UDP to 192.168.110.106:8080 from this Mac (192.168.110.96).
  A passed datagram is ACKed with `ACK\\n`; a dropped one is not.

Usage:
  p4_drive.py run <image> <program> [--packets N] [--tag LABEL]
  p4_drive.py wifi-check
  p4_drive.py lifecycle <image>

<image> is a cold-table name (e.g. just_drop or jit_just_drop); <program> is one
of div2 xdp_drop case_mark just_drop just_tx firewall. Evidence lands in
jit/reports/p4/<tag>/ as case.json, serial.log, perf.json, and capture.pcap.
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request

AGENT = "http://127.0.0.1:9240"
BOARD_IP = "192.168.110.106"
MAC_IP = "192.168.110.96"
STIM_PORT = 8080
IFACE = "en0"
HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "..", "reports", "p4")

COUNTER_NAMES = [
    "rx_packets", "xdp_invocations", "xdp_pass", "xdp_drop", "xdp_tx",
    "xdp_aborted", "rx_delivered", "rx_discarded", "rx_queue_overflow",
    "tx_submitted", "tx_failed", "tx_completed", "runtime_errors",
    "tx_fail_bad_buf", "tx_fail_token", "tx_grp_src", "tx_enq",
    "tx_enq_fail_claim", "tx_enq_fail_ring", "tx_kick", "tx_poll",
    "tx_cap_wait", "tx_nomem_wait", "tx_no_retain", "tx_flush",
    "tx_air_done_fail", "tx_ns_ref", "tx_ns_free", "tx_flow_sample",
    "tx_block_gt10ms", "tx_block_gt100ms", "inactive_skip", "reentry",
    "stack_misalign", "bad_md", "helper_unresolved", "helper_map",
    "pool_drop_misalign", "failed_tx_wifi_last_rc", "tx_pend", "tx_inflight",
    "tx_inflight_cap", "tx_pending_peak", "tx_inflight_peak", "tx_block_max_us",
    "block_since_us",
]


def post(path, body=None, timeout=120):
    data = json.dumps(body if body is not None else {}).encode()
    req = urllib.request.Request(AGENT + path, data=data,
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def get(path, timeout=60):
    return json.load(urllib.request.urlopen(AGENT + path, timeout=timeout))


def now_ms():
    return int(time.time() * 1000)


def serial(since_ms, until_ms=None):
    until_ms = until_ms or now_ms()
    r = post("/v1/get/serial", {"since_unix_ms": since_ms, "until_unix_ms": until_ms})
    return r.get("message", "")


def perf_counters():
    g = get("/v1/get/perf")
    if not g.get("ok"):
        return {"error": g.get("message")}
    buf = base64.b64decode(g["message"].split("b64=", 1)[1])
    out = {}
    for i, name in enumerate(COUNTER_NAMES):
        if (i + 1) * 4 > len(buf):
            break
        out[name] = struct.unpack_from("<I", buf, i * 4)[0]
    return out


def map_get(name):
    g = get("/v1/get/map/" + name)
    if not g.get("ok"):
        return {"error": g.get("message")}
    return {e["key"]: e["value"] for e in g["entries"]}


def map_op(path, body=None, tries=8):
    for _ in range(tries):
        r = post(path, body)
        if r.get("ok"):
            return r
        if "busy" not in r.get("message", ""):
            return r
        time.sleep(0.4)
    return r


def xdp(on):
    return post("/v1/enable/xdp" if on else "/v1/disable/xdp")


def udp_socket(timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind((MAC_IP, 0))
    return s


def wait_rx(timeout_s=40):
    """With XDP disabled, probe until the board ACKs: WiFi joined + RX up."""
    xdp(False)
    s = udp_socket(0.7)
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            s.sendto(b"WAIT-RX\n", (BOARD_IP, STIM_PORT))
            data, _ = s.recvfrom(256)
            if data == b"ACK\n":
                s.close()
                return True
        except OSError as e:
            last_err = str(e)
        time.sleep(0.5)
    s.close()
    raise RuntimeError(f"board did not ACK within {timeout_s}s (last_err={last_err})")


def install(image):
    t0 = now_ms()
    post("/v1/clear/xdp", {"name": "*"})
    r = post("/v1/flash/xdp", {"name": image})
    if not r.get("ok"):
        raise RuntimeError(f"flash {image}: {r}")
    time.sleep(4)
    get("/v1/dut_status")
    wait_rx()
    return {"flash": r["message"], "boot_serial": serial(t0)}


def stimulus(n, payload=b"P4-STIM\n", capture=None, gap=0.02):
    """Send n datagrams with XDP enabled; count ACKs. Optionally tcpdump."""
    tcp = None
    if capture:
        tcp = subprocess.Popen(
            ["tcpdump", "-i", IFACE, "-w", capture, "-U",
             f"udp and host {BOARD_IP}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
    s = udp_socket(0.3)
    acks = 0
    send_err = 0
    for i in range(n):
        try:
            s.sendto(payload, (BOARD_IP, STIM_PORT))
        except OSError:
            send_err += 1
            time.sleep(0.3)
            continue
        try:
            data, _ = s.recvfrom(256)
            if data == b"ACK\n":
                acks += 1
        except socket.timeout:
            pass
        time.sleep(gap)
    s.close()
    if tcp:
        time.sleep(1.0)
        tcp.terminate()
        tcp.wait()
    return {"sent": n, "acks": acks, "send_err": send_err}


def read_pcap(path):
    """Return list of (src_mac, dst_mac, src_ip, dst_ip, proto) for IPv4 frames."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return out
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            incl = struct.unpack_from("<I", ph, 8)[0]
            data = f.read(incl)
            if len(data) < 14:
                continue
            dst = data[0:6].hex(":")
            src = data[6:12].hex(":")
            et = struct.unpack_from(">H", data, 12)[0]
            if et != 0x0800 or len(data) < 34:
                continue
            ip = data[14:]
            src_ip = socket.inet_ntoa(ip[12:16])
            dst_ip = socket.inet_ntoa(ip[16:20])
            proto = ip[9]
            out.append({"src_mac": src, "dst_mac": dst,
                        "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto})
    return out


def mac_of(ip):
    out = subprocess.check_output(["ifconfig", IFACE]).decode()
    for line in out.splitlines():
        if "ether" in line:
            return line.split()[1]
    return None


def run_case(image, program, packets, tag, seed=True):
    d = os.path.join(REPORTS, tag)
    os.makedirs(d, exist_ok=True)
    rec = {"image": image, "program": program, "packets": packets,
           "tag": tag, "seeded": seed, "started_ms": now_ms()}

    boot = install(image)
    rec["flash"] = boot["flash"]
    open(os.path.join(d, "boot-serial.log"), "w").write(boot["boot_serial"])
    rec["cold_table"] = get("/v1/get/xdp").get("message")

    map_name = {"just_drop": "counter", "case_mark": "rxcnt",
                "just_tx": "rxcnt", "firewall": "blacklist",
                "xdp_drop": "blocklist"}.get(program)

    xdp(False)
    if map_name:
        rec["clear_map"] = map_op("/v1/clear/map/" + map_name).get("message")
    seed = None
    if seed and program == "firewall":
        seed = {"key": MAC_IP, "value": "0"}
        rec["seed"] = map_op("/v1/update/map/blacklist", seed).get("message")
    if seed and program == "xdp_drop":
        seed = {"key": MAC_IP, "value": "1"}
        rec["seed"] = map_op("/v1/update/map/blocklist", seed).get("message")
    map_before = map_get(map_name) if map_name else None
    perf_clear = post("/v1/clear/perf")
    perf_before = perf_counters()

    t0 = now_ms()
    xdp(True)
    # Packet capture needs root (BPF); unavailable here. TX is evidenced by the
    # perf xdp_tx/tx_* counters and the rxcnt map instead of a pcap.
    cap = None
    stim = stimulus(packets, capture=cap)
    xdp(False)
    rec["stimulus"] = stim

    map_after = map_get(map_name) if map_name else None
    perf_after = perf_counters()
    rec["serial"] = serial(t0)
    open(os.path.join(d, "serial.log"), "w").write(rec["serial"])

    if map_name and isinstance(map_before, dict) and isinstance(map_after, dict):
        delta = {}
        keys = set(map_before) | set(map_after)
        for k in keys:
            b = int(map_before.get(k, 0))
            a = int(map_after.get(k, 0))
            if a != b:
                delta[k] = {"before": b, "after": a, "delta": a - b}
        rec["map_name"] = map_name
        rec["map_delta"] = delta
    if isinstance(perf_before, dict) and isinstance(perf_after, dict):
        pd = {k: perf_after.get(k, 0) - perf_before.get(k, 0)
              for k in perf_after if perf_after.get(k, 0) != perf_before.get(k, 0)}
        rec["perf_delta"] = pd
        rec["perf_after"] = perf_after
    json.dump(perf_after, open(os.path.join(d, "perf.json"), "w"), indent=2)

    if program == "div2":
        rec["div2"] = div2_expect()

    rec["finished_ms"] = now_ms()
    json.dump(rec, open(os.path.join(d, "case.json"), "w"), indent=2)
    summarize(rec)
    return rec


def board_mac():
    """The board's WiFi MAC, learned from the Mac's ARP table after stimulus."""
    try:
        out = subprocess.check_output(["arp", "-n", BOARD_IP]).decode()
        for tok in out.split():
            if tok.count(":") == 5:
                return tok
    except Exception:
        pass
    return None


def div2_expect():
    """div2 returns le_u32(data[0..4]) / le_u32(data[4..8]) over the Ethernet
    header: dst MAC (board) then src MAC (this Mac). Compute the expected raw
    return from the ARP-learned board MAC and the Mac's own MAC."""
    bm = board_mac()
    mm = mac_of(MAC_IP)
    if not bm or not mm:
        return {"note": "MAC unavailable", "board_mac": bm, "mac_mac": mm}
    dst = bytes.fromhex(bm.replace(":", ""))
    src = bytes.fromhex(mm.replace(":", ""))
    head = dst + src
    a = struct.unpack_from("<I", head, 0)[0]
    b = struct.unpack_from("<I", head, 4)[0]
    ret = 0 if b == 0 else a // b
    action = {0: "Aborted", 1: "Drop", 2: "Pass", 3: "Tx", 4: "Tx"}.get(ret, "Aborted")
    return {"a": a, "b": b, "expected_return": ret, "expected_action": action,
            "board_mac": bm, "mac_mac": mm,
            "note": "stimulus frames share the board dst MAC, so all return this "
                    "value; background frames vary. xdp_aborted should cover the "
                    "stimulus count when expected_action is Aborted."}


def summarize(rec):
    print(f"\n=== {rec['tag']} ({rec['image']}, {rec['program']}) ===")
    print("cold_table:", rec.get("cold_table"))
    print("stimulus:", rec.get("stimulus"))
    if "map_delta" in rec:
        print(f"map {rec['map_name']} delta:", rec["map_delta"])
    pd = rec.get("perf_delta", {})
    keys = ["rx_packets", "xdp_invocations", "xdp_pass", "xdp_drop", "xdp_tx",
            "xdp_aborted", "runtime_errors", "stack_misalign", "bad_md",
            "helper_unresolved", "helper_map", "reentry"]
    print("perf delta:", {k: pd[k] for k in keys if k in pd})
    txkeys = ["tx_submitted", "tx_completed", "tx_failed"]
    print("tx perf delta:", {k: pd[k] for k in txkeys if k in pd})
    if "div2" in rec:
        print("div2:", rec["div2"])


def wifi_check():
    t0 = now_ms()
    ok = wait_rx()
    print("wifi+rx ACK:", ok)
    print(serial(t0))


def lifecycle(image):
    """Exercise the slot lifecycle routes on just_xdp and record what the
    firmware actually supports (cold-load + boot lease; no hot switch)."""
    d = os.path.join(REPORTS, "lifecycle")
    os.makedirs(d, exist_ok=True)
    rec = {"image": image}
    boot = install(image)
    rec["cold_install"] = boot["flash"]
    rec["cold_table"] = get("/v1/get/xdp").get("message")
    rec["xdp_status_route"] = get("/v1/xdp/status")
    rec["switch_route"] = post("/v1/xdp/switch", {"slot": 0, "generation": 1, "policy": "pass"})
    rec["flash_slot_route"] = post("/v1/flash/xdp", {"name": image, "slot": 0})
    rec["enable"] = xdp(True)
    rec["disable"] = xdp(False)
    json.dump(rec, open(os.path.join(d, "lifecycle.json"), "w"), indent=2)
    print(json.dumps(rec, indent=2))


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "wifi-check":
        wifi_check()
    elif cmd == "lifecycle":
        lifecycle(args[1])
    elif cmd == "run":
        image, program = args[1], args[2]
        packets = 30
        tag = f"{image}__{program}"
        seed = True
        i = 3
        while i < len(args):
            if args[i] == "--packets":
                packets = int(args[i + 1]); i += 2
            elif args[i] == "--tag":
                tag = args[i + 1]; i += 2
            elif args[i] == "--no-seed":
                seed = False; i += 1
            else:
                i += 1
        run_case(image, program, packets, tag, seed=seed)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()