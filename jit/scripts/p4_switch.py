#!/usr/bin/env python3
"""P4 slot hot-switch lifecycle on examples/case_xdp (the firmware that registers
the `xdp flash` / `xdp switch` / `get xdp status` serial handlers; just_xdp does
not). Exercises load -> stage -> activate -> switch between a JIT image
(jit_case_mark, primary slot 0) and an AOT image (case_mark_idle, idle slot 1),
recording the slot state machine after every step.

Requires case_xdp firmware flashed and both cold images installed:
  POST /v1/flash/fw {"name":"case-cag"}
  POST /v1/clear/xdp {"name":"*"}
  POST /v1/flash/xdp {"name":"jit_case_mark"}
  POST /v1/flash/xdp {"name":"case_mark_idle"}

Usage: p4_switch.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4_drive as d

OUT = os.path.join(d.REPORTS, "switch")


def status():
    return d.get("/v1/xdp/status").get("message")


def flash_slot(name, slot):
    return d.post("/v1/flash/xdp", {"name": name, "slot": slot}).get("message")


def switch(slot, generation, policy):
    return d.post("/v1/xdp/switch",
                  {"slot": slot, "generation": generation, "policy": policy}).get("message")


def gen_of(flash_reply):
    # "OK xdp flash <slot> <generation> <mcu_us> agent_rx=..."
    return int(flash_reply.split()[4])


def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = d.now_ms()
    # NOTE: do not call GET /v1/get/xdp here: the espflash cold-table list
    # enters the bootloader and resets the board, wiping the leased slot.
    # Boot auto-leases the first cold image (jit_case_mark) into slot 0, so the
    # sequence stages the *other* image into the idle slot first; staging an
    # image into the slot where it is already active returns ERR logic.
    rec = {"steps": []}

    def step(label, reply):
        s = status()
        rec["steps"].append({"step": label, "reply": reply, "status": s})
        print(f"{label}\n  reply: {reply}\n  status: {s}")

    step("initial (boot leased jit_case_mark -> slot0)", None)
    r = flash_slot("case_mark_idle", 1)
    g1 = gen_of(r)
    step("stage case_mark_idle -> slot1 (AOT)", r)
    r = switch(1, g1, "pass")
    step("activate slot0 -> slot1 (AOT)", r)
    r = flash_slot("jit_case_mark", 0)
    g0 = gen_of(r)
    step("stage jit_case_mark -> slot0 (JIT)", r)
    r = switch(0, g0, "pass")
    step("activate slot1 -> slot0 (JIT)", r)

    rec["serial"] = d.serial(t0)
    open(os.path.join(OUT, "serial.log"), "w").write(rec["serial"])
    json.dump(rec, open(os.path.join(OUT, "switch.json"), "w"), indent=2)
    print("\nwrote", os.path.join(OUT, "switch.json"))


if __name__ == "__main__":
    main()