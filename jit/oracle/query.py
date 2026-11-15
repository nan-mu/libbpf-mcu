import json
import sys

doc = json.load(open(sys.argv[1]))
needle = sys.argv[2]
limit = int(sys.argv[3]) if len(sys.argv) > 3 else 12
status = sys.argv[4] if len(sys.argv) > 4 else "fail"
n = 0
for c in doc["cases"]:
    if needle not in c["name"] or c["status"] != status:
        continue
    o = c.get("observables", {})
    print(c["suite"], c["name"])
    print("   jit_ret=", o.get("jit_return"), " rbpf_ret=", o.get("oracle_return"))
    print("   jit_term=", o.get("jit_termination"))
    print("   rbpf_term=", str(o.get("oracle_termination"))[:200])
    if o.get("jit_trace") or o.get("oracle_trace"):
        print("   jit_trace=", json.dumps(o.get("jit_trace"))[:400])
        print("   rbpf_trace=", json.dumps(o.get("oracle_trace"))[:400])
    print("   detail=", c["detail"][:300])
    if c.get("stack_patches"):
        print("   stack_patches=", json.dumps(c["stack_patches"])[:400])
    if c.get("ctx_patches"):
        print("   ctx_patches=", json.dumps(c["ctx_patches"])[:300])
    for r in o.get("memory_regions", []):
        print("   region", r["jit_range"], "vs", r["oracle_range"], "equal=", r["equal"])
    n += 1
    if n >= limit:
        break
print("shown", n)
