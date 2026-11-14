import collections
import json
import sys

doc = json.load(open(sys.argv[1]))
print("summary:", json.dumps(doc["summary"]))

by_status = collections.Counter()
fam = collections.Counter()
examples = {}
for c in doc["cases"]:
    by_status[(c["suite"], c["status"])] += 1
    if c["status"] != "fail":
        continue
    parts = c["name"].split("/")
    key = (c["suite"], "/".join(parts[:2]) if c["suite"] == "probe" else parts[0])
    fam[key] += 1
    examples.setdefault(key, c)

print("\nsuite/status:")
for k, v in sorted(by_status.items()):
    print(f"  {k[0]:10s} {k[1]:14s} {v}")

print("\nfailure families:")
for k, v in fam.most_common():
    print(f"  {k[0]:10s} {k[1]:24s} {v}")

print("\none example per family:")
for k, c in sorted(examples.items()):
    o = c.get("observables", {})
    print(f"  {c['name']}")
    print(f"    jit={o.get('jit_return')} rbpf={o.get('oracle_return')} detail={c['detail'][:160]}")

splits = [c for c in doc["cases"] if c.get("executor_split")]
print(f"\nexecutor splits: {len(splits)}")
for c in splits[:5]:
    print(" ", c["name"], c["executor_split"][:200])

sup = [c for c in doc["cases"] if c["status"] == "unsupported"]
reasons = collections.Counter()
for c in sup:
    d = c["detail"]
    reasons[d[:110]] += 1
print(f"\nunsupported reasons ({len(sup)} cases):")
for k, v in reasons.most_common(20):
    print(f"  {v:5d}  {k}")
