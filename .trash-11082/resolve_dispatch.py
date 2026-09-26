import sys

path = ".rebase-wt/crates/zeroclaw-runtime/src/rpc/dispatch.rs"
with open(path) as f:
    lines = f.readlines()

# Classification: OURS = slice-6 private-memory; THEIRS = landed foundation.
OURS = {3,4,5,6,7,9,10,11,12,30,31,32,33}
# everything else THEIRS
out = []
region = 0
state = "normal"  # normal | ours | theirs
ours_buf = []
theirs_buf = []
for ln in lines:
    if state == "normal":
        if ln.startswith("<<<<<<< HEAD"):
            region += 1
            state = "ours"
            ours_buf = []
            theirs_buf = []
            continue
        out.append(ln)
    elif state == "ours":
        if ln.startswith("======="):
            state = "theirs"
            continue
        ours_buf.append(ln)
    elif state == "theirs":
        if ln.startswith(">>>>>>> upstream/master"):
            pick = ours_buf if region in OURS else theirs_buf
            out.extend(pick)
            state = "normal"
            continue
        theirs_buf.append(ln)

if state != "normal":
    print(f"ERROR: ended in state {state}, region {region}", file=sys.stderr)
    sys.exit(1)

with open(path, "w") as f:
    f.writelines(out)
print(f"resolved {region} regions")
