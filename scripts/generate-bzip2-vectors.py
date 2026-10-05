# Regenerates bzip2 test vectors with CPython's standard-library bz2 module.
import bz2, os
M = (1 << 64) - 1
def lcg(n, seed):
    x, out = seed, bytearray()
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & M
        out.append(x >> 56)
    return bytes(out)
def acgt(n):
    return bytes(b"ACGT"[b >> 6] for b in lcg(n, 1))
small = {
    "EMPTY": (b"", 9),
    "ONE": (b"a", 9),
    "HELLO": (b"hello world", 9),
    "RUN_A": (b"a" * 10000, 9),
    "ALL_BYTES": (bytes(range(256)) * 3, 1),
    "RUNS4": (b"aaaabbbbccccdddd" * 7 + b"zzzz", 9),
    "LONG_RUNS": (b"x" * 255 + b"y" * 256 + b"z" * 1000 + b"q" * 4 + b"w" * 259, 5),
}
for name, (data, lvl) in small.items():
    print(f"const {name}: &str = \"{bz2.compress(data, lvl).hex()}\";")
d = os.path.join(os.path.dirname(__file__), "..", "tests", "vectors", "bzip2")
for lvl in (1, 9):
    c = bz2.compress(acgt(300_000), lvl)
    open(os.path.join(d, f"acgt300k-l{lvl}.bz2"), "wb").write(c)
    print(lvl, len(c))
open(os.path.join(d, "random2k-l9.bz2"), "wb").write(bz2.compress(lcg(2048, 7), 9))
period = lcg(1000, 3) * 2000
c = bz2.compress(period, 9); open(os.path.join(d, "periodic2m-l9.bz2"), "wb").write(c); print("periodic", len(c))
