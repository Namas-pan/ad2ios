#!/usr/bin/env python3
"""Host unit tests for the WPA2-PSK code in bsd/dev/topaz_wlan_wpa.c.

The test compiles the real kernel source (see test_wpa.c) with a tiny set of
kernel header shims, runs it, and compares the printed values against:

  * published vectors (FIPS-197 AES, RFC 2202 HMAC-SHA1, IEEE 802.11i PSK),
  * an independent Python implementation (hashlib/hmac) for PBKDF2, the
    802.11i PRF, PTK derivation and the EAPOL MIC,
  * a property the standard requires: PTK derivation must not depend on the
    argument order (MACs and nonces are sorted before the PRF).

Usage:
    python3 tools/wpa-unit/run.py --tree dxb/xnu       # local / CI
    python tools\\wpa-unit\\run.py --tree %TEMP%\\pt\\xnu

Exit status is non-zero on the first mismatch so CI fails loudly.
"""
import argparse
import glob
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "fake")

# --- expected values -------------------------------------------------------

SHA1_ABC = "a9993e364706816aba3e25717850c26c9cd0d89d"   # FIPS 180-1
AES_ECB = "69c4e0d86a7b0430d8cdb78070b4c55a"            # FIPS-197 C.1
AES_RT = "00112233445566778899aabbccddeeff"
HMAC_RFC2202_2 = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
PMK_80211I = ("f42c6fc52df0ebef9ebb4b90b38a5f90"
              "2e83fe1b135a70e23aed762e9710a12e")
UNWRAP_RFC3394 = "00112233445566778899aabbccddeeff"

PRF_KEY = bytes(range(32))
PRF_DATA = bytes(range(76))
PTK_PMK = bytes(0x40 + i for i in range(32))
PTK_AA = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
PTK_SPA = bytes([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
PTK_ANONCE = bytes(0x80 + i for i in range(32))
PTK_SNONCE = bytes(0xc0 + i for i in range(32))
MIC_KCK = bytes(range(16))
MIC_FRAME = bytes(0x30 + i for i in range(32))


def prf_sha1(key, label, data, out_len):
    """IEEE 802.11i 8.5.1.1 PRF, written straight from the standard."""
    out = b""
    counter = 0
    while len(out) < out_len:
        out += hmac.new(key, label + b"\x00" + data + bytes([counter]),
                        hashlib.sha1).digest()
        counter += 1
    return out[:out_len]


def ptk(pmk, aa, spa, anonce, snonce):
    """PTK = PRF-512(PMK, "Pairwise key expansion", sorted MACs | sorted nonces)."""
    if aa <= spa:
        m = aa + spa
    else:
        m = spa + aa
    if anonce <= snonce:
        n = anonce + snonce
    else:
        n = snonce + anonce
    return prf_sha1(pmk, b"Pairwise key expansion", m + n, 48)


def expected():
    e = {
        "sha1_abc": SHA1_ABC,
        "aes_ecb": AES_ECB,
        "aes_rt": AES_RT,
        "hmac": HMAC_RFC2202_2,
        "pbkdf2_a": PMK_80211I,
        "pbkdf2_b": hashlib.pbkdf2_hmac(
            "sha1", b"ThisIsAPassword", b"ThisIsASSID", 4096, 32).hex(),
        "prf": prf_sha1(PRF_KEY, b"Pairwise key expansion", PRF_DATA, 48).hex(),
        "ptk": ptk(PTK_PMK, PTK_AA, PTK_SPA, PTK_ANONCE, PTK_SNONCE).hex(),
        "ptk_swap": ptk(PTK_PMK, PTK_AA, PTK_SPA, PTK_ANONCE, PTK_SNONCE).hex(),
        "mic": hmac.new(MIC_KCK, MIC_FRAME, hashlib.sha1).digest()[:16].hex(),
        "unwrap": UNWRAP_RFC3394,
        "unwrap_bad": "rejected",
        # end-to-end 4-way handshake against a synthetic authenticator
        "eapol_msg2": "ok",
        "eapol_msg2_mic": "ok",
        "eapol_msg4": "ok",
        "eapol_badmic": "rejected",
        "eapol_replay": "rejected",
    }
    return e


# --- build / run -----------------------------------------------------------

def find_vcvars():
    patterns = [
        r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat",
    ]
    for pat in patterns:
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def build(tree, outdir):
    # -I<tree>/bsd (not bsd/sys): it only has to resolve <sys/topaz_wlan_wpa.h>,
    # and bsd/sys would otherwise shadow the host's own <stdio.h> and <sys/...>.
    incdirs = [FAKE, os.path.join(tree, "bsd"), os.path.join(tree, "bsd", "dev")]
    srcs = [os.path.join(HERE, "test_wpa.c"), os.path.join(HERE, "sha1_host.c")]
    exe = os.path.join(outdir, "wpa_unit.exe" if os.name == "nt" else "wpa_unit")

    cc = os.environ.get("CC")
    if cc:
        cmd = [cc, "-O1", "-o", exe]
        for d in incdirs:
            cmd += ["-I", d]
        cmd += ["-DARM64_BOARD_CONFIG_SWEET"] + srcs
        subprocess.run(cmd, check=True)
        return exe

    if os.name == "nt":
        vcvars = find_vcvars()
        if not vcvars:
            sys.exit("no MSVC environment found (vcvars64.bat missing)")
        # MSVC needs its environment, and cmd's quote handling mangles
        # `call "C:\Program Files\..."` when it is passed through a Python arg
        # list. A generated .bat file sidesteps all of that.
        parts = ["cl", "/nologo", "/W3", "/Fo%s\\" % outdir, "/Fe:%s" % exe,
                 "/DARM64_BOARD_CONFIG_SWEET"]
        parts += ['/I"%s"' % d for d in incdirs]
        parts += ['"%s"' % s for s in srcs]
        bat = os.path.join(outdir, "build.bat")
        with open(bat, "w", encoding="ascii") as f:
            f.write("@echo off\r\ncall \"%s\" >nul\r\n%s\r\n" %
                    (vcvars, " ".join(parts)))
        subprocess.run([bat], check=True)
        return exe

    ccbin = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not ccbin:
        sys.exit("no host C compiler found (set CC)")
    cmd = [ccbin, "-O1", "-Wall", "-o", exe]
    for d in incdirs:
        cmd += ["-I", d]
    cmd += ["-DARM64_BOARD_CONFIG_SWEET"] + srcs
    subprocess.run(cmd, check=True)
    return exe


def run_exe(exe):
    out = subprocess.run([exe], check=True, capture_output=True, text=True).stdout
    got = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            got[k.strip()] = v.strip()
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True,
                    help="path to a patched xnu tree (contains bsd/dev)")
    args = ap.parse_args()
    tree = os.path.abspath(args.tree)
    src = os.path.join(tree, "bsd", "dev", "topaz_wlan_wpa.c")
    if not os.path.isfile(src):
        sys.exit("not found: %s" % src)

    outdir = tempfile.mkdtemp(prefix="wpa-unit-")
    try:
        exe = build(tree, outdir)
        got = run_exe(exe)
    finally:
        shutil.rmtree(outdir, ignore_errors=True)

    want = expected()
    failed = 0
    for name in want:
        if name not in got:
            print("FAIL %-11s missing from output" % name)
            failed += 1
        elif got[name].lower() != want[name].lower():
            print("FAIL %-11s got %s" % (name, got[name]))
            print("     %-11s want %s" % ("", want[name]))
            failed += 1
        else:
            print("ok   %s" % name)
    if failed:
        print("%d of %d checks failed" % (failed, len(want)))
        return 1
    print("all %d checks passed" % len(want))
    return 0


if __name__ == "__main__":
    sys.exit(main())
