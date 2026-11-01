#!/usr/bin/env python3
# winrun.py -- una corsa di Windows 11 + Hyper-V annidato, dall'avvio all'esito,
# senza nessuno davanti (Claude 18/10/2026). Va eseguito da root:
#
#   sudo -n python3 tools/nested/winrun.py [--script S] [--tracer T] [--max S]
#
# Avvia lo script dell'utente (NON lo modifica), si aggancia alla console VNC
# se il vncviewer non parte (bhyve con fbuf ...,wait non fa partire le CPU
# senza un client), registra un tracciatore DTrace e osserva i contatori
# nested ogni 5 s finche' la corsa non ha un esito:
#   RETE      Windows risponde in ssh: la VM resta accesa;
#   BUGCHECK  la CPU0 gira nel ciclo di HalHaltSystem (legge PM1a_STS, porta
#             0x400): lo stop code si legge dallo stack dell'L2 in memoria,
#             poi pulsante di accensione (SIGTERM, Windows fa S5);
#   STALLO    nessun progresso (ingressi in L2 + slow path) per --stallo s:
#             stato dei vlapic, poi pulsante di accensione;
#   USCITO    bhyve e' terminato da solo;
#   TEMPO     scaduto --max: pulsante di accensione.
# Riassunto in logs/run-<ora>-riassunto.txt (e su stdout).

import argparse, mmap, os, re, signal, socket, struct, subprocess, sys, threading, time

W = "/mnt/linuxulator2/vm/wsl2/fbsd"
VM = "vm0:12"
WIN_IP = "win11"
WIN_PW_FILE = "/home/marietto/.config/claude-wsl2/password-windows"
DISPLAY_ENV = {"DISPLAY": ":0", "XAUTHORITY": "/home/marietto/.Xauthority"}

# stop code noti (KeBugCheckEx: codice nel primo argomento)
BUGCHECKS = {
    0x0a: "IRQL_NOT_LESS_OR_EQUAL", 0x1a: "MEMORY_MANAGEMENT",
    0x1e: "KMODE_EXCEPTION_NOT_HANDLED", 0x3b: "SYSTEM_SERVICE_EXCEPTION",
    0x50: "PAGE_FAULT_IN_NONPAGED_AREA", 0x5c: "HAL_INITIALIZATION_FAILED",
    0x7e: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", 0x7f: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x9c: "MACHINE_CHECK_EXCEPTION", 0x9f: "DRIVER_POWER_STATE_FAILURE",
    0x101: "CLOCK_WATCHDOG_TIMEOUT", 0x109: "CRITICAL_STRUCTURE_CORRUPTION",
    0x116: "VIDEO_TDR_FAILURE", 0x119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
    0x124: "WHEA_UNCORRECTABLE_ERROR", 0x133: "DPC_WATCHDOG_VIOLATION",
    0x139: "KERNEL_SECURITY_CHECK_FAILURE", 0x13a: "KERNEL_MODE_HEAP_CORRUPTION",
    0x15f: "CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP", 0x18b: "SECURE_KERNEL_ERROR",
    0x1ca: "SYNTHETIC_WATCHDOG_TIMEOUT", 0x1d5: "DRIVER_PNP_WATCHDOG",
    0xd1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL", 0xc4: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0xef: "CRITICAL_PROCESS_DIED", 0x20001: "HYPERVISOR_ERROR",
}

LOG = None

WIN_IMG = "/mnt/da0p2/bhyve/img/Windows/11/Windows11.img"


def ensure_image_disk():
    """Dopo un riavvio /mnt/da0p2 (UFS, immagine Windows) resta sporco e non
    si monta: bhyve non trova l'immagine ed esce subito. Si monta; se e'
    sporco si fa fsck e si rimonta. /mnt/da0p2 e' una SOTTOCARTELLA (non
    copre lo ZFS di /mnt)."""
    if os.path.exists(WIN_IMG):
        return True
    sh("mount -t ufs /dev/da0p2 /mnt/da0p2", timeout=60)
    if os.path.exists(WIN_IMG):
        say("montato /mnt/da0p2 (immagine Windows)")
        return True
    say("/mnt/da0p2 sporco: fsck in corso...")
    sh("fsck_ffs -y /dev/da0p2", timeout=600)
    sh("mount -t ufs /dev/da0p2 /mnt/da0p2", timeout=60)
    if os.path.exists(WIN_IMG):
        say("fsck + mount ok: immagine Windows disponibile")
        return True
    say("IMPOSSIBILE montare /mnt/da0p2: l'immagine Windows non c'e'")
    return False



def say(msg):
    line = "[winrun %s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    if LOG:
        LOG.write(line + "\n")
        LOG.flush()


def sh(cmd, timeout=30):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def bhyve_pid():
    """Il processo bhyve della VM (nome esatto 'bhyve', /dev/vmm/VM presente).
    La riga di ps NON basta: la prima corsa non lo riconosceva, e la pulizia
    finale ha distrutto la VM mentre girava (18/10 21:37)."""
    if not os.path.exists("/dev/vmm/" + VM):
        return None
    out = sh("pgrep -x bhyve").split()
    return int(out[0]) if out else None


def stats(cpu):
    out = sh("bhyvectl --vm=%s --get-stats --cpu=%d" % (VM, cpu))
    d = {}
    for l in out.splitlines():
        m = re.match(r"(.+?)\s+(\d+)$", l.strip())
        if m:
            d[m.group(1).strip()] = int(m.group(2))
    return {"l2": d.get("ingressi in L2", 0), "slow": d.get("exit nested gestite nello slow path", 0),
            "io": d.get("number of times in/out was intercepted", 0),
            "tot": d.get("total number of vm exits", 0)}


def reg(cpu, name):
    out = sh("bhyvectl --vm=%s --cpu=%d --get-%s" % (VM, cpu, name))
    m = re.search(r"\s(0x[0-9a-f]+)", out)
    return int(m.group(1), 16) if m else None


# --- memoria del guest (sola lettura), EPT12 a identita' per la root ---
class Mem:
    def __init__(self):
        self.fd = os.open("/dev/vmm/" + VM, os.O_RDONLY)

    def rd(self, gpa, n):
        base = gpa & ~0xfff
        m = mmap.mmap(self.fd, ((gpa + n - base + 0xfff) & ~0xfff), mmap.MAP_SHARED,
                      mmap.PROT_READ, offset=base)
        d = m[gpa - base:gpa - base + n]
        m.close()
        return d

    def q(self, gpa):
        return struct.unpack("<Q", self.rd(gpa, 8))[0]

    def walk(self, cr3, va):
        t = cr3 & 0x000ffffffffff000
        for lvl, shf in ((4, 39), (3, 30), (2, 21), (1, 12)):
            e = self.q(t + ((va >> shf) & 0x1ff) * 8)
            if not e & 1:
                return None
            if lvl in (3, 2) and e & 0x80:
                return (e & 0x000fffffffffffff & ~((1 << shf) - 1)) | (va & ((1 << shf) - 1))
            t = e & 0x000ffffffffff000
        return t | (va & 0xfff)

    def vread(self, cr3, va, n):
        out = b""
        while len(out) < n:
            pa = self.walk(cr3, va)
            k = min(0x1000 - (va & 0xfff), n - len(out))
            if pa is None:
                break
            out += self.rd(pa, k)
            va += k
        return out


def find_bugcheck(cpu=0):
    """Cerca nello stack dell'L2 un frame [ritorno kernel, codice, p1..p4]."""
    cr3, rsp = reg(cpu, "cr3"), reg(cpu, "rsp")
    if cr3 is None or rsp is None:
        return None
    try:
        mem = Mem()
        d = mem.vread(cr3, rsp & ~7, 0x3000)
    except OSError as e:
        return "lettura memoria fallita: %s" % e
    v = struct.unpack("<%dQ" % (len(d) // 8), d[:len(d) // 8 * 8])
    for i in range(1, len(v) - 4):
        if v[i] in BUGCHECKS and (v[i - 1] >> 40) == 0xfffff8:
            autopsy(mem, cr3, v[i], v[i + 1:i + 5])
            return "0x%x %s (%s) a rsp+%#x, ritorno %#x" % (
                v[i], BUGCHECKS[v[i]], ", ".join(hex(x) for x in v[i + 1:i + 5]),
                8 * i, v[i - 1])
    return None


AUTOPSY = None


def autopsy(mem, cr3, code, params):
    """Prima che la VM si spenga: per ogni parametro che e' un indirizzo del
    kernel, 2 KB di memoria e le stringhe leggibili (per 0xEF il nome
    dell'eseguibile sta nell'EPROCESS del primo parametro)."""
    out = []
    for k, pv in enumerate(params):
        if (pv >> 47) != 0x1ffff:
            continue
        try:
            d = mem.vread(cr3, pv, 0x800)
        except OSError:
            continue
        if AUTOPSY:
            open("%s-param%d.bin" % (AUTOPSY, k + 1), "wb").write(d)
        strs = [m.group().decode() for m in re.finditer(rb"[ -~]{4,}", d)]
        wide = [m.group().decode("utf-16-le", "replace") for m in
                re.finditer(rb"(?:[ -~]\x00){4,}", d)]
        out.append("param%d %#x: %s %s" % (k + 1, pv, strs[:12], wide[:6]))
    for l in out:
        say("  autopsia " + l)


def rfb_hold(port, stop):
    """Client RFB minimo: tiene aperta la console (sblocca fbuf ...,wait)."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        ver = s.recv(12); s.sendall(ver)
        n = s.recv(1)[0]; s.recv(n)
        s.sendall(bytes([1])); s.recv(4)
        s.sendall(b"\x01")
        init = s.recv(24); s.recv(int.from_bytes(init[20:24], "big"))
        say("console VNC agganciata da winrun (%s)" % ver.strip().decode())
        s.settimeout(2)
        while not stop.is_set():
            try:
                if not s.recv(65536):
                    break
            except socket.timeout:
                pass
    except Exception as e:
        say("aggancio VNC fallito: %s" % e)


def windows_ssh():
    if subprocess.run("ping -c1 -t2 %s >/dev/null 2>&1" % WIN_IP, shell=True).returncode:
        return None
    out = sh("sshpass -f '%s' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "
             "marietto@%s 'echo WINRUN-OK'" % (WIN_PW_FILE, WIN_IP), timeout=20)
    return "WINRUN-OK" in out


def power_button(pid, wait=30):
    say("pulsante di accensione (SIGTERM a bhyve %d)" % pid)
    os.kill(pid, signal.SIGTERM)
    for _ in range(wait):
        time.sleep(1)
        if bhyve_pid() is None:
            say("bhyve terminato")
            return True
    say("bhyve ancora vivo dopo %d s" % wait)
    return False


def main():
    global LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default=W + "/freebsd-nested/tools/nested/12-Windows-11-nvidia-vm12")
    ap.add_argument("--tracer", default=W + "/dtrace/win-percpu2.d")
    ap.add_argument("--max", type=int, default=1500, help="durata massima (s)")
    ap.add_argument("--stallo", type=int, default=60, help="s senza progresso = stallo")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("va eseguito da root (sudo -n python3 ...)")

    ts = time.strftime("%Y%m%d-%H%M%S")
    pre = "%s/logs/run-%s" % (W, ts)
    LOG = open(pre + "-riassunto.txt", "w")
    global AUTOPSY
    AUTOPSY = pre
    say("corsa %s: script %s" % (ts, a.script))
    if bhyve_pid() is not None:
        say("C'E' GIA' una VM %s in esecuzione: esco" % VM)
        return 2

    if not ensure_image_disk():
        say("ESITO: NO-IMMAGINE (disco /mnt/da0p2 non montabile)")
        return 3

    tr = None
    if a.tracer:
        tr = subprocess.Popen(["dtrace", "-s", a.tracer, "-o", pre + "-traccia.txt"],
                              stdout=subprocess.DEVNULL, stderr=open(pre + "-traccia.err", "w"))
        say("tracciatore %s -> %s-traccia.txt" % (os.path.basename(a.tracer), pre))
        time.sleep(3)

    env = dict(os.environ, **DISPLAY_ENV)
    launches = [0]

    def launch():
        """Avvia lo script dell'utente; ritorna il pid di bhyve o None."""
        launches[0] += 1
        log = open("%s-script%s.log" % (pre, "" if launches[0] == 1 else "-%d" % launches[0]), "w")
        subprocess.Popen(["sh", a.script], stdout=log, stderr=subprocess.STDOUT,
                         env=env, cwd="/", start_new_session=True)
        t = time.time()
        while time.time() - t < 60:
            time.sleep(1)
            p = bhyve_pid()
            if p is not None:
                say("bhyve pid %d (avvio %d)" % (p, launches[0]))
                return p
        say("bhyve non e' partito in 60 s: vedi %s-script*.log" % pre)
        return None

    t0 = time.time()
    pid = launch()
    result = None if pid is not None else "NON-PARTITO"

    stop = threading.Event()
    hooked = False
    last = None
    still = 0
    first_l2 = None
    while result is None:
        time.sleep(5)
        el = int(time.time() - t0)
        if bhyve_pid() is None:
            # bhyve esce in silenzio quando il guest si RIAVVIA: Windows lo fa
            # a volte nella fase senza hypervisor (avvio dopo un crash).
            # Come farebbe l'utente: si rilancia, fino a 3 avvii.
            if first_l2 is None and launches[0] < 3:
                say("bhyve uscito prima di Hyper-V (riavvio del guest?): rilancio")
                hooked = False
                last = None
                if launch() is not None:
                    continue
            result = "USCITO"
            break
        if not hooked and el >= 20:
            if subprocess.run("pgrep -q vncviewer", shell=True).returncode != 0:
                threading.Thread(target=rfb_hold, args=(5912, stop), daemon=True).start()
            hooked = True
        s0, s1 = stats(0), stats(1)
        if first_l2 is None and s0["l2"] > 0:
            first_l2 = el
            say("Hyper-V partito: primo ingresso in L2 a %d s" % el)
        if last:
            dios = ((s0["io"] - last[0]["io"]) / 5, (s1["io"] - last[1]["io"]) / 5)
            dio = max(dios)
            hc = 0 if dios[0] >= dios[1] else 1
            prog = (s0["l2"] + s0["slow"] + s1["l2"] + s1["slow"]) - \
                   (last[0]["l2"] + last[0]["slow"] + last[1]["l2"] + last[1]["slow"])
            if el % 30 < 5:
                say("%4d s  cpu0 L2=%d slow=%d | cpu1 L2=%d slow=%d | io/s=%d" % (
                    el, s0["l2"], s0["slow"], s1["l2"], s1["slow"], dio))
            # prima di Hyper-V Windows fa ~35k I/O al secondo: serve anche la
            # CPU con piu' I/O sul ciclo della porta 0x400 (RDX o RCX) in
            # almeno uno di 5 campioni. Il ciclo puo' girare sulla CPU1.
            if dio > 20000 and first_l2 is not None and \
                    any(0x400 in (reg(hc, "rdx"), reg(hc, "rcx")) for _ in range(5)):
                bc = find_bugcheck(hc) or find_bugcheck(1 - hc)
                result = "BUGCHECK"
                say("ciclo HalHaltSystem su cpu%d (in/out %d/s): %s" % (
                    hc, dio, bc or "stop code non trovato negli stack"))
                break
            still = still + 5 if (prog == 0 and first_l2 is not None) else 0
            if still >= a.stallo:
                result = "STALLO"
                say("nessun progresso per %d s (cpu0 L2=%d, cpu1 L2=%d)" % (still, s0["l2"], s1["l2"]))
                for c in (0, 1):
                    say("  cpu%d rip=%#x cr3=%#x" % (c, reg(c, "rip") or 0, reg(c, "cr3") or 0))
                # una schermata blu non riconosciuta sembra uno stallo
                for c in (0, 1):
                    bc = find_bugcheck(c)
                    if bc:
                        result = "BUGCHECK"
                        say("  ...era un bugcheck (stack cpu%d): %s" % (c, bc))
                        break
                break
        last = (s0, s1)
        if first_l2 is not None and el % 20 < 5:
            ok = windows_ssh()
            if ok:
                result = "RETE"
                say("WINDOWS RISPONDE IN SSH a %d s: la VM resta accesa" % el)
                break
        if el >= a.max:
            result = "TEMPO"
            break

    powered_off = False
    if result in ("BUGCHECK", "STALLO", "TEMPO") and bhyve_pid():
        powered_off = power_button(bhyve_pid())
        if not powered_off:
            say("la VM resta: distruggerla a mano se serve")
    stop.set()
    if tr:
        time.sleep(2)
        tr.send_signal(signal.SIGINT)
        try:
            tr.wait(20)
        except subprocess.TimeoutExpired:
            tr.kill()
        tot = {}
        try:
            for m in re.finditer(r"SALVATO cpu(\d) idtvec (0x[0-9a-f]+): (\d+)",
                                 open(pre + "-traccia.txt").read()):
                k = (m.group(1), m.group(2))
                tot[k] = tot.get(k, 0) + int(m.group(3))
        except OSError:
            pass
        say("eventi per l'L2 salvati nell'IDT-vectoring: %s" % (
            ", ".join("cpu%s %s x%d" % (k[0], k[1], v) for k, v in sorted(tot.items())) or "nessuno"))
    # si distrugge SOLO la VM che winrun ha spento col pulsante, e solo se
    # nessun processo bhyve e' ancora vivo
    if powered_off and sh("pgrep -x bhyve").strip() == "" and \
            os.path.exists("/dev/vmm/" + VM):
        sh("bhyvectl --vm=%s --destroy" % VM)
    say("ESITO: %s dopo %d s (riassunto %s-riassunto.txt)" % (result, int(time.time() - t0), pre))
    return 0


if __name__ == "__main__":
    sys.exit(main())
