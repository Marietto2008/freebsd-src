#!/usr/local/bin/python3
# ptpad-drive.py -- Claude 27/10/2026, parere #106. Driver HOST del test ptpad sotto QEMU
# `-accel bhyve`. Sostituisce ptpad_assembla per le corse vere (quello leggeva il contatore a VM
# FINITA: delta 0 ovunque). NON si lancia senza consenso: avvia la VM data dopo `--`.
#
# Protocollo con L1 (ptpad_test.c.inc, sulla COM1 = stdin/stdout di QEMU con -serial stdio):
#   L1 "PTPAD WAIT piano"        -> host invia "<piano>\n"
#   L1 "PTPAD PLAN cases=<p>"    -> host verifica p == piano richiesto, altrimenti STOP
#   L1 "PTPAD CASE <n>"          -> host legge il contatore (CTR before), segna "ack-<n>", invia 'g'
#   L1 "PTPAD L1 ..."            -> host segna "l1-<n>", legge il contatore (CTR after), TERM alive
#   L1 "PTPAD MAP ..."           -> copiata come "MAP ..." (pteaddr: GPA della PTE di D, casi H)
# Accanto a CTR (nested_ept_mmio_emulated) il driver legge RFL (nested_ept12_viol_reflected): nei
# casi H (scrittura hardware) la prova di percorso e' delta mmio 0 e delta riflessioni 1.
# RFE (nested_ept12_viol_emul_reflected), EST (_emul_stale), ENC (_emul_nocache), solo nel modulo con
# la correzione di H1 (parere #110 §5.6): ciascuno letto se il suo sysctl esiste; altrimenti nessuna
# riga e una nota in driver.txt. Parere #111: anche RTX/RTR (vept_ptp_write_retry_xlate/_remap); la riga
# "PTPAD XINFO" di L1 (GLA e RIP dal VMCS12) va nel blocco del caso; una traccia FBT inutilizzabile scrive
# FBTDROP nel combinato (sessione non conclusiva, #111 §5.4).
# L1 e' FERMO fra CASE e 'g', e fra la riga L1 e il CASE successivo non esegue L2: le due letture
# del contatore racchiudono esattamente il movsq del caso.
#
# H2 sotto QEMU (parere #106 D3): un errore di VM_RUN NON termina QEMU; stampa "Error running vm"
# su stderr e rientra in vm_run in un anello caldo. Il driver lo vede su stderr, chiude il caso
# aperto con TERM bhyve_died (= VM_RUN ha restituito errore al processo utente) e uccide QEMU.
#
# Uscite in --out: combinato.txt (per ptpad_an.py, scritto via via; le righe FBT inserite alla
# fine), seriale.txt e qemu-stderr.txt con istante host, fbt.txt/fbt.err se --fbt, driver.txt.
# Codice d'uscita: 0 corsa completata o caso D chiuso con errore di VM_RUN; 2 STOP del protocollo;
# 3 timeout; 4 dtrace non pronto (nessuna VM avviata); 5 stato della VM ignoto (killpg fallito o processi
# del gruppo sopravvissuti: RUNNER=UNKNOWN, ripristino NON verificato).
#
# Uso: ptpad-drive.py --piano B,C,A,A_D --out DIR [--fbt ptpad-fbt.d] [--timeout 120]
#                     [--ctr-cmd '...'] [--dtrace-cmd '...'] -- <comando QEMU...>
import argparse, os, queue, re, shlex, signal, subprocess, sys, threading, time

MARK = '/nonexistent/ptpad-mark/'
CASI = ('B', 'C', 'A', 'A_D', 'H', 'H_D', 'HD_DATA', 'HD_PTP', 'HD_DATA_PDE', 'HD_DATA_ALL', 'HD_PTP_ALL',
    'HD_CONFLICT', 'HD_CONFLICT_PDE', 'H_PDE', 'HM_RAM', 'HM_PTP',
    'D_DATA', 'D_PTP', 'D_DATA_PDE', 'D_DATA_ALL', 'D_PTP_ALL', 'D_CONFLICT', 'D_CONFLICT_PDE', 'DM_PTP')
CASI_D = ('D_DATA', 'D_PTP', 'D_DATA_PDE', 'D_DATA_ALL', 'D_PTP_ALL', 'D_CONFLICT', 'D_CONFLICT_PDE', 'DM_PTP')
# #131: HM_PTP e DM_PTP sono caratterizzazioni (esito = diagnosi), sempre ULTIME: nessun cancello dopo
CASI_DIAGNOSI = ('HM_PTP', 'DM_PTP')
RIGHE_SESSIONE = ('PTPAD MEM ', 'PTPAD FIXMMIO ', 'PTPAD PCIDEV ', 'PTPAD BRIDGE ', 'PTPAD BAR ', 'PTPAD BARBAD ',
    'PTPAD ROM ', 'PTPAD PCI_SCAN_COMPLETE ')
# #132 §3.1: casi che toccano Y o Y': regioni verificate PRIMA dell'ACK (L2 non parte se la raccolta non e' completa)
CASI_Y = ('HM_RAM', 'HM_PTP', 'DM_PTP')
# #132 §3.2: errori di VM_RUN che chiudono SUBITO la finestra (il secondo), emulazioni dopo il primo errore idem
SOGLIA_ERRORI = 2
SOGLIA_EMULAZIONI = 2
# #132 §3.2 (HM): riflessioni dentro un caso aperto oltre le quali il driver ferma la VM senza aspettare il timeout
SOGLIA_RIFLESSIONI = 64
CASI_HW = ('H', 'H_D', 'HD_DATA', 'HD_PTP', 'HD_DATA_PDE', 'HD_DATA_ALL', 'HD_PTP_ALL', 'HD_CONFLICT',
    'HD_CONFLICT_PDE', 'H_PDE', 'HM_RAM')
# H2 (29/10, parere #119): contatori del modulo con la correzione di H2/P3, letti solo se esistono
H2_OPZ = (('H2F', '/sbin/sysctl -n hw.vmm.vmx.vept_h2_viol_final'),
    ('H2P', '/sbin/sysctl -n hw.vmm.vmx.vept_h2_viol_ptp'),
    ('H2M', '/sbin/sysctl -n hw.vmm.vmx.vept_h2_misconf'),
    ('H2U', '/sbin/sysctl -n hw.vmm.vmx.vept_h2_unread'),
    ('H2A', '/sbin/sysctl -n hw.vmm.vmx.vept_h2_already'),
    ('MER', '/sbin/sysctl -n hw.vmm.vmx.nested_ept12_misconf_emul_reflected'),
    ('CAP', '/sbin/sysctl -n hw.vmm.gla2gpa_restart_capped'),
    # #142 §4.1: moduli RIPFIX. FTL = vCPU fermati dal latch fatale; VMU = Fase C (VEPT_MMIO non emulabile, nesting)
    ('FTL', '/sbin/sysctl -n hw.vmm.fatal_latches'),
    ('VMU', '/sbin/sysctl -n hw.vmm.vmx.nested_vept_mmio_unemulable'))


# #134 §7: processi POSSEDUTI dal driver (gruppo della VM, dtrace). Se il driver muore per un'eccezione o per un
# segnale, pulizia_finale() li chiude comunque (TERM, poi KILL): nella sessione DM reale il crollo del driver aveva
# lasciato vivo dtrace, e un collaudo interrotto due VM finte per cinque ore.
POSSEDUTI = {'gruppi': [], 'dtrace': [], 'kill_cmd': None}


def pulizia_finale():
	for g in list(POSSEDUTI['gruppi']):
		for sig in (signal.SIGTERM, signal.SIGKILL):
			try:
				os.killpg(g, sig)
			except OSError:
				break
			sys.stderr.write('pulizia finale: segnale %d al gruppo %d\n' % (sig, g))
			for _ in range(20):
				time.sleep(0.25)
				try:
					os.killpg(g, 0)
				except OSError:
					break
			else:
				continue
			break
	for d in list(POSSEDUTI['dtrace']):
		if d.poll() is None and POSSEDUTI['kill_cmd']:
			sys.stderr.write('pulizia finale: chiudo dtrace (pid %d)\n' % d.pid)
			subprocess.run(POSSEDUTI['kill_cmd'] + [str(d.pid)])
			try:
				d.wait(10)
			except subprocess.TimeoutExpired:
				pass


def _esci_per_segnale(sig, frame):
	raise SystemExit(128 + sig)


def piano_valido(p):
	"""Stesse regole di ptpad_leggi_piano in L1: nomi noti, nessun duplicato, B primo, al piu'
	UN caso D e per ultimo."""
	c = p.split(',')
	if not c or c[0] != 'B' or len(set(c)) != len(c) or any(x not in CASI for x in c):
		return False
	d = [i for i, x in enumerate(c) if x in CASI_D]
	return len(d) <= 1 and (not d or d[0] == len(c) - 1)


def segna(etichetta):
	"""Confine di caso per ptpad-fbt.d: un fstatat del driver su un percorso inesistente."""
	try:
		os.stat(MARK + etichetta)
	except OSError:
		pass


def fbt_per_caso(testo, driver_pid, vm_pids, visti, chiusi):
	"""Dalla traccia FBT (righe FBTEV, ordinate per timestamp) conta mmio/walk nella finestra di
	ogni caso: da mark ack-<n> a mark l1-<n>, o a mark fine se il caso non ha risposto.
	Parere #107 §4: i marcatori devono venire dal pid del DRIVER, le sonde FBT da un pid della VM
	(process group del lancio); ogni caso aperto deve avere il suo ack, ogni caso chiuso il suo l1,
	nell'ordine del protocollo. Altrimenti None: correlazione non certa, nessuna riga FBT.
	Ritorna {caso: (mmio, walk)} oppure None."""
	if '== FBT PRONTA ==' not in testo or '== FBT CHIUSA ==' not in testo:
		return None
	ev = []
	for r in testo.splitlines():
		m = re.match(r'FBTEV t=(\d+) pid=(\d+) tid=\d+ k=(mmio|walk|mark)(?: m=(\S+))?$', r.strip())
		if m:
			ev.append((int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)))
	ev.sort(key=lambda e: e[0])
	out = {}
	cur = None
	marche = []
	for t, pid, k, m in ev:
		if k == 'mark':
			if pid != driver_pid:
				return None
			if m.startswith('qmp-'):
				continue			# #141: marcatore del cancello QMP, non un confine di caso
			marche.append(m)
			if m.startswith('ack-'):
				cur = m[4:]
				out[cur] = [0, 0]
			elif m.startswith('l1-') or m == 'fine':
				cur = None
			continue
		if pid not in vm_pids:
			return None
		if cur is not None:
			out[cur][0 if k == 'mmio' else 1] += 1
	attese = []
	for c in visti:
		attese.append('ack-' + c)
		if c in chiusi:
			attese.append('l1-' + c)
	if [x for x in marche if x != 'fine'] != attese or 'fine' not in marche:
		return None
	return {c: tuple(v) for c, v in out.items()}


def vmrun_dopo_errore(testo, vm_pids, driver_pid=None):
	"""#136 §6.1, #137 §5: dalla traccia FBT (righe k=vmrun, k=vmrun_err e i marcatori del driver, ordinate per
	timestamp: lo stesso orologio) quanti VM_RUN di QEMU sono iniziati DOPO il ritorno del primo VM_RUN fallito, e
	in quale finestra di caso e' caduto quell'errore (l'ultimo marcatore prima: 'ack-<caso>' -> caso; 'l1-' o
	'fine' -> nessun caso). Fail-closed: traccia non chiusa o evento da un pid fuori dal gruppo -> None.
	Ritorna {'errori': n, 'dopo': n, 'rc': primo errno, 'caso': nome o None}."""
	if '== FBT PRONTA ==' not in testo or '== FBT CHIUSA ==' not in testo:
		return None
	ev = []
	tids = set()			# #138 §3.1: thread che chiamano vm_run (con un vCPU: uno solo)
	for r in testo.splitlines():
		m = re.match(r'FBTEV t=(\d+) pid=(\d+) tid=(\d+) k=(vmrun|vmrun_err)(?: rc=(-?\d+))?$', r.strip())
		if m:
			if int(m.group(2)) not in vm_pids:
				return None
			tids.add(int(m.group(3)))
			ev.append((int(m.group(1)), m.group(4), m.group(5)))
			continue
		m = re.match(r'FBTEV t=(\d+) pid=(\d+) tid=\d+ k=mark m=(\S+)$', r.strip())
		if m and (driver_pid is None or int(m.group(2)) == driver_pid):
			ev.append((int(m.group(1)), 'mark', m.group(3)))
	ev.sort(key=lambda e: e[0])
	t0, rc, errori, dopo, caso, ultimo = None, None, 0, 0, None, None
	# #141 §3.1: ingressi in vm_run PRIMA del marcatore 'qmp-cont' (deve essere 0: monitor pronto prima del primo)
	tc = [t for t, k, r in ev if k == 'mark' and r == 'qmp-cont']
	prima_cont = None if not tc else sum(1 for t, k, r in ev if k == 'vmrun' and t < tc[0])
	for t, k, r in ev:
		if k == 'mark':
			if r.startswith('qmp-'):
				continue
			ultimo = r
		elif k == 'vmrun_err':
			errori += 1
			if t0 is None:
				t0, rc = t, int(r)
				caso = ultimo[4:] if ultimo is not None and ultimo.startswith('ack-') else None
		elif t0 is not None and t > t0:
			dopo += 1
	return {'errori': errori, 'dopo': dopo, 'rc': rc, 'caso': caso, 'tids': len(tids), 'prima_cont': prima_cont}


def fatali_da_fbt(testo, vm_pids, driver_pid=None):
	"""#142 §4.1: le sonde del latch (ptpad-fbt-ripfix-nested.d). None se la traccia non le aveva ARMATE (manca
	'== FBT SONDE FATALI ==') o non e' chiusa, o se un evento viene da un pid fuori dal gruppo della VM. Ogni
	evento e' attribuito alla finestra del caso (ultimo marcatore 'ack-<caso>' prima, come vmrun_dopo_errore).
	Ritorna i campi della riga FBTF: il PRIMO latch, il PRIMO ritorno, la PRIMA Fase C, le riflessioni (veptrefl)
	nella finestra del caso del latch, e l'ordine latch <= ritorno <= primo vmrun_err sullo stesso thread."""
	if '== FBT PRONTA ==' not in testo or '== FBT CHIUSA ==' not in testo or '== FBT SONDE FATALI ==' not in testo:
		return None
	ev = []
	for r in testo.splitlines():
		r = r.strip()
		m = re.match(r'FBTEV t=(\d+) pid=(\d+) tid=(\d+) k=(fatal|fatalret|veptunemul|veptrefl|vmrun_err)\b(.*)$', r)
		if m:
			if int(m.group(2)) not in vm_pids:
				return None
			kv = dict(x.split('=', 1) for x in m.group(5).split() if '=' in x)
			ev.append((int(m.group(1)), m.group(4), int(m.group(3)), kv))
			continue
		m = re.match(r'FBTEV t=(\d+) pid=(\d+) tid=\d+ k=mark m=(\S+)$', r)
		if m and (driver_pid is None or int(m.group(2)) == driver_pid) and not m.group(3).startswith('qmp-'):
			ev.append((int(m.group(1)), 'mark', 0, {'m': m.group(3)}))
	ev.sort(key=lambda e: e[0])
	ultimo, primo = None, {}
	finestra = {}			# caso -> riflessioni veptrefl nella sua finestra
	for t, k, tid, kv in ev:
		if k == 'mark':
			ultimo = kv['m'][4:] if kv['m'].startswith('ack-') else None
			continue
		if k == 'veptrefl':
			if ultimo is not None:
				finestra[ultimo] = finestra.get(ultimo, 0) + 1
			continue
		primo.setdefault(k, (t, tid, kv, ultimo))
	n = lambda k: sum(1 for e in ev if e[1] == k)
	f = {'sonde': 1, 'latch': n('fatal'), 'ritorno': n('fatalret'), 'unemul': n('veptunemul')}
	la, rt, un, er = primo.get('fatal'), primo.get('fatalret'), primo.get('veptunemul'), primo.get('vmrun_err')
	f['errno'] = la[2].get('errno', '-') if la else '-'
	f['stadio'] = la[2].get('stadio', '-') if la else '-'
	f['rip'] = la[2].get('rip', '-') if la else '-'
	f['gpa'] = la[2].get('gpa', '-') if la else '-'
	f['caso'] = (la[3] or '-') if la else '-'
	f['nextrip'] = rt[2].get('nextrip', '-') if rt else '-'
	f['rip_r'] = rt[2].get('rip', '-') if rt else '-'
	f['len'] = rt[2].get('len', '-') if rt else '-'
	f['frip'] = rt[2].get('frip', '-') if rt else '-'
	f['unemul_gpa'] = un[2].get('gpa', '-') if un else '-'
	f['unemul_caso'] = (un[3] or '-') if un else '-'
	f['refl_caso'] = finestra.get(la[3], 0) if la and la[3] else '-'
	if la and rt and er:
		f['ordine'] = 1 if (la[0] <= rt[0] <= er[0] and la[1] == rt[1] == er[1]) else 0
	else:
		f['ordine'] = '-'
	return f


FBTF_CAMPI = ('sonde', 'latch', 'errno', 'stadio', 'rip', 'gpa', 'caso', 'ritorno', 'nextrip', 'rip_r', 'len', 'frip',
    'unemul', 'unemul_gpa', 'unemul_caso', 'refl_caso', 'ordine')


def qmp_lettore(percorso, q, prima_del_cont=None, attesa=5.0):
	"""#140 §3, #141 §3.1: cancello di OSSERVABILITA'. QEMU parte FERMA (-S): nessun VM_RUN prima di 'cont'
	(cpu_can_run e' falso finche' la VM non e' in esecuzione). Si connette al socket (fino ad 'attesa' s), legge il
	saluto, negozia qmp_capabilities e ne ATTENDE il successo -> 'QMP_READY'; chiama prima_del_cont() (il marcatore
	FBT 'qmp-cont'), invia 'cont' -> 'QMP_CONT_INVIATO'; poi registra ogni riga fino a EOF -> 'QMP_EOF'. Qualunque
	fallimento prima del cont -> 'QMP_NON_PRONTO <motivo>': il driver si ferma e la VM non viene mai fatta partire."""
	import socket
	t = lambda: time.monotonic_ns()
	s, motivo, t_fine = None, 'timeout', time.monotonic() + attesa
	while time.monotonic() < t_fine:
		try:
			s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			s.connect(percorso)
			break
		except OSError as ex:
			s.close()
			s, motivo = None, str(ex)
			time.sleep(0.05)
	if s is None:
		q.put(('qmp', t(), 'QMP_NON_PRONTO connessione: %s' % motivo))
		return
	s.settimeout(attesa)
	f = s.makefile('rb')
	try:
		saluto = f.readline().decode('utf-8', 'replace').rstrip('\r\n')
		q.put(('qmp', t(), saluto))
		if '"QMP"' not in saluto:
			q.put(('qmp', t(), 'QMP_NON_PRONTO saluto inatteso'))
			return
		s.sendall(b'{"execute": "qmp_capabilities"}\n')
		while True:
			r = f.readline().decode('utf-8', 'replace').rstrip('\r\n')
			if r == '':
				q.put(('qmp', t(), 'QMP_NON_PRONTO EOF durante la negoziazione'))
				return
			q.put(('qmp', t(), r))
			if r.startswith('{"return"'):
				break
			if r.startswith('{"error"'):
				q.put(('qmp', t(), 'QMP_NON_PRONTO capabilities rifiutate'))
				return
	except OSError as ex:
		q.put(('qmp', t(), 'QMP_NON_PRONTO negoziazione: %s' % ex))
		return
	q.put(('qmp', t(), 'QMP_READY'))
	if prima_del_cont is not None:
		prima_del_cont()
	s.sendall(b'{"execute": "cont"}\n')
	q.put(('qmp', t(), 'QMP_CONT_INVIATO'))
	s.settimeout(None)
	for b in iter(f.readline, b''):
		q.put(('qmp', t(), b.decode('utf-8', 'replace').rstrip('\r\n')))
	q.put(('qmp', t(), 'QMP_EOF'))


def qmp_evento(riga):
	"""Una riga QMP -> 'EVENT QMP_<NOME> ...' per gli eventi che contano (SHUTDOWN con guest e reason, STOP,
	RESUME), oppure None."""
	import json
	if riga.startswith(('QMP_NON_PRONTO', 'QMP_READY', 'QMP_CONT_INVIATO', 'QMP_EOF')):
		return 'EVENT ' + riga
	try:
		j = json.loads(riga)
	except ValueError:
		return None
	ev = j.get('event') if isinstance(j, dict) else None
	if ev == 'SHUTDOWN':
		d = j.get('data') or {}
		return 'EVENT QMP_SHUTDOWN guest=%s reason=%s' % (str(d.get('guest')).lower(), d.get('reason'))
	if ev in ('STOP', 'RESUME'):
		return 'EVENT QMP_%s' % ev
	return None


def identita_esecuzione(pid):
	"""#137 §4: binario e libvmmapi EFFETTIVAMENTE in uso nel processo (procstat), non quelli del file su disco."""
	b = subprocess.run(['/usr/bin/procstat', '-b', str(pid)], capture_output=True, text=True).stdout.splitlines()
	binario = b[1].split()[-1] if len(b) > 1 else '?'
	libs = set()
	for x in subprocess.run(['/usr/bin/procstat', '-v', str(pid)], capture_output=True, text=True).stdout.splitlines():
		f = x.split()
		if f and 'libvmmapi' in f[-1]:
			libs.add(f[-1])
	return binario, ','.join(sorted(libs)) or 'assente'


def inserisci_fbt(combinato, conte):
	"""Aggiunge 'FBT mmio=<0|1> ptp=<0|1>' dopo la riga CASE di ogni caso con finestra FBT."""
	righe = []
	for r in combinato.splitlines():
		righe.append(r)
		m = re.match(r'CASE (\S+)$', r)
		if m and conte is not None and m.group(1) in conte:
			mm, ww = conte[m.group(1)]
			righe.append('FBT mmio=%d ptp=%d' % (mm > 0, ww > 0))
	return '\n'.join(righe) + '\n'


def lettore(flusso, q, tag):
	for b in iter(flusso.readline, b''):
		q.put((tag, time.monotonic_ns(), b.decode('utf-8', 'replace').rstrip('\r\n')))
	q.put((tag, time.monotonic_ns(), None))


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument('--piano', required=True)
	ap.add_argument('--out', required=True)
	ap.add_argument('--fbt')
	ap.add_argument('--timeout', type=int, default=120)
	ap.add_argument('--ctr-cmd', default='/sbin/sysctl -n hw.vmm.vmx.nested_ept_mmio_emulated')
	ap.add_argument('--rfl-cmd', default='/sbin/sysctl -n hw.vmm.vmx.nested_ept12_viol_reflected')
	ap.add_argument('--rfe-cmd', default='/sbin/sysctl -n hw.vmm.vmx.nested_ept12_viol_emul_reflected')
	ap.add_argument('--est-cmd', default='/sbin/sysctl -n hw.vmm.vmx.nested_ept12_viol_emul_stale')
	ap.add_argument('--enc-cmd', default='/sbin/sysctl -n hw.vmm.vmx.nested_ept12_viol_emul_nocache')
	ap.add_argument('--rtx-cmd', default='/sbin/sysctl -n hw.vmm.vmx.vept_ptp_write_retry_xlate')
	ap.add_argument('--rtr-cmd', default='/sbin/sysctl -n hw.vmm.vmx.vept_ptp_write_retry_remap')
	ap.add_argument('--dtrace-cmd', default='sudo -n /usr/sbin/dtrace')
	ap.add_argument('--kill-cmd', default='sudo -n kill -TERM')
	# collaudo: i contatori H2 da file <dir>/<sigla> invece che dai sysctl dell'host (che col modulo
	# H2 caricato sarebbero VERI anche in una prova con la VM finta)
	ap.add_argument('--h2-dir', default=None)
	# #131: dopo il primo "Error running vm" si osserva per N secondi prima di chiudere (errore singolo, ciclo
	# caldo, uscita spontanea di QEMU)
	ap.add_argument('--err-window', type=float, default=2.0)
	# SOLO collaudo (il runner non lo passa mai): os.killpg fallisce con EPERM, per provare RUNNER=UNKNOWN
	ap.add_argument('--collaudo-killpg-fallito', action='store_true')
	# #137 §4: nome (inizio di comm) del processo di cui registrare binario e libvmmapi in uso (IDENT)
	ap.add_argument('--ident-comm', default='qemu-system')
	# #140 §3: socket QMP di QEMU da cui registrare SHUTDOWN (causa) e STOP
	ap.add_argument('--qmp', default=None)
	# SOLO collaudo (#134 §7): eccezione dopo il primo ACK, per provare che pulizia_finale chiude il gruppo
	ap.add_argument('--collaudo-eccezione', action='store_true')
	ap.add_argument('--oracolo', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
	    '..', '..', '..', 'ptpad_an.py'))
	ap.add_argument('vm', nargs=argparse.REMAINDER)
	a = ap.parse_args()
	vm = a.vm[1:] if a.vm[:1] == ['--'] else a.vm
	if not vm or not piano_valido(a.piano):
		print('STOP: piano non valido o comando VM assente', file=sys.stderr)
		return 2
	os.makedirs(a.out, exist_ok=True)
	comb = open(os.path.join(a.out, 'combinato.txt'), 'w', buffering=1)
	ser = open(os.path.join(a.out, 'seriale.txt'), 'w', buffering=1)
	err = open(os.path.join(a.out, 'qemu-stderr.txt'), 'w', buffering=1)
	log = open(os.path.join(a.out, 'driver.txt'), 'w', buffering=1)

	def dice(s):
		log.write('%d %s\n' % (time.monotonic_ns(), s))

	def ctr(cmd=None):
		return subprocess.run(shlex.split(cmd or a.ctr_cmd), capture_output=True, text=True,
		    check=True).stdout.strip()

	def rfl():
		return ctr(a.rfl_cmd)

	opz = []			# contatori opzionali presenti: (sigla, comando)
	h2_opz = H2_OPZ if a.h2_dir is None else tuple((x, 'cat %s/%s' % (a.h2_dir, x)) for x, _ in H2_OPZ)
	for sigla, cmd in (('RFE', a.rfe_cmd), ('EST', a.est_cmd), ('ENC', a.enc_cmd),
	    ('RTX', a.rtx_cmd), ('RTR', a.rtr_cmd)) + h2_opz:
		try:
			ctr(cmd)
			opz.append((sigla, cmd))
		except (subprocess.CalledProcessError, OSError):
			pass

	# parere #107 §1: il cancello per caso usa LO STESSO oracolo dell'analisi offline
	import importlib.util
	sp = importlib.util.spec_from_file_location('ptpad_an', a.oracolo)
	an = importlib.util.module_from_spec(sp)
	sp.loader.exec_module(an)
	blocchi = {}			# caso -> righe del log combinato del caso

	def scrivi(riga):
		comb.write(riga + '\n')
		if aperto_ref[0] is not None:
			blocchi.setdefault(aperto_ref[0], []).append(riga)

	aperto_ref = [None]
	mappa = []			# la riga MAP di L1, una sola, prima dei casi
	sessione = []			# #131: righe MEM/FIXMMIO/PCIDEV/BRIDGE/BAR, per il cancello

	def cancello(n):
		"""None se il caso puo' far proseguire la sessione, altrimenti il motivo dello STOP.
		B deve essere ARCH_PASS (cancello B); gli altri: delta esattamente 1 e un esito pulito."""
		# la riga MAP precede i casi: senza, il cancello non vedrebbe pteaddr (casi H)
		if n in CASI_DIAGNOSI:
			return None		# #131: l'esito e' la diagnosi, e il caso e' l'ultimo
		casi = an.leggi('\n'.join(sessione + mappa + blocchi.get(n, [])) + '\n')[0]
		c = casi.get(n)
		if c is None:
			return 'blocco del caso illeggibile'
		v, perche = an.verdetto(n, c)
		if n == 'B' and v != 'PATH_COVERED_ARCH_PASS':
			return 'B_GATE_FALLITO: %s (%s)' % (v, perche)
		if n in CASI_HW:
			# controllo hardware: entrambi gli esiti sono DATI (anche NO_VIOLATION); il resto ferma
			if v not in ('HW_CONTROL_PASS', 'HW_CONTROL_NO_VIOLATION'):
				return 'caso %s: %s (%s)' % (n, v, perche)
			return None
		if an.delta(c) != 1:
			return 'delta %s != 1 al caso %s' % (an.delta(c), n)
		if v not in ('PATH_COVERED_ARCH_PASS', 'PATH_COVERED_H1_REPRODUCED'):
			return 'caso %s: %s (%s)' % (n, v, perche)
		return None

	dice('piano %s; vm: %s; oracolo %s' % (a.piano, ' '.join(vm), a.oracolo))
	for sigla in ('RFE', 'EST', 'ENC', 'RTX', 'RTR') + tuple(x for x, _ in H2_OPZ):
		dice('%s %s' % (sigla, 'presente' if sigla in dict(opz) else 'ASSENTE (modulo senza il contatore)'))

	def fotografa_chiusura(term):
		# H2 (#119 §3.2): caso aperto chiuso SENZA risposta di L1 (tempo scaduto, VM uscita da sola):
		# i contatori host restano leggibili e dicono se L0 ha emulato a ripetizione (stesso RIP)
		# o se la VM si e' spenta fail-closed (ENC); l'oracolo decide
		comb.write('CTR after=%s\n' % ctr())
		comb.write('RFL after=%s\n' % rfl())
		for sigla, cmd in opz:
			comb.write('%s after=%s\n' % (sigla, ctr(cmd)))
		comb.write('TERM %s\n' % term)
	# il piano RICHIESTO apre il log (cosi' l'analisi lo conosce anche se L1 diverge); l'eco di L1
	# va in PLANECO e la sessione prosegue solo se coincide
	comb.write('PLAN cases=%s\n' % a.piano)
	dt = None
	if a.fbt:
		fo = os.path.join(a.out, 'fbt.txt')
		open(fo, 'w').close()
		dt = subprocess.Popen(shlex.split(a.dtrace_cmd) + ['-q', '-s', a.fbt, '-o', fo, str(os.getpid())],
		    stdout=subprocess.DEVNULL, stderr=open(os.path.join(a.out, 'fbt.err'), 'w'))
		POSSEDUTI['dtrace'].append(dt)
		POSSEDUTI['kill_cmd'] = shlex.split(a.kill_cmd)
		for _ in range(60):
			if '== FBT PRONTA ==' in open(fo).read():
				break
			if dt.poll() is not None:
				break
			time.sleep(0.25)
		if '== FBT PRONTA ==' not in open(fo).read():
			dice('STOP: dtrace non pronto, nessuna VM avviata')
			subprocess.run(shlex.split(a.kill_cmd) + [str(dt.pid)])
			dt.wait()
			return 4
		dice('FBT pronta')

	# process group proprio: la terminazione colpisce cpuset/timeout/QEMU e nient'altro (#107 §3)
	p = subprocess.Popen(vm, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
	    start_new_session=True)
	POSSEDUTI['gruppi'].append(p.pid)
	dice('vm pid %d pgid %d' % (p.pid, p.pid))
	vm_pids = set()
	identificati = []

	def membri():
		r = subprocess.run(['/bin/ps', '-ax', '-o', 'pid=', '-o', 'pgid=', '-o', 'comm='],
		    capture_output=True, text=True).stdout
		for x in r.splitlines():
			f = x.split()
			if len(f) >= 3 and f[1] == str(p.pid):
				if int(f[0]) not in vm_pids:
					dice('membro del gruppo: pid %s comm %s' % (f[0], f[2]))
					if f[2].startswith(a.ident_comm) and not identificati:
						# #137 §4: identita' di esecuzione, registrata una volta
						b, l = identita_esecuzione(int(f[0]))
						comb.write('IDENT pid=%s bin=%s libvmmapi=%s\n' % (f[0], b, l))
						identificati.append(f[0])
				vm_pids.add(int(f[0]))

	uccisa = []			# segnali davvero consegnati dal driver al gruppo di QEMU
	fallita = []			# #132 §3.2: killpg falliti (errno), registrati senza sovrascrivere l'esito
	def termina(motivo):
		if p.poll() is not None:
			return
		membri()
		for sig, nome in ((signal.SIGTERM, 'TERM'), (signal.SIGKILL, 'KILL')):
			try:
				if a.collaudo_killpg_fallito:
					raise PermissionError(1, 'collaudo: killpg fallito')
				os.killpg(p.pid, sig)
			except ProcessLookupError:
				break
			except OSError as ex:
				fallita.append('%s:%s' % (nome, ex.errno))
				comb.write('EVENT KILL_FAILED segnale=%s errno=%s motivo=%s\n' % (nome, ex.errno, motivo))
				continue
			uccisa.append(nome)
			comb.write('EVENT QEMU_TERMINATED_BY_DRIVER segnale=%s motivo=%s\n' % (nome, motivo))
			try:
				p.wait(5)
				break
			except subprocess.TimeoutExpired:
				continue
	q = queue.Queue()
	threading.Thread(target=lettore, args=(p.stdout, q, 'out'), daemon=True).start()
	threading.Thread(target=lettore, args=(p.stderr, q, 'err'), daemon=True).start()
	if a.qmp:
		qmpf = open(os.path.join(a.out, 'qmp.txt'), 'w', buffering=1)
		threading.Thread(target=qmp_lettore, args=(a.qmp, q, lambda: segna('qmp-cont')), daemon=True).start()
	qmp_stato = {'eof': False, 'non_pronto': None}

	def qmp_tratta(t, riga):
		qmpf.write('%d %s\n' % (t, riga))
		if riga == 'QMP_EOF':
			qmp_stato['eof'] = True
		if riga.startswith('QMP_NON_PRONTO'):
			qmp_stato['non_pronto'] = riga
		e = qmp_evento(riga)
		if e is not None:
			if aperto is not None:
				scrivi(e)
			else:
				comb.write(e + '\n')

	def invia(b):
		try:
			p.stdin.write(b)
			p.stdin.flush()
		except BrokenPipeError:
			dice('invio fallito: L1 non legge piu\' (VM uscita)')

	esito, uscita = None, 0
	aperto = None			# caso con ack inviato e senza riga L1
	errvm = {'t0': None, 'n': 0, 'ctr0': 0, 'fatto': False, 'ser': 0}

	def chiudi_errore(qemu_uscito, motivo):
		# #131 §6.2: fine della finestra di osservazione dopo il primo errore di VM_RUN in un caso aperto.
		# #132 §3.2: motivo = finestra (2 s di silenzio), ripetuti (secondo errore), emulazioni (il contatore
		# sale dopo l'errore), uscita (QEMU chiusa da sola), subito (caso che non ammette finestra); seriale_dopo =
		# righe di L1 dopo l'errore (progressione del guest)
		nonlocal esito, uscita
		segna('fine')
		c1 = ctr()
		comb.write('EVENT VMRUN_ERRORS n=%d ctr_delta=%d qemu_uscito=%d seriale_dopo=%d ms=%d motivo=%s\n' % (
		    errvm['n'], int(c1) - errvm['ctr0'], 1 if qemu_uscito else 0, errvm['ser'],
		    int((time.monotonic() - errvm['t0']) * 1000), motivo))
		comb.write('CTR after=%s\n' % c1)
		comb.write('RFL after=%s\n' % rfl())
		for sigla, cmd in opz:
			comb.write('%s after=%s\n' % (sigla, ctr(cmd)))
		comb.write('TERM bhyve_died\n')
		esito = 'VMRUN_ERROR_QEMU caso %s' % aperto
		if aperto is None or (not aperto.startswith('D_') and aperto not in CASI_DIAGNOSI):
			# DM reale 30/10: il caso era gia' chiuso dalla riga L1 (guest avanti) e QEMU e' uscita a fine serie;
			# prima qui il driver crollava (aperto None). Ora: STOP registrato, nessuna eccezione
			uscita = 2
			comb.write('STOP kind=VMRUN motivo=errore di VM_RUN nel caso non-D %s\n' % aperto)
		errvm['fatto'] = True
		termina('VMRUN_ERROR_QEMU')
	visti = []			# casi aperti, in ordine
	chiusi = []			# casi con riga L1
	pianook = False			# eco del piano ricevuta e uguale
	fine = {'out': False, 'err': False}
	scadenza = time.monotonic() + a.timeout
	rfl0 = [None]			# RFL alla riga CASE del caso aperto (#132 §3.2, HM)
	while not (fine['out'] and fine['err']):
		if errvm['t0'] is not None and not errvm['fatto']:
			if time.monotonic() - errvm['t0'] > a.err_window:
				chiudi_errore(False, 'finestra')
				break
			if int(ctr()) - errvm['ctr0'] >= SOGLIA_EMULAZIONI:
				chiudi_errore(False, 'emulazioni')	# l'istruzione rientra nell'emulatore: non si aspetta
				break
		if aperto in ('HM_PTP',) and rfl0[0] is not None and errvm['t0'] is None:
			if int(rfl()) - rfl0[0] >= SOGLIA_RIFLESSIONI:
				segna('fine')
				fotografa_chiusura('rfl_loop')
				esito, uscita = 'LOOP_RIFLESSIONI caso %s' % aperto, 2
				comb.write('STOP kind=LOOP motivo=%d riflessioni senza risposta di L1 nel caso %s\n' % (SOGLIA_RIFLESSIONI, aperto))
				break
		try:
			tag, t, riga = q.get(timeout=0.2)
		except queue.Empty:
			if time.monotonic() > scadenza:
				esito, uscita = 'TIMEOUT', 3
				if aperto is not None:
					segna('fine')
					fotografa_chiusura('timeout')
				comb.write('STOP kind=TIMEOUT motivo=nessuna riga entro %d s\n' % a.timeout)
				break
			continue
		if tag == 'qmp':
			qmp_tratta(t, riga)
			if qmp_stato['non_pronto']:
				# #141 §3.1: monitor non pronto -> la VM (ferma, -S) NON viene fatta partire
				esito, uscita = 'STOP %s' % qmp_stato['non_pronto'], 2
				comb.write('STOP kind=QMP motivo=%s\n' % qmp_stato['non_pronto'])
				break
			continue
		if riga is None:
			fine[tag] = True
			continue
		if tag == 'err':
			err.write('%d %s\n' % (t, riga))
			if 'porta chiusa, nessun nuovo VM_RUN' in riga or 'porta della VM chiusa dal vCPU' in riga:
				# #136 §6.1: la porta di QEMU si e' chiusa (frontend corretto): evento, non verdetto
				ev = 'EVENT QEMU_PORTA_VM ' if 'porta della VM' in riga else 'EVENT QEMU_PORTA '
				if aperto is not None:
					scrivi(ev + riga)
				else:
					comb.write(ev + riga + '\n')
				continue
			if riga.startswith('Error running vm'):
				if aperto is None:
					membri()
					comb.write('EVENT VMRUN_ERROR_QEMU caso=- riga=%s\n' % riga)
					esito, uscita = 'STOP errore di VM_RUN fuori da un caso', 2
					comb.write('STOP kind=VMRUN motivo=fuori da un caso\n')
					termina('VMRUN_ERROR_QEMU')
					break
				if errvm['t0'] is None:
					# #131: primo errore: si apre la finestra; TERM bhyve_died = VM_RUN ha restituito errore
					# al processo QEMU, NON la morte di un bhyve standalone (compatibilita' con ptpad_an)
					membri()
					comb.write('EVENT VMRUN_ERROR_QEMU caso=%s riga=%s\n' % (aperto, riga))
					errvm['t0'], errvm['n'], errvm['ctr0'] = time.monotonic(), 1, int(ctr())
					if aperto not in CASI_D and aperto not in CASI_DIAGNOSI:
						chiudi_errore(False, 'subito')	# #132 §3.2: nessuna finestra fuori dai casi D/diagnosi
						break
				else:
					errvm['n'] += 1
				if errvm['n'] >= SOGLIA_ERRORI:
					chiudi_errore(False, 'ripetuti')	# #132 §3.2: secondo errore, si ferma SUBITO
					break
			continue
		ser.write('%d %s\n' % (t, riga))
		if errvm['t0'] is not None:
			# #143 (corsa fra i due tubi, collaudo k5 del 30/10): EPT/EPTW del caso aperto L1 le scrive PRIMA di
			# entrare in L2; stdout e stderr sono letti da due thread, quindi possono arrivare DOPO la riga d'errore
			# pur essendo state scritte prima. Non sono progresso del guest, finche' nessun'altra riga e' arrivata.
			# #144 §1.3: esenti SOLO una EPT e una EPTW del caso APERTO, nel formato esatto del protocollo; duplicati,
			# righe malformate o di un altro caso contano come progresso (il seriale grezzo resta comunque intero)
			pre = errvm.setdefault('pre', set())
			k = None
			if re.match(r'PTPAD EPT t=[0-9a-f]+ pd=[0-9a-f]+ d=[0-9a-f]+$', riga):
				k = 'EPT'
			elif aperto is not None and re.match(r'PTPAD EPTW %s t=[0-9a-f]+/\d l4=[0-9a-f]+/\d l3=[0-9a-f]+/\d '
			    r'l2=[0-9a-f]+/\d d=[0-9a-f]+/\d ok=[01]$' % re.escape(aperto), riga):
				k = 'EPTW'
			if errvm['ser'] == 0 and k is not None and k not in pre:
				pre.add(k)
				dice('riga pre-ingresso letta dopo l\'errore (non e\' progresso): %s' % riga)
			else:
				errvm['ser'] += 1	# #132 §3.2: L1 scrive dopo l'errore = il guest progredisce
		if riga.startswith(RIGHE_SESSIONE):
			# #131: regioni di L1 (RAM, Y, MMIO fisso, PCI) una volta, prima dei casi
			if visti:
				esito, uscita = 'STOP riga di sessione dopo l\'inizio dei casi', 2
				comb.write('STOP kind=PROTOCOL motivo=riga di sessione dopo un CASE\n')
				break
			comb.write(riga[len('PTPAD '):] + '\n')
			sessione.append(riga[len('PTPAD '):])
			continue
		if riga.startswith('PTPAD MAP '):
			if visti:
				esito, uscita = 'STOP riga MAP dopo l\'inizio dei casi', 2
				comb.write('STOP kind=PROTOCOL motivo=MAP dopo un CASE\n')
				break
			if mappa:
				esito, uscita = 'STOP riga MAP ripetuta', 2
				comb.write('STOP kind=PROTOCOL motivo=MAP ripetuta\n')
				break
			mappa.append('MAP %s' % riga[len('PTPAD MAP '):])
			comb.write(mappa[0] + '\n')
		elif riga == 'PTPAD WAIT piano':
			invia((a.piano + '\n').encode())
		elif riga.startswith('PTPAD PLAN '):
			m = re.match(r'PTPAD PLAN cases=(\S+)$', riga)
			comb.write('PLANECO %s\n' % riga[len('PTPAD PLAN '):])
			if not m or m.group(1) != a.piano or pianook or visti:
				esito, uscita = 'STOP piano di L1 diverso da quello richiesto: %s' % riga, 2
				comb.write('STOP kind=PROTOCOL motivo=eco del piano diversa o ripetuta\n')
				break
			pianook = True
		elif riga.startswith('PTPAD CASE '):
			n = riga[len('PTPAD CASE '):]
			# #107 §1: piano eco gia' verificato, e il CASE dev'essere ESATTAMENTE il prossimo del piano
			prossimo = a.piano.split(',')[len(visti)] if len(visti) < len(a.piano.split(',')) else None
			if not pianook or aperto is not None or n != prossimo:
				esito, uscita = 'STOP CASE %s inatteso (atteso %s, aperto %s)' % (n, prossimo, aperto), 2
				comb.write('STOP kind=PROTOCOL motivo=CASE %s fuori sequenza\n' % n)
				break
			if n in CASI_Y:
				motivo = an.regioni_motivo(an.sessione_da_testo('\n'.join(sessione) + '\n'))
				if motivo is not None:
					# #132 §3.1: nessun ACK, il caso non entra in L2: resta NOT_RUN_FERMATA
					esito, uscita = 'STOP regioni di L1 prima di %s: %s' % (n, motivo), 2
					comb.write('STOP kind=GATE motivo=regioni prima di %s: %s\n' % (n, motivo))
					break
			aperto = aperto_ref[0] = n
			scrivi('CASE %s' % n)
			scrivi('CTR before=%s' % ctr())
			r0 = rfl()
			scrivi('RFL before=%s' % r0)
			rfl0[0] = int(r0)
			for sigla, cmd in opz:
				scrivi('%s before=%s' % (sigla, ctr(cmd)))
			segna('ack-' + n)
			visti.append(n)
			membri()
			invia(b'g')
			if a.collaudo_eccezione:
				raise RuntimeError('collaudo: eccezione dopo l\'ACK di %s' % n)
		elif riga.startswith('PTPAD EPT '):
			# G1b (#126): voci foglia di EPT12 di T, PD e D prima del run, dentro il blocco del caso
			if aperto is None:
				esito, uscita = 'STOP riga EPT senza caso aperto', 2
				comb.write('STOP kind=PROTOCOL motivo=EPT senza caso\n')
				break
			scrivi(riga[len('PTPAD '):])
		elif riga.startswith(('PTPAD EPTW ', 'PTPAD EPTPOST ', 'PTPAD EPTBAD ')):
			# #132 §3.1/§4: traduzione EPT12 del caso verificata da L1 subito prima e subito dopo l'entrata
			if aperto is None:
				esito, uscita = 'STOP riga %s senza caso aperto' % riga.split()[1], 2
				comb.write('STOP kind=PROTOCOL motivo=%s senza caso\n' % riga.split()[1])
				break
			scrivi(riga[len('PTPAD '):])
			if riga.startswith('PTPAD EPTBAD '):
				segna('fine')
				fotografa_chiusura('vm_exited')
				esito, uscita = 'STOP EPT12 del caso %s diversa da quella attesa (L2 non eseguito)' % aperto, 2
				comb.write('STOP kind=GATE motivo=EPTBAD %s\n' % aperto)
				break
		elif riga.startswith('PTPAD LIV '):
			# H2-AD (#123 §3): i quattro livelli del walk di D prima/dopo, dentro il blocco del caso
			if aperto is None:
				esito, uscita = 'STOP riga LIV senza caso aperto', 2
				comb.write('STOP kind=PROTOCOL motivo=LIV senza caso\n')
				break
			scrivi(riga[len('PTPAD '):])
		elif riga.startswith('PTPAD XINFO '):
			if aperto is None:
				esito, uscita = 'STOP riga XINFO senza caso aperto', 2
				comb.write('STOP kind=PROTOCOL motivo=XINFO senza caso\n')
				break
			scrivi(riga[len('PTPAD '):])
		elif riga.startswith('PTPAD L1 '):
			if aperto is None:
				esito, uscita = 'STOP riga L1 senza caso aperto', 2
				break
			segna('l1-' + aperto)
			if errvm['t0'] is not None and not errvm['fatto']:
				# DM reale 30/10: dopo UN errore di VM_RUN QEMU rientra e L1 RISPONDE (il movsq e' stato saltato:
				# nextrip gia' avanzato da vm_handle_inst_emul). La finestra si chiude QUI, nel blocco del caso,
				# con motivo=l1; il caso resta vivo e la sessione prosegue
				scrivi('EVENT VMRUN_ERRORS n=%d ctr_delta=%d qemu_uscito=0 seriale_dopo=%d ms=%d motivo=l1' % (
				    errvm['n'], int(ctr()) - errvm['ctr0'], errvm['ser'], int((time.monotonic() - errvm['t0']) * 1000)))
				errvm['fatto'] = True
			scrivi(riga[len('PTPAD '):])
			scrivi('CTR after=%s' % ctr())
			scrivi('RFL after=%s' % rfl())
			for sigla, cmd in opz:
				scrivi('%s after=%s' % (sigla, ctr(cmd)))
			scrivi('TERM alive')
			chiusi.append(aperto)
			motivo = cancello(aperto)
			aperto = aperto_ref[0] = None
			if motivo is not None:
				# #107 §1: NESSUN ACK al caso successivo; L1 resta fermo e la VM si chiude
				esito, uscita = 'STOP %s' % motivo, 2
				comb.write('STOP kind=GATE motivo=%s\n' % motivo)
				break
		elif riga.startswith('PTPAD NOACK') or riga.startswith('PTPAD PLAN rifiutato'):
			esito, uscita = 'STOP %s' % riga, 2
			comb.write('STOP kind=PROTOCOL motivo=%s\n' % riga)
			break

	if a.qmp and not qmp_stato['non_pronto']:
		# #141 §3.2: gli eventi QMP che restano in coda si leggono FINO A EOF del socket (QEMU uscita), entro un
		# limite dichiarato di 2 s; la chiusura si registra (eof=1) o no (eof=0: assenza non provata)
		t_q = time.monotonic() + 2.0
		while not qmp_stato['eof'] and time.monotonic() < t_q:
			try:
				tag, t, riga = q.get(timeout=0.1)
			except queue.Empty:
				continue
			if tag == 'qmp' and riga is not None:
				qmp_tratta(t, riga)
		comb.write('EVENT QMP_CHIUSURA eof=%d\n' % (1 if qmp_stato['eof'] else 0))
	if errvm['t0'] is not None and not errvm['fatto']:
		chiudi_errore(True, 'uscita')	# #131: QEMU ha chiuso da solo durante la finestra dopo l'errore
	segna('fine')
	termina(esito or 'fine della serie')
	try:
		rc = p.wait(10)			# #132 §3.2: mai appeso su una QEMU che non muore
	except subprocess.TimeoutExpired:
		rc = -999
	# superstiti del gruppo: il ripristino si dichiara solo se non ne resta nessuno
	vivi = [x.split()[0] for x in subprocess.run(['/bin/ps', '-ax', '-o', 'pid=', '-o', 'pgid='],
	    capture_output=True, text=True).stdout.splitlines() if len(x.split()) == 2 and x.split()[1] == str(p.pid)]
	if not vivi and rc != -999:
		POSSEDUTI['gruppi'].remove(p.pid)	# gruppo raccolto: niente segnali a un pgid che potrebbe essere riusato
	if vivi:
		comb.write('EVENT SURVIVORS pgid=%d pid=%s\n' % (p.pid, ','.join(vivi)))
		dice('superstiti del gruppo %d: %s' % (p.pid, vivi))
	if esito is None and rc == -999:
		esito, uscita = 'STOP la VM non termina', 5
	elif esito is None:
		if aperto is not None:
			esito, uscita = 'STOP caso %s senza risposta ne\' errore' % aperto, 2
			fotografa_chiusura('vm_exited')
			comb.write('STOP kind=PROTOCOL motivo=caso %s senza risposta\n' % aperto)
		elif visti != a.piano.split(','):
			# compreso L1 senza piano (report_skip): nessun caso, sessione NON completata
			esito, uscita = 'STOP casi eseguiti %s invece del piano %s' % (','.join(visti) or 'nessuno', a.piano), 2
			comb.write('STOP kind=PROTOCOL motivo=casi eseguiti %s\n' % (','.join(visti) or 'nessuno'))
		else:
			esito = 'COMPLETA'
	dice('vm rc=%d; esito %s' % (rc, esito))
	# #131 §6.2: esito del RUNNER, separato dall'esito tecnico del caso (che decide l'oracolo)
	# KILLED solo se il driver ha davvero consegnato un segnale per fermare una VM anomala (errori di VM_RUN, ciclo
	# di riflessioni); VM_EXITED se QEMU e' uscita da sola dopo l'errore; UNKNOWN (#132) se un killpg e' fallito o
	# resta un processo del gruppo: lo stato della VM non e' noto e il ripristino NON e' verificato
	anomalo = (esito or '').startswith(('VMRUN_ERROR', 'LOOP_RIFLESSIONI'))
	if vivi or (fallita and not uccisa) or rc == -999:
		runner = 'UNKNOWN'
		uscita = 5
	elif esito == 'COMPLETA':
		runner = 'COMPLETE'
	elif esito == 'TIMEOUT':
		runner = 'TIMED_OUT'
	elif anomalo:
		runner = 'KILLED' if uccisa else 'VM_EXITED'
	else:
		runner = 'STOPPED'
	comb.write('RUNNER=%s\n' % runner)
	comb.write('VM_RC=%d\n' % rc)
	dice('RUNNER=%s' % runner)
	comb.close()
	if dt is not None:
		time.sleep(0.5)			# switchrate 10hz: lascia uscire gli ultimi record
		subprocess.run(shlex.split(a.kill_cmd) + [str(dt.pid)])
		dt.wait()
		POSSEDUTI['dtrace'].remove(dt)
		ftesto = open(os.path.join(a.out, 'fbt.txt')).read()
		ferr = open(os.path.join(a.out, 'fbt.err')).read()
		# #138 §3.1: l'uscita 0 di dtrace non garantisce zero perdite; dtrace le dichiara su stderr ("N drops on
		# CPU k", "dynamic variable drops"). Si registra SEMPRE (senza la parola che l'oracolo tratta come perdita
		# globale quando e' presente): FBTV si scrive solo con stderr vuoto, quindi nessuna perdita dichiarata
		perse = sum(1 for x in ferr.splitlines() if 'drop' in x.lower())
		with open(os.path.join(a.out, 'combinato.txt'), 'a') as cf:
			cf.write('FBTSTATO stderr=%d righe_perdite=%d chiusa=%d\n' % (len(ferr), perse,
			    1 if '== FBT CHIUSA ==' in ftesto else 0))
		conte = fbt_per_caso(ftesto, os.getpid(), vm_pids, visti, chiusi)
		if conte is None or ferr.strip():
			# fail-closed (#107 §4): stderr di dtrace NON vuoto, traccia incompleta, pid estranei o
			# marcatori fuori protocollo -> nessuna riga FBT; i dati di L1 restano nel log
			dice('FBT NON utilizzabile (stderr %d byte, correlazione %s): nessuna riga FBT' %
			    (len(ferr), 'ok' if conte is not None else 'NON certa'))
			# #111 §5.4: perdite o correlazione incerta = sessione non conclusiva (l'oracolo vede DROP)
			with open(os.path.join(a.out, 'combinato.txt'), 'a') as cf:
				cf.write('FBTDROP stderr=%d correlazione=%s\n' %
				    (len(ferr), 'ok' if conte is not None else 'NON_CERTA'))
		else:
			cp = os.path.join(a.out, 'combinato.txt')
			testo = open(cp).read()
			open(os.path.join(a.out, 'combinato-senza-fbt.txt'), 'w').write(testo)
			open(cp, 'w').write(inserisci_fbt(testo, conte))
			dice('FBT per caso: %s' % conte)
			vr = vmrun_dopo_errore(ftesto, vm_pids, os.getpid())
			if vr is not None:
				# #136 §6.1: in coda (riferita all'ultimo caso del log); caso = la finestra dove cade il primo errore
				with open(cp, 'a') as cf:
					cf.write('FBTV errori=%d dopo_errore=%d rc=%s caso=%s tid=%d prima_cont=%s\n' % (vr['errori'],
					    vr['dopo'], vr['rc'], vr['caso'] or '-', vr['tids'],
					    '-' if vr['prima_cont'] is None else vr['prima_cont']))
				dice('FBT VM_RUN: %s' % vr)
			ff = fatali_da_fbt(ftesto, vm_pids, os.getpid())
			if ff is not None:
				# #142 §4.1: solo con le sonde del latch ARMATE (script RIPFIX); in coda come FBTV
				with open(cp, 'a') as cf:
					cf.write('FBTF %s\n' % ' '.join('%s=%s' % (k, ff[k]) for k in FBTF_CAMPI))
				dice('FBT latch: %s' % ff)
	print('ESITO=%s RUNNER=%s VM_RC=%d USCITA=%d' % (esito, runner, rc, uscita))
	dice('ESITO=%s USCITA=%d' % (esito, uscita))
	return uscita


if __name__ == '__main__':
	for _s in (signal.SIGTERM, signal.SIGHUP):
		signal.signal(_s, _esci_per_segnale)
	try:
		_rc = main()
	finally:
		pulizia_finale()
	sys.exit(_rc)
