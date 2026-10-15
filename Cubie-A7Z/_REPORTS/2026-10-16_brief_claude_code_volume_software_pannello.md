# Brief per Claude Code — alzare via software il volume dell'altoparlante del pannello

Data: 16/10/2026
Da: Claude (sessione cloud, solo ricerca: **nessun accesso alla scheda**)
Per: Claude Code con accesso alla Cubie A7Z (Allwinner A733 / sun60iw2),
FreeBSD 15.0-RELEASE-p3, kernel `#132 a733-bringup`

Documenti collegati: la domanda del 16/10/2026 sul pannello e il volume,
`2026-09-16_domanda_a_opus_audio_hdmi_a733.md`,
`GPU/MISURE_20260817_WAVESHARE_720x720.txt`,
`_REPORTS/edid_waveshare_720x720.bin`.

---

## 0. Obiettivo

Far uscire **più forte e più intelligibile** l'audio dell'altoparlante
collegato all'header bianco a 4 pin del pannello Waveshare, agendo **dal
software della Cubie**. Ogni guadagno va **misurato in dB**, non giudicato a
orecchio.

**Criterio di successo**: stesso segnale di prova, stessa posizione del
microfono, livello misurato più alto di N dB rispetto alla linea di base,
senza tosatura, persistente dopo un riavvio, documentato.

**Fuori perimetro**: l'audio della fonia (altoparlante sulla TEL0161,
codec NAU88C10 del SIM7600G). **Il modulo 4G non si tocca**: niente chiamate,
SMS o comandi AT.

---

## 1. Cosa sappiamo, e quanto ne siamo sicuri

### La catena

```
applicazione
  -> sound(4) di FreeBSD (mixer, vchan, volume software)
  -> driver I2S/audio dell'A733 -> trasmettitore HDMI dell'A733
  -> cavo HDMI
  -> RTD2660H (estrae i campioni; l'audio esce in DIGITALE, I2S/SPDIF)
  -> DAC esterno (?) -> jack HP
                     -> amplificatore (?) -> header 4 pin -> altoparlante 8 ohm
```

### I fatti

| Fatto | Fonte | Affidabilita' |
|---|---|---|
| Pannello Waveshare "4inch HDMI LCD (C)", scaler Realtek RTD2660H | serigrafia + foto della wiki | alta |
| L'EDID dichiara audio LPCM a 2 canali, 32/44,1/48 kHz, 16/20/24 bit, altoparlanti FL+FR, e contiene il VSDB HDMI | EDID letto il 16/9/2026 | alta |
| Temporizzazione: 44 MHz, 976x754 totali, 59,8 Hz | EDID + registri TCON | alta |
| L'RTD2660/2662 fa uscire l'audio HDMI solo in digitale (I2S/SPDIF); non ha un DAC analogico | brief Realtek RTD2662/2660 + forum | media |
| Sulla scheda ci sono un TSSOP-20 tra il tasto Menu e il jack HP e un SOP-16 accanto all'header bianco | foto della wiki (700x494) | sigle illeggibili; il ruolo e' ignoto (uno potrebbe essere il ponte USB del tocco) |
| Alimentazione a 5 V, quindi tetto di circa 1,5 W su 8 ohm a ponte (V^2/2R) | fisica | alta, salvo un elevatore dedicato |
| "8 ohm 5 W" e pinout `+ - - +` | rapporto del 16/10 | ⚠ **non compaiono** nella wiki del 31/05/2023: fonte da ritrovare |
| Il menu a schermo ha una voce Volume | nessuna fonte | **ignoto** |
| Il pannello risponde a DDC/CI | nessuna fonte per questo modello | **ignoto** |
| Il controller HDMI dell'A733 e' il DesignWare di Synopsys | linea Allwinner (H3, A83T, H6, H616/H618) | probabile, **non verificato** |

---

## 2. Dove si puo' alzare il livello: le leve

| # | Leva | Dove agisce | Guadagno possibile | Note |
|---|---|---|---|---|
| A | Togliere le attenuazioni software | mixer, vchan, applicazione | 2,5–5 dB con i valori predefiniti; di piu' se qualcuno li ha abbassati | facile, nessun rischio |
| B | Correggere l'allineamento dei bit o la larghezza del campione | driver I2S + trasmettitore HDMI della Cubie | **6 dB per ogni bit** di spostamento | sospetto concreto in un bring-up |
| C | Registri di guadagno digitale nel driver, campo LSV dell'Audio InfoFrame | driver | dipende | vanno verificati a 0 dB |
| D | Volume dello scaler (menu o DDC/CI VCP `0x62`) | pannello | potenzialmente il piu' grande, ed e' analogico | il menu richiede l'utente; il DDC/CI dipende dal controller I2C della Cubie |
| E | Elaborazione del contenuto (passa-alto, compressore, limitatore) | catena di riproduzione | +6–10 dB **percepiti** a parita' di picco | ultima leva |
| F | Guadagno digitale oltre 0 dB dentro sound(4) | volume per canale (vpc) | fino a 100/`hw.snd.vpc_0db` | **tosa**: solo con un limitatore; meglio E |

Cosa il software **non** puo' fare: superare il tetto di potenza
dell'amplificatore (circa 1,5 W a 5 V) o cambiare un guadagno fissato da
resistenze.

---

## 3. Regole valide per tutta l'indagine

1. **Modulo 4G**: non toccarlo.
2. **I2C**: **non scrivere mai all'indirizzo `0x50`** (l'EDID). Sul bus DDC si
   mandano solo i pacchetti DDC/CI verso `0x37` descritti al §4, fase 5.
   Niente scansioni (`i2c -s`) del bus DDC se non servono: un controller
   fragile puo' bloccarsi.
3. **Tasto Power del pannello**: non chiedere all'utente di premerlo. Non e'
   chiaro se faccia cadere la linea HPD, e c'e' l'indagine aperta sui riavvii.
4. **Volume**: avvisa l'utente prima di ogni tono forte. Toni di 3 secondi al
   massimo, si sale a gradini partendo da −30 dBFS, mai toni continui a fondo
   scala.
5. **Riavvii**: annota `sysctl kern.boottime` all'inizio e alla fine di ogni
   sessione di prova. Un riavvio silenzioso durante le prove deve emergere e
   va riportato in `_REPORTS/Riavvii-Spontanei/`.
6. **Modifiche al driver**: una alla volta, con misura prima e dopo, in commit
   separati sul ramo del bring-up. Nel messaggio di commit va il dato misurato.
7. **Non dichiarare un guadagno che non hai misurato.**

---

## 4. Piano di indagine, in ordine

### Fase 0 — Inventario (sola lettura)

```sh
sysctl kern.boottime
sysctl hw.snd.verbose=2 ; cat /dev/sndstat    # unita' e catene di feeder
mixer -a
which sndctl && sndctl -v -f /dev/dspN        # formati nativi, hwbuf.format, feederchain, volume per canale
sysctl hw.snd dev.pcm
```

Da ricavare:
- quale unita' `pcm` e' l'HDMI e quale e' il microfono (o i microfoni) dell'hub;
  qual e' `hw.snd.default_unit`;
- se `bitperfect` e' attivo: in quel caso il volume software viene saltato;
- **i file sorgente** del bring-up che gestiscono l'audio HDMI: il controller
  I2S/audio dell'A733 (nei BSP Allwinner si chiamano spesso "ahub" o
  "daudio"), la parte audio del trasmettitore HDMI (N/CTS, InfoFrame, canale
  di stato) e i nodi del device tree (scheda audio, hdmi, ddc);
- **chi riproduce i suoni** nell'uso normale (suoneria, notifiche): quale
  processo, quale libreria, quale formato, e se imposta un proprio volume.

### Fase 1 — Banco di misura

**(a) Autonomo, con i microfoni dell'hub** (se si possono usare in
registrazione):

```sh
# tono mono a 1 kHz, 3 s, a -20 dBFS, poi la versione stereo con lo stesso segnale sui due canali
sox -n -r 48000 -b 16 -c 1 t20.wav synth 3 sine 1000 gain -20
sox -M t20.wav t20.wav t20_st.wav

# registra dal microfono mentre il tono suona sull'HDMI
sox -t oss -r 48000 -c 1 -b 16 /dev/dspM rec.wav trim 0 4 &
sleep 0.5; sox t20_st.wav -t oss /dev/dspN; wait

# livello del solo tono, prendendo la parte centrale della registrazione
sox rec.wav -n trim 1 2 sinc 900-1100 stats 2>&1 | grep 'RMS lev'
```

- Misura anche il **rumore di fondo** registrando senza tono: il tono deve
  stare almeno 20 dB sopra.
- **Blocca il guadagno del microfono** (mixer del dispositivo di
  registrazione), annotalo, ed escludi qualsiasi AGC. Il picco registrato
  deve restare sotto −3 dBFS.
- Ripeti tre volte: la dispersione deve stare sotto 1 dB, altrimenti il banco
  non e' affidabile.
- Se `sox` non c'e', genera i WAV con un piccolo script (Python `wave`+`math`)
  o in C.

**(b) Con l'utente, in alternativa o come controprova**: multimetro in AC tra
`+` e `−` **dello stesso canale** (mai verso massa), con un tono a **400 Hz**
(la banda dei multimetri economici). Il tetto a 5 V e' circa 3,5 V RMS.
L'amplificatore e' probabilmente in classe D, quindi la lettura e'
indicativa: conta il confronto con il tono e senza.

**Linea di base**: misura a −20, −10, −6 e −3 dBFS. Il livello misurato deve
crescere di quanto cresce l'ingresso. Se si appiattisce presto, a valle c'e'
una tosatura o un limitatore.

### Fase 2 — Canali e cablaggio (verificabili da software)

```sh
sox -n -r 48000 -b 16 -c 1 s.wav synth 3 sine 1000 gain -12
sox -n -r 48000 -b 16 -c 1 z.wav trim 0 3      # 3 s di silenzio
sox s.wav si.wav vol -1                         # stesso tono, polarita' invertita
sox -M s.wav z.wav  L.wav                       # solo canale sinistro
sox -M z.wav s.wav  R.wav                       # solo canale destro
sox -M s.wav s.wav  inphase.wav                 # uguale sui due canali
sox -M s.wav si.wav antiphase.wav               # canali in opposizione
```

| Esito | Significato |
|---|---|
| L forte e R quasi nullo (o viceversa); in fase circa uguale a in opposizione | altoparlante su un solo canale: **corretto**. Assicurati che l'audio vada anche su quel canale |
| L circa uguale a R; **in fase quasi silenzio, in opposizione forte** | l'altoparlante sta **a cavallo dei due canali** (pin 2–3 o 1–4): la voce centrata si cancella. **Va ricablato** sui pin 1–2 o 3–4. Dillo all'utente |
| tutto ugualmente debole | prosegui |

Ripiego software, solo provvisorio, se il cablaggio e' sbagliato e non si
puo' rifare: invertire un canale su tutta l'uscita (il mono diventa 2s,
+6 dB). Rovina pero' la stereofonia e l'ascolto in cuffia dal jack HP.

### Fase 3 — Attenuazioni dentro FreeBSD (leva A)

Fatti dal sorgente (albero 16-CURRENT in `marietto2008/freebsd-src`; da
verificare sul 15.0 della scheda):
- il volume software e' **lineare**: `SND_VOL_CALC_SAMPLE` in
  `sys/dev/sound/pcm/matrix.h:212`; lo 0 dB del master vale 100;
- i valori predefiniti del mixer sono 75 (`sys/dev/sound/pcm/mixer.c:76-89`).
  Quindi `pcm` a 75 vale −2,5 dB; se `vol` e' genitore di `pcm`, si arriva a
  −5 dB;
- il volume per canale (vpc) viene **riportato a 0 dB a ogni apertura**
  (`chn_vpc_reset(..., 1)`, `channel.c:1257`);
  `hw.snd.vpc_0db` vale 45 per default. Il fattore effettivo e' (volume del
  canale / vpc_0db) x (master / 100) (`SND_VOL_CALC_VAL`, `matrix.h:214`).
  Si va sopra 0 dB solo se l'applicazione imposta il proprio volume
  (`SNDCTL_DSP_SETPLAYVOL`) oltre vpc_0db, e in quel caso si tosa
  (`pcm_clamp_calc`). Lo dice anche pcm(4).

Azioni:

```sh
mixer -f /dev/mixerN vol.volume=1 pcm.volume=1   # se l'unita' HDMI ha un mixer
sndctl -f /dev/dspN -v | grep volume             # durante la riproduzione: volume per canale dell'applicazione
```

- Controlla e porta al massimo anche il volume interno dell'applicazione che
  riproduce i suoni.
- **Persistenza**: `rc.d/mixer` (`mixer_enable="YES"` e' il default) salva lo
  stato **solo allo spegnimento pulito**. Con i riavvii silenziosi quel
  salvataggio non avviene, quindi salva esplicitamente subito:
  `mixer -f /dev/mixerN -o > /var/db/mixerN-state`.
- Misura il guadagno ottenuto.

### Fase 4 — Allineamento e larghezza dei campioni nel driver HDMI (leve B e C)

**Perche' e' sospetto.** In un bring-up devono combaciare il controller I2S
(larghezza dello slot, risoluzione, giustificazione, polarita' di LRCK) e
l'ingresso audio del trasmettitore HDMI (larghezza dati e modo I2S dichiarati;
sul DesignWare, `AUD_CONF0/1`).
- Ogni bit di spostamento verso destra costa **6 dB senza distorsione**:
  l'audio esce uniformemente piu' basso, esattamente il sintomo descritto.
- Uno spostamento verso sinistra invece dà distorsione da ribaltamento ai
  livelli alti.

**Prova senza toccare il codice:**

```sh
sndctl -f /dev/dspN play.format=s16le:2.0    # poi s24le:2.0, poi s32le:2.0
sndctl -f /dev/dspN -v | grep -E 'hwbuf.format|feederchain'   # durante la riproduzione
```

1. Per ogni formato riproduci lo stesso tono a −20 dBFS e misuralo. Ti aspetti
   lo stesso livello, entro ±0,5 dB.
2. Differenze di circa 6, 12, 24 o 48 dB indicano un errore di allineamento.
   Ripeti a −3 dBFS e ascolta o analizza: se c'e' distorsione, quel formato e'
   spostato a sinistra.
3. ⚠ Se il driver dichiara un solo formato nativo (`play.formats`), sound(4)
   converte in software e la prova non dice nulla: in quel caso conta solo la
   revisione del codice.

**Revisione del codice e dei registri:**
- controller I2S: slot (32 bit?), risoluzione, modo (I2S standard, giustificato
  a sinistra o a destra), BCLK/LRCK;
- trasmettitore HDMI: larghezza e modo I2S dichiarati, coerenti con quanto
  sopra;
- **Audio InfoFrame**: LSV (level shift) **= 0 dB**, CA = `0x00` (FL/FR),
  numero di canali corretto;
- canale di stato IEC 60958: lunghezza di parola coerente con i dati;
- eventuali registri di guadagno digitale nel blocco audio dell'A733: valore
  attuale contro 0 dB;
- **N/CTS** (non influisce sul livello, ma conta se ci sono scatti o buchi).
  Con il pixel clock a 44 MHz: 48 kHz ha N=6144 e CTS=44000 (intero), 32 kHz
  ha N=4096 e CTS=44000, mentre 44,1 kHz ha N=6272 e CTS non intero.
  **Preferisci 48 kHz da un capo all'altro** (`sndctl play.rate=48000`).

**Confronto con Linux**, se si puo' avviare: lo stesso pannello e' gia' stato
pilotato da Linux. Riproduci lo stesso tono al 100% e misuralo con lo stesso
banco. Se Linux suona piu' forte a parita' di livello digitale, la differenza
sta nella configurazione del driver FreeBSD: leggi gli stessi registri sotto
Linux e confrontali.

### Fase 5 — Volume nello scaler (leva D)

**5a. Menu a schermo (lo fa l'utente; tu prepari le istruzioni e raccogli
l'esito)**: premere **Menu** (il secondo tasto partendo dai connettori),
scorrere con Up/Down, cercare Volume, Audio, Sound o Mute, annotare il valore,
portarlo al massimo, chiudere con Exit. **Non premere Power.** Evitare le voci
Reset e Auto adjust. Se il volume c'e' e non era al massimo, e' la leva
analogica piu' grande: rimisura.

**5b. DDC/CI dalla Cubie.** Prima stabilisci **chi pilota le linee DDC**:
- in FreeBSD: `ls /dev/iic*`, `sysctl dev.iicbus | grep %parent`, `devinfo -rv`;
- nel device tree: la proprieta' `ddc` o `ddc-i2c-bus` del nodo hdmi. Il
  `dwc_hdmi` di FreeBSD legge l'EDID tramite un bus I2C esterno indicato da
  `ddc` (`sys/dev/hdmi/dwc_hdmi_fdt.c:122`);
- nel driver del bring-up: se l'EDID si legge tramite i registri del master
  I2C **interno** del DesignWare (`0x7E00`–`0x7E0x`: `I2CM_SLAVE`,
  `I2CM_ADDRESS`, `I2CM_DATAO`, `I2CM_DATAI`, `I2CM_OPERATION`), **il DDC/CI
  non puo' funzionare**. Quel master fa solo letture e scritture di un byte, o
  letture di 8 byte; Linux rifiuta `0x37` su quel controller dal 2019 (patch
  "drm/bridge: dw-hdmi: Refuse DDC/CI transfers on the internal I2C
  controller"). In quel caso fermati e riportalo. **Leggere l'EDID dimostra
  che il filo funziona, non che il controller sappia fare DDC/CI.**
- se invece il DDC arriva a un TWI generico o a un `gpioiic`, prova. La
  sintassi e' verificata su `usr.sbin/i2c/i2c.c`: modo interpretato,
  larghezza `0` = nessun offset e un solo messaggio, indirizzo a 7 bit.

```sh
# Get VCP 0x62 (Audio: Speaker Volume)
i2c -i 'w N 0x37 0 0 51 82 01 62 de'
sleep 0.05
i2c -i 'r N 0x37 0 0 11'

# Get VCP 0x8D (Audio mute: 1 = muto, 2 = attivo)
i2c -i 'w N 0x37 0 0 51 82 01 8d 31'
sleep 0.05
i2c -i 'r N 0x37 0 0 11'
```

| Risposta | Significato |
|---|---|
| `6e 88 02 00 62 TP MH ML SH SL CK` | supportato: volume attuale = `SH SL`, massimo = `MH ML` |
| quarto byte `01` | codice VCP non supportato |
| `6e 80 be ...` | messaggio nullo |
| `ff...`, errore, checksum sbagliato | niente DDC/CI, oppure il controller non e' in grado |

- **Checksum della risposta**: lo XOR di `0x50` con tutti i byte, `CK` escluso.
  Una risposta con checksum sbagliato non vale nulla.
- **Set VCP** (solo dopo un Get valido):
  `i2c -i 'w N 0x37 0 0 51 84 03 62 00 VV CK'` con `CK = 0xDA ^ VV`
  (per esempio `VV=32` dà `CK=e8`). Poi rifai il Get e misura.
- Se servono tempi precisi o la lettura delle capability a frammenti, scrivi
  un piccolo programma in C con l'ioctl `I2CRDWR` invece di concatenare
  comandi di shell.
- L'unica alternativa e' hardware: un master I2C esterno sui pin HDMI 15, 16 e
  17, con linee a 5 V e quindi un traslatore di livello. **Non va fatta senza
  l'approvazione dell'utente.**

### Fase 6 — Identificare DAC e amplificatore (lo chiedi all'utente)

Chiedi una **foto macro** delle sigle di questi chip:
- il TSSOP-20 tra il tasto Menu e il jack HP;
- il SOP-16 accanto all'header bianco;
- ogni altro chip vicino al jack.

Come leggere il risultato:
- **amplificatore con pin di volume in continua** (VOL/DC volume): con ogni
  probabilita' e' lo scaler a comandarlo, con un PWM, quindi il volume c'e' e
  si regola dal menu o via DDC/CI;
- **amplificatore a guadagno fisso piu' DAC in modo hardware**: non esiste una
  manopola analogica e il livello dipende solo da quello digitale. Restano le
  leve A, B ed E.

Le piazzole `PWM`/`GND` accanto ai tasti sono quasi certamente per la
retroilluminazione, non per l'audio.

### Fase 7 — Elaborazione del contenuto (leva E)

Se il segnale digitale e' gia' a fondo scala e non basta, si puo' aumentare la
sonorita' **percepita** a parita' di picco:
- **passa-alto a 200–300 Hz**: l'altoparlante piccolo non riproduce i bassi,
  che pero' consumano margine all'amplificatore;
- **compressore** con guadagno di recupero e **limitatore** a −1 dBFS;
- facoltativamente un leggero rinforzo tra 2 e 4 kHz (presenza della voce).

Punto di partenza, da tarare misurando (il compressore viene dall'esempio del
manuale di sox):

```sh
sox in.wav out.wav highpass 250 compand 0.3,1 6:-70,-60,-20 -5 -90 0.2 gain -l 6
sox out.wav -n stats 2>&1 | grep -E 'Pk lev|RMS lev'   # picco <= -1 dBFS
```

Dove applicarlo:
- sui **file fissi** (suonerie, notifiche): elaborali una volta sola, offline.
  E' la soluzione piu' pulita;
- sull'audio generato al momento: nella catena dell'applicazione, oppure a
  livello di sistema con virtual_oss(8). Verifica nelle sue opzioni se offre
  guadagno o compressione.

Leva F (guadagno vpc oltre 0 dB) solo se E non si puo' applicare, e sempre con
un limitatore.

---

## 5. Cosa consegnare

Un file `_REPORTS/AAAA-MM-GG_volume_software_esito.md` con:
1. **Inventario**: unita' pcm, driver, file sorgente, nodi del device tree,
   chi riproduce i suoni.
2. **Banco di misura**: metodo, rumore di fondo, ripetibilita'.
3. **Tabella delle misure**: condizione | livello misurato (dB) | differenza
   rispetto alla base | note.
4. Esito della **fase 2** (canali e cablaggio).
5. Esito della **fase 4**: livelli per formato, con `hwbuf.format`, e i
   registri letti.
6. **Percorso del DDC** e risultato di VCP `0x62`/`0x8D`, con i byte grezzi.
7. **Menu a schermo**: esito riferito dall'utente.
8. **Sigle dei chip** (fase 6).
9. **Configurazione finale** applicata e come e' resa persistente.
10. Cosa resta aperto.
11. `kern.boottime` all'inizio e alla fine.

---

## 6. Osservazioni collaterali (non di volume, ma da sapere mentre lavori)

- **Pogo pin**: il pannello ha 5 pogo pin "communication/power supply" che
  toccano il connettore a 40 pin di un Raspberry montato sulle colonnine (5 V,
  GND, I2C del tocco). Se la Cubie e' montata cosi', i 5 V di pannello e Cubie
  sono in parallelo, e con la USB-C del pannello alimentata da un'altra fonte
  si hanno **due alimentatori in parallelo**. Verificalo prima di attribuire
  al software un riavvio durante le prove.
- **Piazzole `PWM`/`GND`** accanto ai tasti: probabilmente sono l'ingresso
  PWM della retroilluminazione. Controlla che non ci sia saldato niente.
- La configurazione Waveshare per Raspberry usa `hdmi_force_hotplug=1`
  (ignora l'HPD) e `config_hdmi_boost=10` (pilotaggio TMDS forte). Se lo
  schermo si oscura da solo, l'ampiezza di uscita HDMI dell'A733 nel bring-up
  e' un indiziato da guardare.

---

## 7. Riferimenti

**Sorgente FreeBSD** (`marietto2008/freebsd-src`, albero 16-CURRENT):
- `sys/dev/sound/pcm/matrix.h:203-219` — 0 dB del master = 100, vpc = 45,
  formule del volume
- `sys/dev/sound/pcm/mixer.c:76-89` — valori predefiniti 75
- `sys/dev/sound/pcm/channel.c:122-176`, `:1257`, `:1674-1687` — vpc,
  `hw.snd.vpc_0db`, azzeramento all'apertura
- `sys/dev/sound/pcm/feeder_volume.c`, `pcm.h` (`pcm_clamp_calc`) — volume
  software e tosatura
- `usr.sbin/i2c/i2c.c` — modo interpretato, larghezza 0
- `usr.sbin/sndctl/sndctl.8`, `usr.sbin/mixer/mixer.8`, `libexec/rc/rc.d/mixer`
- `sys/dev/hdmi/dwc_hdmi.c`, `dwc_hdmi_fdt.c` — EDID tramite il bus I2C esterno `ddc`

**Web:**
- Patch dw-hdmi "Refuse DDC/CI transfers on the internal I2C controller" (2019):
  https://lkml.iu.edu/hypermail/linux/kernel/1910.0/02372.html
- Caso Orange Pi Zero3 (H618), DDC/CI fallito sul bus DesignWare HDMI:
  https://juejin.cn/post/7344571292353904703
- Brief Realtek RTD2662/2660:
  https://www.orientdisplay.com/wp-content/uploads/2021/02/rtd2662_spec_brief_0702_171.pdf
- PCB800099 (RTD2662/2660): https://www.mattmillman.com/info/lcd/pcb800099/
- Wiki Waveshare 4inch HDMI LCD (C) (stampa PDF del 31/05/2023, pagine 1–5 di 8):
  https://www.waveshare.com/wiki/4inch_HDMI_LCD_(C)
- Manuale Waveshare 10.1inch HDMI LCD (New RTD2660 Version), funzione dei tasti:
  https://www.waveshare.com/wiki/10.1inch_HDMI_LCD_(New_RTD2660_Version)_User_Manual
- ddcutil(1): https://man.archlinux.org/man/ddcutil.1

---

*Brief scritto da Claude per Marietto, 16/10/2026. Nessuna delle prove qui
descritte e' stata eseguita: la scheda era spenta e questa sessione non ha
accesso alla Cubie.*
