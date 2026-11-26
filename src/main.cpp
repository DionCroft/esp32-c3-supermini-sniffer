/*
 * ESP32-C3 SuperMini - passive 2.4 GHz 802.11 sniffer / channel analyser
 *
 * One radio does two jobs:
 *   1) open a softAP ("ESP32-SNIFFER") serving the web dashboard. The home
 *      channel (default 6) is NVS-persisted; the AP starts on it at boot and
 *      is the channel it returns to.
 *   2) promiscuous capture on the current channel, parsed into bounded
 *      in-memory state (512-frame ring, up to 64 BSSIDs, 32-slot SSID pool,
 *      nominal 1 s rate buckets (128 stored samples)) exposed via a small
 *      JSON HTTP API.
 *
 * S3 milestone: channel sweep 1-13. A loop()-tick state machine hops the AP
 * (esp_wifi_set_channel) sequentially through channels 1..13, ~500 ms settle
 * then a dwell (2-10 s, default 4) of capture per channel. The promiscuous RX
 * callback buckets frames into the current sweep channel via the volatile
 * g_sw_active variable (0 = off, 1..13 = sweep channel, 128+ch = pre-sweep
 * baseline observation). Per-channel metrics: frames, frame rate, distinct
 * BSSIDs (cap 32), distinct SSIDs, security mix (open/wpa2/wpa3/other from
 * beacon IEs), strongest-BSSID RSSI (max + mean), RTS/CTS/ACK count, and
 * activity_pct = fraction of the dwell during which at least one frame was
 * seen within the last 250 ms - an occupancy estimate, NOT a noise floor.
 * New/moved BSSIDs are detected vs the previous sweep (RAM); the first sweep
 * builds its baseline from a ~5 s pre-sweep observation on the home channel.
 * S4 milestone: event/anomaly engine. NEW_SSID (a (bssid,ssid) pair seen for
 * the first time since boot; pairs seen during the first EVENT_NEWSSID_GRACE_MS
 * are silently baselined), DEAUTH_BURST (EVENT_DEAUTH_BURST_N deauth mgmt
 * frames, subtype 0x0C, from one BSSID within EVENT_DEAUTH_WINDOW_MS) and
 * RATE_SPIKE (current 1 s bucket > EVENT_SPIKE_RATIO_NUM x the trailing
 * EVENT_SPIKE_BASE_S baseline rate) are derived inside the existing
 * promiscuous frame path - no new capture machinery, no extra WiFi overhead.
 * A 32-entry in-RAM ring (< 4 KB) persists to LittleFS "/events.json" (JSON
 * array, newest last; capped at EVENT_FILE_MAX_BYTES, oldest truncated;
 * write-through debounced at EVENT_FLUSH_DEBOUNCE_MS).
 * S5 milestone: session capture + CSV/JSON export. One open session at a
 * time ("session start" / "session stop" / "session list" on the serial
 * console AND /api/session/start|stop|list); state at /api/session; closed
 * sessions persist to LittleFS as /sN.json + /sN.csv (monotonic id counter
 * in /sess.idx, newest 3 closed kept), built from snapshots of the EXISTING
 * bounded structures (g_bss rows, g_ssid pool, event ring, sweep channel
 * counters) - no new unbounded stores. While a session is open its snapshot
 * is rewritten every 60 s (loop() millis() debounce, same pattern as the S4
 * 5 s events flush) via tmp+rename, which littleFS executes atomically.
 * Export: /api/session/export?fmt=csv|json&id=N streams the files with
 * Content-Disposition attachment (bounded heap). No new RTOS tasks; no
 * littleFS writes on the frame-callback path.
 * Serial console (USB-Serial-JTAG, CRLF, case-insensitive):
 *   sweep [dwell_s] | sweep stop | home | ch N | diag | events | events clear
 *   | session [start|stop|list]
 * API (additive): /api/sweep, /api/sweep/start?dwell=N, /api/sweep/stop,
 * /api/events, /api/session, /api/session/start, /api/session/stop,
 * /api/session/list, /api/session/export.
 *
 * Capture uses the esp_wifi promiscuous API available in the IDF floor used
 * by arduino-esp32 2.0.17 (IDF 4.4 base):
 *     wifi_promiscuous_filter_t f = { WIFI_PROMIS_FILTER_MASK_ALL };
 *     esp_wifi_set_promiscuous_filter(&f);
 *     esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);   // void(void*, wifi_promiscuous_pkt_type_t)
 *     esp_wifi_set_promiscuous(true);
 * The callback buffer is wifi_promiscuous_pkt_t* (wifi_pkt_rx_ctrl_t rx_ctrl then
 * payload). We read rx_ctrl.rssi (dBm), rx_ctrl.sig_len (frame length incl. the
 * 4-byte FCS - subtract 4), rx_ctrl.channel, rx_ctrl.rate, rx_ctrl.sig_mode.
 *
 * No libraries beyond the built-in WiFi / WebServer / LittleFS / NVS.
 * Single-core FreeRTOS: the capture callback only does bounded state updates
 * under a short portMUX critical section (no allocation, no I/O), so it does
 * not starve the web link.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include "esp_wifi.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ----------------------------- configuration -----------------------------
#define FW_VERSION    "0.5.0-session"
#define CHIP_NAME     "ESP32-C3"
#define AP_SSID       "ESP32-SNIFFER"
#define AP_CHANNEL    6      // default home channel (NVS may hold 1..13)
#define BTN_PIN       9
#define MONITOR_BAUD  115200

#define RING_SIZE     512
#define BSS_MAX       64
#define RSSI_HIST     128
#define SSID_MAX      32
#define SSID_MAXLEN   32
#define RATE_SLOTS    128

// sweep 1-13
#define SETTLE_MS     500    // radio settle after each channel hop
#define PRIME_MS      5000   // first-sweep baseline observation on home channel
#define SWEEP_BSS_CAP 32     // distinct BSSIDs tracked per sweep channel
#define SWEEP_LIST_CAP 16    // max new/moved entries reported

// event/anomaly engine (S4) - owner-tunable thresholds
#define EVENT_RING_SIZE       32      // in-RAM ring (40 B/event -> 1.25 KB)
#define EVENT_FILE_MAX_BYTES  16384   // \events.json cap; oldest truncated on overflow
#define EVENT_FLUSH_DEBOUNCE_MS 5000  // write-through flush at most once per period
#define EVENT_NEWSSID_GRACE_MS 60000  // pairs first seen inside this window are silently baselined
#define EVENT_DEAUTH_BURST_N  3       // deauths from one BSSID ...
#define EVENT_DEAUTH_WINDOW_MS 10000  // ... within this window -> DEAUTH_BURST
#define EVENT_SPIKE_RATIO_NUM 2       // current 1 s bucket > 2 x baseline -> RATE_SPIKE
#define EVENT_SPIKE_BASE_S    60      // trailing baseline window (1 s buckets)
#define EVENT_SPIKE_MIN_S     15      // no spike event before this much baseline data
#define EVENT_SPIKE_REARM_MS  15000   // re-arm delay after a spike event (no flooding)
#define EVENT_PAIR_CAP        32      // (bssid,ssid) dedup table
#define EVENT_DEAUTH_CAP      16      // per-BSSID deauth burst trackers
#define EVENT_FILE          "/events.json"

// session capture + export (S5)
#define SESSION_FILE_MAX_BYTES    65536  // per-file cap for /sN.json and /sN.csv
#define SESSION_FLUSH_DEBOUNCE_MS 60000  // open-session rewrite period (loop millis() gate)
#define SESSION_KEEP              3      // newest closed sessions retained
#define SESSION_CSV_BSS_CAP       64     // flat CSV rows, one per BSS (== BSS_MAX)
#define SESSION_IDX_FILE          "/sess.idx"

// ----------------------------- bounded state -----------------------------
enum { SEC_OPEN=0, SEC_WEP, SEC_WPA, SEC_WPA2, SEC_WPA3, SEC_WPA2_3, SEC_ENT, SEC_UNKNOWN };
static const char* const sec_name[] = {"OPEN","WEP","WPA","WPA2","WPA3","WPA2-3","ENT","?"};

struct RingEntry {
  uint32_t ts;      // uptime ms
  uint8_t  ch;
  int8_t   rssi;    // dBm
  uint8_t  type;    // 0 mgmt / 1 ctrl / 2 data / 3 other
  uint8_t  subtype;
  uint16_t rate;    // raw PHY rate code (11b/g)
  uint8_t  phy;     // sig_mode: 0 11b/g, 1 11n, 3 11ac
  uint8_t  src[6];
  uint8_t  bssid[6];
  uint8_t  ssid_idx; // 255 = none
};

struct SSIDEntry {
  uint8_t len;
  uint8_t data[SSID_MAXLEN];
  uint8_t used;
};

struct BSS {
  uint8_t  mac[6];
  uint8_t  used;
  uint8_t  ssid_idx;
  uint8_t  sec;
  int8_t   rssi;    // live (latest beacon/probe-resp), -127 = unknown
  int8_t   rmin;    // 127 = unknown
  int8_t   rmax;    // -127 = unknown
  int64_t  rsum;    // sum over mgmt RSSI samples
  uint32_t rsum_n;  // mgmt RSSI sample count
  uint32_t frames;  // total frames seen for this bssid
  uint32_t first_ms;
  uint32_t last_ms;
  uint16_t beacon_int; // raw field (units of 1.024 ms)
  uint8_t  ch;         // channel of the last frame seen for this BSS (S5; 0 = unknown)
  int8_t   hist[RSSI_HIST];
  uint8_t  hist_head;
  uint8_t  hist_count;
};

// Per-BSSID record inside a sweep channel (or the pre-sweep baseline).
struct SweepBss {
  uint8_t mac[6];
  int8_t  rmax;      // strongest RSSI seen (mgmt beacon/probe-resp), -127 none
  uint8_t sec;       // last parsed security (SEC_*)
  uint8_t ssid_idx;  // 255 = none
  uint8_t used;
};

// Per sweep-channel raw counters (finalized values are computed on demand).
struct SweepCh {
  uint32_t frames;      // all frame types bucketed on this channel during dwell
  uint32_t ctrl;        // RTS/CTS/ACK frames
  uint32_t active_ms;   // ms of the dwell with a frame within the last 250 ms
  uint32_t ssid_mask;   // bits over the global 32-slot SSID pool
  SweepBss bss[SWEEP_BSS_CAP];
  uint8_t  bss_n;
};

// Derived, per-channel metric snapshot used for logging + JSON.
struct ChMetrics {
  uint32_t frames;
  uint32_t ctrl;
  uint16_t rate;        // frames/s over the (elapsed) dwell
  uint8_t  act;         // activity % 0..100 (occupancy estimate)
  uint8_t  bssids;
  uint8_t  ssids;
  uint8_t  sec_open, sec_wpa2, sec_wpa3, sec_other;
  int8_t   rmax, ravg;  // strongest-BSSID RSSI max / mean, -127 = none
};

static RingEntry  g_ring[RING_SIZE];
static volatile uint32_t g_ring_head = 0;   // next write index
static volatile uint32_t g_ring_total = 0;  // total frames ever written

static BSS        g_bss[BSS_MAX];
static SSIDEntry  g_ssid[SSID_MAX];
static volatile uint8_t g_ssid_used = 0;

static volatile uint32_t g_total   = 0;
static volatile uint32_t g_dropped = 0;     // ring overwrites (events after RING_SIZE writes)
static uint32_t  g_type_cnt[4];
static uint32_t  g_sub_cnt[4][16];

static uint16_t  g_rate[RATE_SLOTS];
static volatile uint32_t  g_rate_idx = 0;
static volatile uint32_t  g_rate_in_progress = 0;
static uint32_t  g_rate_bucket_start = 0;
static uint32_t  g_rate_window_ms = 0;

static portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;

static uint8_t  g_ap_mac[6] = {0};
static char     g_ap_mac_str[18] = "00:00:00:00:00:00";
static String   g_ap_ip = "192.168.4.1";
static uint8_t  g_channel = AP_CHANNEL;
static uint8_t  g_home_ch = AP_CHANNEL;   // NVS-persisted home channel (1..13)
static bool     g_promisc = false;

WebServer server(80);

// ----------------------------- sweep state -------------------------------
enum { SW_IDLE=0, SW_PRIME, SW_SETTLE, SW_DWELL, SW_HOME, SW_DONE };
enum { HA_NONE=0, HA_BEGIN_SWEEP, HA_DONE, HA_ABORT };
static volatile uint8_t g_sw_state = SW_IDLE;
static volatile uint8_t g_sw_ch = 0;        // channel being settled / captured
static volatile uint8_t g_sw_active = 0;    // 0 off, 1..13 sweep ch, 128+ch baseline
static volatile uint8_t g_sw_home_action = HA_NONE; // where SW_HOME settles to
static volatile uint32_t g_sw_last_frame_ms = 0;    // last frame bucketed this dwell
static uint32_t g_sw_start_ms = 0;          // uptime ms at sweep start
static uint32_t g_sw_phase_ms = 0;          // uptime ms at current phase start
static uint32_t g_sw_done_ms = 0;           // duration of last completed sweep
static uint32_t g_sw_tick_ms = 0;           // last activity-accumulation tick
static uint8_t  g_sw_dwell_s = 4;
static uint8_t  g_quietest = 0;             // 0 until a sweep completes
static bool     g_have_baseline = false;    // previous-sweep baseline available

static SweepCh   g_sweep_ch[13];            // raw per-channel counters (13 ch)
static SweepBss  g_base[13][SWEEP_BSS_CAP]; // baseline BSSIDs per channel
static uint8_t   g_base_n[13];

static uint8_t g_new_mac[SWEEP_LIST_CAP][6];
static uint8_t g_new_ssid[SWEEP_LIST_CAP];
static uint8_t g_new_ch[SWEEP_LIST_CAP];
static uint8_t g_new_n = 0;
static uint8_t g_moved_mac[SWEEP_LIST_CAP][6];
static uint8_t g_moved_from[SWEEP_LIST_CAP];
static uint8_t g_moved_to[SWEEP_LIST_CAP];
static uint8_t g_moved_n = 0;

// ----------------------------- event engine (S4) -------------------------
// Bounded event/anomaly engine; thresholds in the #define block above.
// Detection hooks the existing promiscuous frame path: ev_detect() is called
// from the RX callback under g_mux (no new capture machinery, no extra WiFi
// overhead). The in-RAM ring (32 x 40 B < 4 KB) persists to LittleFS
// "/events.json" (JSON array, newest last) with a 5 s write-through debounce;
// the file is capped at EVENT_FILE_MAX_BYTES (oldest truncated on overflow).
static void hexmac(const uint8_t* m, char out[18]);      // fwd (helpers below)
static void appendSsid(String& s, const uint8_t* d, uint8_t len); // fwd (helpers below)
enum { EV_NEW_SSID=1, EV_DEAUTH_BURST=2, EV_RATE_SPIKE=3 };
static const char* ev_type_name(uint8_t t){
  switch (t){
    case EV_NEW_SSID:     return "new_ssid";
    case EV_DEAUTH_BURST: return "deauth_burst";
    case EV_RATE_SPIKE:   return "rate_spike";
    default:              return "unknown";
  }
}
struct EvEntry {
  uint32_t ts_s;      // seconds since boot
  uint8_t  type;      // EV_*
  uint8_t  ch;        // 1-13, 0 if unknown
  char     detail[32]; // up to 31 chars + NUL
};
struct EvPair {       // (bssid,ssid) dedup; ssid_idx 255 = hidden (no SSID IE)
  uint8_t mac[6];
  uint8_t ssid_idx;
  uint8_t used;
};
struct EvDeauth {     // per-BSSID deauth burst tracker
  uint8_t  mac[6];
  uint32_t last_ms;
  uint8_t  cnt;
  uint8_t  used;
};

static EvEntry   g_ev_ring[EVENT_RING_SIZE];
static volatile uint32_t g_ev_head = 0;    // next write index
static volatile uint8_t  g_ev_fill = 0;    // 0..EVENT_RING_SIZE
static volatile uint8_t  g_ev_pending = 0; // write-through pending
static uint32_t  g_ev_last_flush_ms = 0;
static EvPair    g_ev_pair[EVENT_PAIR_CAP];
static uint8_t   g_ev_baseline_cnt = 0;    // distinct pairs baselined during the grace window
static EvDeauth  g_ev_deauth[EVENT_DEAUTH_CAP];
static uint32_t  g_ev_last_spike_ms = 0;
static uint8_t   g_ev_loaded_boot = 0;     // events loaded from LittleFS at boot

// --------------------------- session logging (S5) -------------------------
// One active session at a time; all updates from loop()/HTTP/console context
// (single-threaded loop task) - the frame callback only touches g_total.
static bool     g_sess_active = false;
static uint32_t g_sess_start_ms = 0;       // uptime ms at start
static uint32_t g_sess_total0 = 0;         // g_total at start
static uint8_t  g_sess_open_id = 0;        // id reserved for the open session
static uint8_t  g_sess_last_closed = 0;    // last closed id (from /sess.idx)
static uint32_t g_sess_last_flush_ms = 0;  // 60 s open-snapshot flush gate

// Called with g_mux held. Overwrites the oldest event when full (ring semantics).
static void ev_push(uint8_t type, uint8_t ch, const char* det, uint32_t now_ms){
  EvEntry e;
  e.ts_s = now_ms / 1000;
  e.type = type;
  e.ch = (ch >= 1 && ch <= 13) ? ch : 0;
  if (det) strncpy(e.detail, det, sizeof(e.detail) - 1);
  e.detail[sizeof(e.detail) - 1] = '\0';
  g_ev_ring[g_ev_head] = e;
  g_ev_head = (g_ev_head + 1) % EVENT_RING_SIZE;
  if (g_ev_fill < EVENT_RING_SIZE) g_ev_fill++;
  g_ev_pending = 1;
}
// Called with g_mux held. NEW_SSID: a (bssid,ssid) pair seen for the first
// time since boot; pairs first seen during the grace window are silently
// baselined (counted, reported on the diag line).
static void ev_pair_check(const uint8_t* mac, uint8_t key, uint8_t ch, uint8_t sslen, uint8_t ssid_idx, uint32_t now_ms){
  for (int i = 0; i < EVENT_PAIR_CAP; i++){
    if (g_ev_pair[i].used && !memcmp(g_ev_pair[i].mac, mac, 6) && g_ev_pair[i].ssid_idx == key)
      return;                                 // pair already known
  }
  int fi = -1;
  for (int i = 0; i < EVENT_PAIR_CAP; i++) if (!g_ev_pair[i].used){ fi = i; break; }
  if (fi < 0) return;                         // dedup table full: silently skip
  g_ev_pair[fi].used = 1;
  g_ev_pair[fi].ssid_idx = key;
  memcpy(g_ev_pair[fi].mac, mac, 6);
  if (now_ms < EVENT_NEWSSID_GRACE_MS){
    g_ev_baseline_cnt++;                      // silently baseline during the grace window
    return;
  }
  char det[32];
  if (sslen > 0){
    uint8_t l = (ssid_idx < SSID_MAX && g_ssid[ssid_idx].used) ? g_ssid[ssid_idx].len : 0;
    if (l > 31) l = 31;
    memcpy(det, g_ssid[ssid_idx].data, l);
    det[l] = '\0';
  } else {
    strcpy(det, "hidden");
  }
  ev_push(EV_NEW_SSID, ch, det, now_ms);
}
// Called with g_mux held. DEAUTH_BURST: EVENT_DEAUTH_BURST_N deauth mgmt
// frames (subtype 0x0C) from one BSSID within EVENT_DEAUTH_WINDOW_MS; one
// event per burst (counter resets + re-arms after the window).
static void ev_deauth_hit(const uint8_t* mac, uint8_t ch, uint32_t now_ms){
  EvDeauth* t = nullptr;
  int fi = -1;
  for (int i = 0; i < EVENT_DEAUTH_CAP; i++){
    if (g_ev_deauth[i].used){
      if (!memcmp(g_ev_deauth[i].mac, mac, 6)) t = &g_ev_deauth[i];
      break;
    } else if (fi < 0) fi = i;
  }
  if (!t){
    if (fi < 0) return;                       // trackers full: silently skip
    t = &g_ev_deauth[fi];
    memset(t, 0, sizeof(*t));
    memcpy(t->mac, mac, 6);
    t->used = 1;
  }
  if (now_ms - t->last_ms > EVENT_DEAUTH_WINDOW_MS) t->cnt = 0; // window elapsed: re-arm
  t->last_ms = now_ms;
  t->cnt++;
  if (t->cnt >= EVENT_DEAUTH_BURST_N){
    char det[18];
    hexmac(mac, det);
    ev_push(EV_DEAUTH_BURST, ch, det, now_ms);
    t->cnt = 0;
  }
}
// Called with g_mux held from the promiscuous RX callback.
static void ev_detect(uint8_t* f, uint16_t len, uint8_t type, uint8_t subtype,
                      const uint8_t* bssid, bool bssid_set, uint8_t ch,
                      uint8_t ssid_idx, uint8_t sslen, uint32_t now_ms){
  // NEW_SSID: beacon (8) / probe-resp (5) carrying a BSSID; hidden SSID -> key 255.
  if (type == 0 && (subtype == 5 || subtype == 8) && bssid_set){
    uint8_t key;
    if (sslen > 0){
      if (ssid_idx == 255) return;            // SSID pool full: nothing to key on
      key = ssid_idx;
    } else {
      key = 255;
    }
    ev_pair_check(bssid, key, ch, sslen, ssid_idx, now_ms);
  }
  // DEAUTH_BURST: deauth mgmt frames. BSSID = addr3 (f+16); fall back to the
  // transmitter addr2 (f+10) when addr3 is all zeros.
  if (type == 0 && subtype == 0x0C && len >= 24){
    uint8_t db[6];
    memcpy(db, f + 16, 6);
    bool nz = false;
    for (int i = 0; i < 6; i++) if (db[i]) nz = true;
    if (!nz){
      memcpy(db, f + 10, 6);
      nz = false;
      for (int i = 0; i < 6; i++) if (db[i]) nz = true;
    }
    if (nz && (db[0] & 0x01) == 0) ev_deauth_hit(db, ch, now_ms);
  }
}
// Called from loop() after each committed 1 s bucket (g_mux NOT held).
// RATE_SPIKE: current bucket > EVENT_SPIKE_RATIO_NUM x the trailing
// EVENT_SPIKE_BASE_S baseline rate; no event until the baseline has
// EVENT_SPIKE_MIN_S of data; zero baseline guarded; re-arms after an event.
static void ev_rate_check(uint16_t cur, const uint16_t* base, uint32_t bn){
  if (bn < EVENT_SPIKE_MIN_S) return;
  uint32_t sum = 0;
  for (uint32_t i = 0; i < bn; i++) sum += base[i];
  uint32_t mean = sum / bn;
  if (mean == 0) return;                       // zero-baseline guard
  if (cur <= mean * EVENT_SPIKE_RATIO_NUM) return;  // strictly greater required
  uint32_t now = millis();
  if (now - g_ev_last_spike_ms < EVENT_SPIKE_REARM_MS) return;
  g_ev_last_spike_ms = now;
  char det[24];
  snprintf(det, sizeof(det), "%u pps vs %u pps", (unsigned)cur, (unsigned)mean);
  portENTER_CRITICAL(&g_mux);
  ev_push(EV_RATE_SPIKE, g_channel, det, now);
  portEXIT_CRITICAL(&g_mux);
}
// Serialize the first n entries (oldest first) as a JSON array; detail is
// escaped with the same rules as SSIDs (appendSsid).
static void events_json_to(String& s, const EvEntry* a, int n){
  s += '[';
  for (int i = 0; i < n; i++){
    const EvEntry* e = &a[i];
    if (i) s += ',';
    s += "{\"ts\":"; s += (unsigned)e->ts_s;
    s += ",\"type\":\""; s += ev_type_name(e->type); s += "\"";
    s += ",\"ch\":"; s += (int)(e->ch ? e->ch : 0);
    s += ",\"detail\":\"";
    appendSsid(s, (const uint8_t*)e->detail, (uint8_t)strlen(e->detail));
    s += "\"}";
  }
  s += ']';
}
// Write-through: persist the ring to EVENT_FILE, capping the file at
// EVENT_FILE_MAX_BYTES by truncating the oldest events.
static void events_flush(){
  static EvEntry snap[EVENT_RING_SIZE];
  uint8_t fill = 0;
  uint32_t head = 0;
  portENTER_CRITICAL(&g_mux);
  fill = g_ev_fill;
  head = g_ev_head;
  for (int i = 0; i < (int)fill; i++){
    uint32_t idx = (head + EVENT_RING_SIZE - fill + i) % EVENT_RING_SIZE; // oldest first
    snap[i] = g_ev_ring[idx];
  }
  portEXIT_CRITICAL(&g_mux);
  String s;
  s.reserve(3300);
  int n = fill;
  while (n > 0){
    s = String();
    events_json_to(s, snap, n);
    if ((int)s.length() <= EVENT_FILE_MAX_BYTES) break;
    n--;                                       // file cap: truncate oldest
  }
  if (n == 0) s = "[]";
  File f = LittleFS.open(EVENT_FILE, "w");
  if (f){
    f.print(s);
    f.close();
  }
}
// Strict JSON array parser for the events file: whitespace-tolerant, detail
// escapes unescaped; any structural/semantic defect -> 0 (start empty, no
// crash). Events stream into win (a ring of wcap >= EVENT_RING_SIZE+1 slots).
static int events_parse(const char* p, int len, EvEntry* win, uint32_t wcap){
  int i = 0;
  auto skipws = [&](){ while (i < len && (p[i]==' '||p[i]=='\t'||p[i]=='\n'||p[i]=='\r')) i++; };
  skipws();
  if (i >= len || p[i] != '[') return 0;
  i++;
  skipws();
  if (i < len && p[i] == ']') return 0;        // empty array
  uint32_t total = 0;
  while (true){
    skipws();
    if (i >= len || p[i] != '{') return 0;
    i++;
    EvEntry e;
    memset(&e, 0, sizeof(e));
    char det[32];
    int dlen = 0;
    bool have_ts = false, have_type = false, have_det = false;
    bool bad = false;
    while (true){
      skipws();
      if (i >= len || p[i] != '"'){ bad = true; break; }
      i++;
      char key[8];
      int kl = 0;
      while (i < len && p[i] != '"'){
        char c = p[i++];
        if (c == '\\' && i < len) c = p[i++];
        if (kl < 7) key[kl++] = c;
      }
      if (i >= len){ bad = true; break; }
      i++;
      key[kl] = 0;
      skipws();
      if (i >= len || p[i] != ':'){ bad = true; break; }
      i++;
      if (strcmp(key, "ts") == 0){
        skipws();
        if (i >= len || p[i] < '0' || p[i] > '9'){ bad = true; break; }
        unsigned long v = 0;
        while (i < len && p[i] >= '0' && p[i] <= '9'){
          v = v * 10 + (uint32_t)(p[i++] - '0');
          if (v > 0xFFFFFFFFUL){ bad = true; break; }
        }
        if (bad) break;
        e.ts_s = (uint32_t)v;
        have_ts = true;
      } else if (strcmp(key, "type") == 0){
        if (i >= len || p[i] != '"'){ bad = true; break; }
        i++;
        char tv[16];
        int tl = 0;
        while (i < len && p[i] != '"'){
          char c = p[i++];
          if (c == '\\' && i < len) c = p[i++];
          if (tl < 15) tv[tl++] = c;
        }
        if (i >= len){ bad = true; break; }
        i++;
        tv[tl] = 0;
        if (strcmp(tv, "new_ssid") == 0) e.type = EV_NEW_SSID;
        else if (strcmp(tv, "deauth_burst") == 0) e.type = EV_DEAUTH_BURST;
        else if (strcmp(tv, "rate_spike") == 0) e.type = EV_RATE_SPIKE;
        else { bad = true; break; }
        have_type = true;
      } else if (strcmp(key, "ch") == 0){
        skipws();
        if (i >= len || p[i] < '0' || p[i] > '9'){ bad = true; break; }
        unsigned long v = 0;
        while (i < len && p[i] >= '0' && p[i] <= '9'){
          v = v * 10 + (uint32_t)(p[i++] - '0');
          if (v > 13){ bad = true; break; }
        }
        if (bad) break;
        e.ch = (uint8_t)v;
      } else if (strcmp(key, "detail") == 0){
        if (i >= len || p[i] != '"'){ bad = true; break; }
        i++;
        while (i < len && p[i] != '"'){
          char c = p[i];
          if (c == '\\'){
            i++;
            if (i >= len){ bad = true; break; }
            char q = p[i++];
            if (q == 'n') c = '\n';
            else if (q == 'r') c = '\r';
            else if (q == 't') c = '\t';
            else if (q == 'u'){
              if (i + 4 > len){ bad = true; break; }
              int code = 0;
              for (int k = 0; k < 4; k++){
                char h = p[i++];
                int d;
                if (h >= '0' && h <= '9') d = h - '0';
                else if (h >= 'a' && h <= 'f') d = h - 'a' + 10;
                else if (h >= 'A' && h <= 'F') d = h - 'A' + 10;
                else { bad = true; break; }
                code = code * 16 + d;
              }
              if (bad) break;
              c = (code < 0x100) ? (char)code : '?';
            }
            else c = q;                        // \" \\ \/ and friends
          } else {
            i++;
          }
          if (dlen < 31) det[dlen++] = c;      // detail is bounded at 31 chars
        }
        if (i >= len){ bad = true; break; }
        i++;
        det[dlen] = 0;
        have_det = true;
      } else {
        bad = true; break;                    // unknown key: not our format
      }
      skipws();
      if (i < len && p[i] == ','){ i++; continue; }
      if (i < len && p[i] == '}'){ i++; break; }
      bad = true; break;
    }
    if (bad || !have_ts || !have_type || !have_det) return 0;
    memcpy(e.detail, det, sizeof(e.detail));
    win[total % wcap] = e;
    total++;
    skipws();
    if (i < len && p[i] == ','){ i++; continue; }
    if (i < len && p[i] == ']'){ i++; break; }
    return 0;
  }
  skipws();
  if (i != len) return 0;                     // trailing garbage: corrupt
  return (int)total;
}
// Boot load: read EVENT_FILE into the ring (newest last in the file).
// Missing or corrupt file -> start empty (no crash). Returns events loaded.
static uint8_t events_load(){
  if (!LittleFS.exists(EVENT_FILE)) return 0;
  File f = LittleFS.open(EVENT_FILE, "r");
  if (!f) return 0;
  int len = f.size();
  if (len <= 0 || len > EVENT_FILE_MAX_BYTES + 256){ f.close(); return 0; }
  uint8_t* buf = (uint8_t*)malloc((size_t)len + 1);
  if (!buf){ f.close(); return 0; }
  int rd = (int)f.read(buf, (size_t)len);
  f.close();
  if (rd != len){ free(buf); return 0; }
  buf[rd] = '\0';
  static EvEntry win[EVENT_RING_SIZE + 1];
  int total = events_parse((const char*)buf, len, win, EVENT_RING_SIZE + 1);
  free(buf);
  if (total <= 0) return 0;
  int take = total > EVENT_RING_SIZE ? EVENT_RING_SIZE : total;
  int start = (total - take) % (int)(EVENT_RING_SIZE + 1);
  portENTER_CRITICAL(&g_mux);
  for (int k = 0; k < take; k++){
    g_ev_ring[k] = win[(start + k) % (EVENT_RING_SIZE + 1)];
  }
  g_ev_fill = (uint8_t)take;
  g_ev_head = (uint32_t)take;
  g_ev_pending = 0;
  portEXIT_CRITICAL(&g_mux);
  return (uint8_t)take;
}
// "events clear": clear the ring AND truncate the LittleFS file.
static void events_clear(){
  portENTER_CRITICAL(&g_mux);
  g_ev_fill = 0;
  g_ev_head = 0;
  g_ev_pending = 0;
  portEXIT_CRITICAL(&g_mux);
  File f = LittleFS.open(EVENT_FILE, "w");
  if (f){
    f.print("[]");
    f.close();
  }
}
// "events": print the current ring, compact, newest first.
static void events_print_console(){
  static EvEntry snap[EVENT_RING_SIZE];
  uint8_t fill = 0;
  uint32_t head = 0;
  portENTER_CRITICAL(&g_mux);
  fill = g_ev_fill;
  head = g_ev_head;
  for (int i = 0; i < (int)fill; i++){
    uint32_t idx = (head + EVENT_RING_SIZE - 1 - i) % EVENT_RING_SIZE;
    snap[i] = g_ev_ring[idx];
  }
  portEXIT_CRITICAL(&g_mux);
  if (!fill){
    Serial.println("[events] (none)");
    return;
  }
  for (int i = 0; i < (int)fill; i++){
    const EvEntry* e = &snap[i];
    Serial.printf("[events] %s ch=%u ts=%us %.*s\n", ev_type_name(e->type),
                  (unsigned)(e->ch ? e->ch : 0), (unsigned)e->ts_s,
                  (int)strlen(e->detail), e->detail);
  }
}

// ----------------------------- NVS (home channel) ------------------------
static void nvs_load_home(){
  nvs_handle_t h;
  if (nvs_open("sniffer", NVS_READONLY, &h) != ESP_OK) return;
  uint8_t v = 0;
  if (nvs_get_u8(h, "homech", &v) == ESP_OK && v >= 1 && v <= 13) g_home_ch = (uint8_t)v;
  nvs_close(h);
}
static void nvs_save_home(uint8_t ch){
  nvs_handle_t h;
  if (nvs_open("sniffer", NVS_READWRITE, &h) != ESP_OK) return;
  nvs_set_u8(h, "homech", ch);
  nvs_commit(h);
  nvs_close(h);
}

// ----------------------------- helpers -----------------------------------
static int hexval(char c){
  if (c>='0'&&c<='9') return c-'0';
  if (c>='a'&&c<='f') return c-'a'+10;
  if (c>='A'&&c<='F') return c-'A'+10;
  return -1;
}
static bool parse_mac(const String& s, uint8_t* out){
  if (s.length()!=17) return false;
  const char* c = s.c_str();
  uint8_t tmp[6];
  for (int k=0;k<6;k++){
    int i=3*k;
    if (k>0 && c[i-1]!=':') return false;
    int h=hexval(c[i]), l=hexval(c[i+1]);
    if (h<0||l<0) return false;
    tmp[k]=(uint8_t)((h<<4)|l);
  }
  memcpy(out, tmp, 6);   // commit only on full success
  return true;
}
static void appendMac(String& s, const uint8_t* m){
  static const char* hex="0123456789ABCDEF";
  for (int i=0;i<6;i++){
    s += hex[m[i]>>4]; s += hex[m[i]&0xF];
    if (i<5) s += ':';
  }
}
static void hexmac(const uint8_t* m, char out[18]){
  static const char* hex="0123456789ABCDEF";
  for (int i=0;i<6;i++){
    out[3*i]=hex[m[i]>>4]; out[3*i+1]=hex[m[i]&0xF];
    if (i<5) out[3*i+2]=':';
  }
  out[17]='\0';
}
// Binary-safe SSID -> JSON (printable ASCII literal, everything else \u00XX).
static void appendSsid(String& s, const uint8_t* d, uint8_t len){
  char b[8];
  for (int i=0;i<len;i++){
    uint8_t c=d[i];
    if (c=='"')      s += "\\\"";
    else if (c=='\\') s += "\\\\";
    else if (c=='\n') s += "\\n";
    else if (c=='\r') s += "\\r";
    else if (c=='\t') s += "\\t";
    else if (c<0x20 || c>=0x7f){ snprintf(b, sizeof(b), "\\u%04X", c); s += b; }
    else s += (char)c;
  }
}
static int bss_count(){
  int c=0;
  for (int i=0;i<BSS_MAX;i++) if (g_bss[i].used) c++;
  return c;
}
static uint8_t ssid_lookup(const uint8_t* d, uint8_t len){
  for (int i=0;i<SSID_MAX;i++){
    if (g_ssid[i].used && g_ssid[i].len==len && !memcmp(g_ssid[i].data,d,len)) return (uint8_t)i;
  }
  return 255;
}
static uint8_t ssid_add(const uint8_t* d, uint8_t len){
  uint8_t idx = ssid_lookup(d,len);
  if (idx!=255) return idx;
  for (int i=0;i<SSID_MAX;i++){
    if (!g_ssid[i].used){
      g_ssid[i].used=1; g_ssid[i].len=len; memcpy(g_ssid[i].data,d,len);
      g_ssid_used++;
      return (uint8_t)i;
    }
  }
  return 255;
}
static BSS* bss_find_locked(const uint8_t* mac){
  for (int i=0;i<BSS_MAX;i++) if (g_bss[i].used && !memcmp(g_bss[i].mac,mac,6)) return &g_bss[i];
  return nullptr;
}
// Called while holding g_mux.
static BSS* bss_find_or_create(const uint8_t* mac, bool create){
  BSS* found = bss_find_locked(mac);
  if (found) return found;
  if (!create) return nullptr;
  for (int i=0;i<BSS_MAX;i++){
    if (!g_bss[i].used){
      BSS* b=&g_bss[i];
      memset(b,0,sizeof(*b));
      memcpy(b->mac,mac,6);
      b->used=1; b->rssi=-127; b->rmin=127; b->rmax=-127;
      b->ssid_idx=255; b->sec=SEC_UNKNOWN;
      return b;
    }
  }
  return nullptr; // table full
}
// SSID element (id 0): probe-request (4) IEs start at offset 24,
// probe-response (5) / beacon (8) IEs start at offset 36.
// Only those subtypes carry this element; any other subtype, or a header
// too short to reach the element, yields 0 (no SSID). An SSID element whose
// length exceeds maxlen is rejected outright, never truncated.
static uint8_t parse_ssid(uint8_t* f, uint16_t len, uint8_t subtype, uint8_t* out, uint8_t maxlen){
  uint16_t ie_start;
  if (subtype==4) ie_start = 24;
  else if (subtype==5 || subtype==8) ie_start = 36;
  else return 0;
  if (len < ie_start) return 0;
  for (uint16_t off=ie_start; off+2<=len;){
    uint8_t id=f[off], l=f[off+1];
    if (off+2+l>len) break;
    if (id==0){
      if (l>maxlen) return 0;
      memcpy(out, f+off+2, l);
      return l;
    }
    off += 2 + l;
  }
  return 0;
}
// Security metadata from the management-frame IE list, beacon (8) and
// probe-response (5) only, with len>=36. IEs are walked from offset 36 with
// bounds LOCAL to each IE. A single IE whose length field overruns the frame
// end is truncated and forces SEC_UNKNOWN - we never silently stop and label a
// privacy frame WEP. The 0x0010 privacy bit is a legacy heuristic: a privacy
// frame advertising no RSN/WPA IE is reported SEC_WEP (NOT a cryptographic
// guarantee: it cannot distinguish WEP from other ciphers or validate keys).
// RSN (id 48) and WPA (id 221) bodies carry a 4-byte vendor prefix
// (OUI + version) before the pairwise count, then count+4-byte selector
// pairs. RSN OUI 00:0f:ac; WPA prefix 00:50:f2:01. Pairwise TKIP=2, CCMP=4.
// AKM classes (wpa_common.h selectors): 2/4/6 PSK family, 8/9 SAE family,
// 1/3/5 enterprise family. SAE+PSK->WPA2-3, SAE only->WPA3, supported PSK
// ->WPA2, enterprise->ENT. Malformed/truncated/unsupported -> SEC_UNKNOWN.
static uint8_t parse_security(uint8_t* f, uint16_t len, uint8_t subtype) {
    if (subtype != 8 && subtype != 5) return SEC_UNKNOWN;
    if (!f || len < 36) return SEC_UNKNOWN;

    uint16_t cap = (uint16_t)(f[34] | (f[35] << 8));
    bool privacy = (cap & 0x0010) != 0;

    auto oui_eq = [](const uint8_t* p, const uint8_t* o) {
        return p[0] == o[0] && p[1] == o[1] && p[2] == o[2];
    };

    auto parse_rsn = [&](const uint8_t* d, uint8_t l) -> uint8_t {
        static const uint8_t RSN_OUI[3] = {0x00, 0x0f, 0xac};
        if (l < 8) return SEC_UNKNOWN;
        uint16_t ver = (uint16_t)(d[0] | (d[1] << 8));
        if (ver != 1) return SEC_UNKNOWN;

        if (!oui_eq(d + 2, RSN_OUI)) return SEC_UNKNOWN;
        uint8_t group_type = d[5];
        if (group_type != 2 && group_type != 4) return SEC_UNKNOWN;

        uint16_t pc = (uint16_t)(d[6] | (d[7] << 8));
        if (pc == 0) return SEC_UNKNOWN;
        if ((uint16_t)(l - 8) < (uint16_t)pc * 4) return SEC_UNKNOWN;

        bool valid_cipher = false;
        for (uint16_t k = 0; k < pc; k++) {
            const uint8_t* sel = d + 8 + k * 4;
            if (!oui_eq(sel, RSN_OUI)) return SEC_UNKNOWN;
            uint8_t t = sel[3];
            if (t == 2 || t == 4) valid_cipher = true; else return SEC_UNKNOWN;
        }

        uint16_t ac_off = 8 + pc * 4;
        if ((uint16_t)(l - ac_off) < 2) return SEC_UNKNOWN;
        uint16_t ac = (uint16_t)(d[ac_off] | (d[ac_off + 1] << 8));
        if (ac == 0) return SEC_UNKNOWN;
        if ((uint16_t)(l - ac_off - 2) < (uint16_t)ac * 4) return SEC_UNKNOWN;

        bool psk = false, sae = false, ent = false, bad = false;
        for (uint16_t k = 0; k < ac; k++) {
            const uint8_t* sel = d + ac_off + 2 + k * 4;
            if (!oui_eq(sel, RSN_OUI)) return SEC_UNKNOWN;
            switch (sel[3]) {
                case 2: case 4: case 6: psk = true; break;
                case 8: case 9: sae = true; break;
                case 1: case 3: case 5: ent = true; break;
                default: bad = true; break;
            }
        }
        if (bad) return SEC_UNKNOWN;
        if (!psk && !sae && !ent) return SEC_UNKNOWN;
        if (!valid_cipher) return SEC_UNKNOWN;

        if (sae && psk) return SEC_WPA2_3;
        if (sae) return SEC_WPA3;
        if (ent) return SEC_ENT;
        if (psk) return SEC_WPA2;
        return SEC_UNKNOWN;
    };

    auto parse_wpa = [&](const uint8_t* d, uint8_t l) -> uint8_t {
        static const uint8_t WPA_OUI[3] = {0x00, 0x50, 0xf2};
        if (l < 12) return SEC_UNKNOWN;
        if (!oui_eq(d, WPA_OUI) || d[3] != 1) return SEC_UNKNOWN;

        uint16_t ver = (uint16_t)(d[4] | (d[5] << 8));
        if (ver != 1) return SEC_UNKNOWN;

        if (!oui_eq(d + 6, WPA_OUI)) return SEC_UNKNOWN;
        uint8_t group_type = d[9];
        if (group_type != 2 && group_type != 4) return SEC_UNKNOWN;

        uint16_t pc = (uint16_t)(d[10] | (d[11] << 8));
        if (pc == 0) return SEC_UNKNOWN;
        if ((uint16_t)(l - 12) < (uint16_t)pc * 4) return SEC_UNKNOWN;

        bool valid_cipher = false;
        for (uint16_t k = 0; k < pc; k++) {
            const uint8_t* sel = d + 12 + k * 4;
            if (!oui_eq(sel, WPA_OUI)) return SEC_UNKNOWN;
            uint8_t t = sel[3];
            if (t == 2 || t == 4) valid_cipher = true; else return SEC_UNKNOWN;
        }

        uint16_t ac_off = 12 + pc * 4;
        if ((uint16_t)(l - ac_off) < 2) return SEC_UNKNOWN;
        uint16_t ac = (uint16_t)(d[ac_off] | (d[ac_off + 1] << 8));
        if (ac == 0) return SEC_UNKNOWN;
        if ((uint16_t)(l - ac_off - 2) < (uint16_t)ac * 4) return SEC_UNKNOWN;

        bool psk = false, ent = false, bad = false;
        for (uint16_t k = 0; k < ac; k++) {
            const uint8_t* sel = d + ac_off + 2 + k * 4;
            if (!oui_eq(sel, WPA_OUI)) return SEC_UNKNOWN;
            switch (sel[3]) {
                case 2: psk = true; break;
                case 1: ent = true; break;
                default: bad = true; break;
            }
        }
        if (bad) return SEC_UNKNOWN;
        if (!psk && !ent) return SEC_UNKNOWN;
        if (!valid_cipher) return SEC_UNKNOWN;

        if (ent) return SEC_ENT;
        if (psk) return SEC_WPA;
        return SEC_UNKNOWN;
    };

    uint8_t rsn_sec = SEC_UNKNOWN;
    uint8_t wpa_sec = SEC_UNKNOWN;
    bool rsn_found = false;
    bool wpa_found = false;
    bool malformed = false;

    uint16_t off = 36;
    while (off + 2 <= len) {
        uint8_t id = f[off];
        uint8_t l = f[off + 1];
        if (l > len - off - 2) {
            malformed = true;
            break;
        }
        if (id == 48) {
            rsn_found = true;
            rsn_sec = parse_rsn(f + off + 2, l);
            if (rsn_sec == SEC_UNKNOWN) malformed = true;
        } else if (id == 221) {
            if (l >= 4 && f[off + 2] == 0x00 && f[off + 3] == 0x50 && f[off + 4] == 0xf2 && f[off + 5] == 0x01) {
                wpa_found = true;
                wpa_sec = parse_wpa(f + off + 2, l);
                if (wpa_sec == SEC_UNKNOWN) malformed = true;
            }
        }
        off += 2 + l;
    }

    if (off != len) return SEC_UNKNOWN;
    if (malformed) return SEC_UNKNOWN;
    if (!privacy && (rsn_found || wpa_found)) return SEC_UNKNOWN;

    if (rsn_found && rsn_sec != SEC_UNKNOWN) return rsn_sec;
    if (wpa_found && wpa_sec != SEC_UNKNOWN) return wpa_sec;

    if (privacy) return SEC_WEP;
    return SEC_OPEN;
}

// ----------------------------- capture callback --------------------------
static void promiscuous_cb(void* buf, wifi_promiscuous_pkt_type_t ptype){
  if (!buf) return;
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  uint32_t sig_len = p->rx_ctrl.sig_len;
  if (sig_len <= 4) return;                              // nothing but FCS
  uint16_t frame_len = (uint16_t)(sig_len - 4);          // subtract 4-byte FCS

  uint8_t type;
  switch (ptype){
    case WIFI_PKT_MGMT: type=0; break;
    case WIFI_PKT_CTRL: type=1; break;
    case WIFI_PKT_DATA: type=2; break;
    default:            type=3; break;                 // WIFI_PKT_MISC
  }

  // Per the installed SDK, WIFI_PKT_MISC carries a zero-length payload: it is
  // metadata-only (channel switch, sleep-wake and other vendor packets).
  // Never parse it as 802.11; count it as an "other" frame with no fabricated
  // address or frame-control fields.
  if (type==3){
    uint32_t now = millis();
    portENTER_CRITICAL(&g_mux);
    if (g_ring_total >= RING_SIZE) { if (g_dropped < UINT32_MAX) g_dropped++; }
    RingEntry e;
    memset(&e,0,sizeof(e));
    e.ts=now; e.ch=(uint8_t)p->rx_ctrl.channel;
    e.rssi=(int8_t)p->rx_ctrl.rssi; e.type=type;
    e.rate=(uint16_t)p->rx_ctrl.rate; e.phy=(uint8_t)p->rx_ctrl.sig_mode;
    e.ssid_idx=255;                                     // src/bssid left zero
    g_ring[g_ring_head]=e;
    g_ring_head=(g_ring_head+1)%RING_SIZE;
    if (g_ring_total < UINT32_MAX) g_ring_total++;
    if (g_total < UINT32_MAX) g_total++;
    if (g_type_cnt[type] < UINT32_MAX) g_type_cnt[type]++;
    if (g_rate_in_progress < UINT32_MAX) g_rate_in_progress++;
    // MISC has no 802.11 content: for sweep bookkeeping it only counts toward
    // per-channel frames + activity, never BSSID/SSID/security.
    if (g_sw_active && g_sw_active <= 13){
      SweepCh* sc = &g_sweep_ch[g_sw_active-1];
      if (sc->frames < UINT32_MAX) sc->frames++;
      g_sw_last_frame_ms = now;
    }
    portEXIT_CRITICAL(&g_mux);
    return;
  }

  uint8_t* f = p->payload;
  // ACK/CTS: 10 bytes, RA only at f+4. RTS: 16 bytes, RA at f+4, TA at f+10.
  // A 3-addr management/data header needs 24. Do not impose a universal 24-byte
  // floor: valid short control frames must still be counted.
  if (type==1 ? frame_len < 10 : frame_len < 24) return;

  int8_t   rssi  = (int8_t)p->rx_ctrl.rssi;              // signed dBm
  uint8_t  ch    = (uint8_t)p->rx_ctrl.channel;
  uint16_t rate  = (uint16_t)p->rx_ctrl.rate;            // 11b/g PHY rate code
  uint8_t  phy   = (uint8_t)p->rx_ctrl.sig_mode;         // 0 11b/g, 1 11n, 3 11ac

  uint16_t fc = (uint16_t)(f[0] | (f[1]<<8));
  uint8_t  subtype = (fc >> 4) & 0x0F;

  uint8_t src[6]; memset(src,0,6);                       // transmitter / TA
  if (type==2){                                          // data: TA is addr2 (24B hdr)
    memcpy(src, f+10, 6);
  } else if (type==1 && (subtype==11)){                  // control: only RTS
    if (frame_len >= 16) memcpy(src, f+10, 6);           // TA is addr2
  }                                                      // ACK/CTS: no source addr; stays zero

  uint8_t bssid[6]; memset(bssid,0,6);
  bool bss_create=false;
  bool bssid_set=false;
  if (type==0){                                          // management
    if (subtype==8 || subtype==5){
      if (frame_len >= 36) { memcpy(bssid, f+16, 6); bssid_set=true; } // BSSID = addr3
    }
    memcpy(src, f+10, 6);                                // TA = addr2
  } else if (type==2){                                   // data: ToDS/FromDS addr rules
    bool tds = (fc & 0x0100) != 0;
    bool fds = (fc & 0x0200) != 0;
    if (!tds && !fds){
      if (frame_len >= 24) { memcpy(bssid, f+16, 6); bssid_set=true; } // BSSID = addr3
    } else if (tds && !fds){
      if (frame_len >= 24) { memcpy(bssid, f+4, 6); bssid_set=true; }  // BSSID = addr1
    } else if (!tds && fds){
      if (frame_len >= 24) { memcpy(bssid, f+10, 6); bssid_set=true; } // BSSID = addr2
    } else if (tds && fds){
      if (frame_len < 30) return;
      // Four-address WDS has NO BSSID; leave bssid zero and bssid_set false
    }
  }
  if (bssid_set){
    bool nonzero = false;
    for (int i=0; i<6; i++) if (bssid[i] != 0) { nonzero = true; break; }
    bool unicast = (bssid[0] & 0x01) == 0;
    if (nonzero && unicast) bss_create = true;
    else { memset(bssid, 0, 6); bssid_set = false; }
  }

  // SSID / security: bounded locals computed BEFORE taking g_mux; the pool
  // mutation (ssid_add) happens under the same lock as BSS/ring state.
  uint8_t ssid_idx=255; uint8_t ssidbuf[SSID_MAXLEN]; uint8_t sslen=0;
  uint8_t sec = SEC_UNKNOWN;
  if (type==0){
    if (subtype==8 || subtype==5 || subtype==4){
      sslen = parse_ssid(f, frame_len, subtype, ssidbuf, SSID_MAXLEN);
    }
    if (subtype==8 || subtype==5){
      sec = parse_security(f, frame_len, subtype);
    }
  }

  uint32_t now = millis();
  bool is_mgmt_ap = (type==0 && (subtype==8 || subtype==5) && frame_len>=36); // RSSI-representative

  portENTER_CRITICAL(&g_mux);
  if (g_ring_total >= RING_SIZE) { if (g_dropped < UINT32_MAX) g_dropped++; }
  RingEntry e;
  e.ts=now; e.ch=ch; e.rssi=rssi; e.type=type; e.subtype=subtype;
  e.rate=rate; e.phy=phy;
  memcpy(e.src,src,6); memcpy(e.bssid,bssid,6);
  if (sslen>0) ssid_idx = ssid_add(ssidbuf, sslen);      // pool mutation under g_mux
  e.ssid_idx=ssid_idx;
  g_ring[g_ring_head]=e;
  g_ring_head=(g_ring_head+1)%RING_SIZE;
  if (g_ring_total < UINT32_MAX) g_ring_total++;
  if (g_total < UINT32_MAX) g_total++;
  if (g_type_cnt[type] < UINT32_MAX) g_type_cnt[type]++;
  if (subtype<16 && g_sub_cnt[type][subtype] < UINT32_MAX) g_sub_cnt[type][subtype]++;
  if (g_rate_in_progress < UINT32_MAX) g_rate_in_progress++;

  if (bss_create){
    BSS* b = bss_find_or_create(bssid, true);
    if (b){
      if (b->first_ms==0) b->first_ms=now;
      b->last_ms=now;
      b->ch=ch;                                         // S5: last-seen channel (bounded overwrite)
      if (b->frames < UINT32_MAX) b->frames++;
      if (is_mgmt_ap){
        if (b->rsum_n==0){ b->rmin=rssi; b->rmax=rssi; }
        if (rssi<b->rmin) b->rmin=rssi;
        if (rssi>b->rmax) b->rmax=rssi;
        b->rssi=rssi;
        if (b->rsum_n != UINT32_MAX) { b->rsum += (int64_t)rssi; b->rsum_n++; }
        b->hist[b->hist_head]=rssi;
        b->hist_head=(b->hist_head+1)%RSSI_HIST;
        if (b->hist_count<RSSI_HIST) b->hist_count++;
        b->sec = sec;
        if (sslen>0) b->ssid_idx=ssid_idx;
        if (subtype==8 && frame_len>=36) b->beacon_int = (uint16_t)(f[32] | (f[33]<<8));
      }
    }
  }

  // ---------------- sweep bucketing (g_mux held) ----------------
  // g_sw_active: 0 = off, 1..13 = capture into that sweep channel,
  // 128+ch = pre-sweep baseline observation on channel ch.
  if (g_sw_active){
    if (g_sw_active <= 13){
      SweepCh* sc = &g_sweep_ch[g_sw_active-1];
      if (sc->frames < UINT32_MAX) sc->frames++;
      if (type==1 && (subtype==11 || subtype==12 || subtype==13))
        if (sc->ctrl < UINT32_MAX) sc->ctrl++;
      if (bssid_set){
        SweepBss* e2 = nullptr;
        for (int k=0;k<SWEEP_BSS_CAP;k++){
          if (sc->bss[k].used && !memcmp(sc->bss[k].mac,bssid,6)){ e2=&sc->bss[k]; break; }
        }
        if (!e2 && sc->bss_n < SWEEP_BSS_CAP){
          e2 = &sc->bss[sc->bss_n++];
          memset(e2,0,sizeof(*e2));
          memcpy(e2->mac,bssid,6);
          e2->rmax=-127; e2->used=1;
        }
        if (e2){
          if (is_mgmt_ap && rssi>e2->rmax) e2->rmax=rssi;
          if (sec!=SEC_UNKNOWN) e2->sec=sec;
          if (sslen>0) e2->ssid_idx=ssid_idx;
        }
      }
      if (sslen>0 && ssid_idx<SSID_MAX) sc->ssid_mask |= (1u<<ssid_idx);
      g_sw_last_frame_ms = now;
    } else {
      // Pre-sweep observation: record BSSIDs seen on the home channel.
      uint8_t bc = (uint8_t)(g_sw_active-128);
      if (bssid_set && bc <= 12){
        SweepBss* tab = g_base[bc];
        SweepBss* e2 = nullptr;
        for (int k=0;k<SWEEP_BSS_CAP;k++){
          if (tab[k].used && !memcmp(tab[k].mac,bssid,6)){ e2=&tab[k]; break; }
        }
        if (!e2 && g_base_n[bc] < SWEEP_BSS_CAP){
          e2 = &tab[g_base_n[bc]];
          memset(e2,0,sizeof(*e2));
          memcpy(e2->mac,bssid,6);
          e2->rmax=-127; e2->used=1;
          g_base_n[bc]++;
        }
      }
    }
  }
  // ---------------- event detection (S4; g_mux held) ----------------
  ev_detect(f, frame_len, type, subtype, bssid, bssid_set, ch,
            ssid_idx, sslen, now);
  portEXIT_CRITICAL(&g_mux);
}

// ----------------------------- sweep engine ------------------------------
static bool wifi_hop(uint8_t ch){
  // Move the whole wifi driver (softAP follows) to the primary channel.
  esp_err_t e = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  if (e != ESP_OK){
    Serial.printf("[sweep] esp_wifi_set_channel(%u) failed: %s\n", (unsigned)ch, esp_err_to_name(e));
    return false;
  }
  g_channel = ch;
  return true;
}
// Called while holding g_mux.
static void sweep_reset_tables(){
  memset(g_sweep_ch, 0, sizeof(g_sweep_ch));
  g_new_n = 0; g_moved_n = 0; g_quietest = 0;
}
// Derived metrics for one channel. elapsed_ms = full dwell (finalized) or the
// time elapsed so far (live, in-progress channel).
static void sweep_channel_metrics(SweepCh* c, uint32_t elapsed_ms, ChMetrics* m){
  m->frames = c->frames;
  m->ctrl   = c->ctrl;
  uint32_t r = elapsed_ms ? (c->frames * 1000ULL / elapsed_ms) : 0;
  m->rate   = (r > 65535) ? 65535 : (uint16_t)r;
  uint32_t a = elapsed_ms ? (c->active_ms * 100ULL / elapsed_ms) : 0;
  m->act    = (a > 100) ? 100 : (uint8_t)a;
  m->bssids = c->bss_n;
  m->ssids  = (uint8_t)__builtin_popcount(c->ssid_mask);
  m->sec_open = m->sec_wpa2 = m->sec_wpa3 = m->sec_other = 0;
  m->rmax = -127; m->ravg = -127;
  int64_t sum = 0; uint32_t n = 0;
  for (int k=0;k<(int)c->bss_n;k++){
    SweepBss* b = &c->bss[k];
    switch (b->sec){
      case SEC_OPEN: m->sec_open++; break;
      case SEC_WPA2: m->sec_wpa2++; break;
      case SEC_WPA3: m->sec_wpa3++; break;
      default:       m->sec_other++; break;   // WEP/WPA/WPA2-3/ENT/unknown
    }
    if (b->rmax != -127){
      if (b->rmax > m->rmax) m->rmax = b->rmax;
      sum += (int64_t)b->rmax; n++;
    }
  }
  if (n) m->ravg = (int8_t)(sum / n);
}
// Called while holding g_mux (after the final channel's counters are settled).
static void sweep_compute_new_moved(){
  g_new_n = 0; g_moved_n = 0;
  for (uint8_t ch = 1; ch <= 13; ch++){
    SweepCh* c = &g_sweep_ch[ch-1];
    for (int k = 0; k < (int)c->bss_n; k++){
      SweepBss* b = &c->bss[k];
      uint8_t base_ch = 0;
      for (int bc = 0; bc < 13 && !base_ch; bc++){
        for (int j = 0; j < g_base_n[bc]; j++){
          if (!memcmp(g_base[bc][j].mac, b->mac, 6)){ base_ch = (uint8_t)(bc+1); break; }
        }
      }
      if (base_ch == 0){
        if (g_new_n < SWEEP_LIST_CAP){
          memcpy(g_new_mac[g_new_n], b->mac, 6);
          g_new_ssid[g_new_n] = b->ssid_idx;
          g_new_ch[g_new_n] = ch;
          g_new_n++;
        }
      } else if (base_ch != ch){
        if (g_moved_n < SWEEP_LIST_CAP){
          memcpy(g_moved_mac[g_moved_n], b->mac, 6);
          g_moved_from[g_moved_n] = base_ch;
          g_moved_to[g_moved_n] = ch;
          g_moved_n++;
        }
      }
    }
  }
}
// Quietest channel = lowest weighted score over (activity_pct, frame rate,
// BSSID count), each term normalized by its own max across the 13 channels:
//   score = 0.5*(act/max_act) + 0.3*(rate/max_rate) + 0.2*(bss/max_bss)
// All-zero sweep -> channel 1. Ties -> lower channel number.
static void sweep_compute_quietest(){
  ChMetrics m[13];
  uint32_t dwell_ms = (uint32_t)g_sw_dwell_s * 1000;
  uint32_t max_act = 0, max_rate = 0, max_bss = 0;
  for (int i=0;i<13;i++){
    sweep_channel_metrics(&g_sweep_ch[i], dwell_ms, &m[i]);
    if (m[i].act > max_act) max_act = m[i].act;
    if (m[i].rate > max_rate) max_rate = m[i].rate;
    if (m[i].bssids > max_bss) max_bss = m[i].bssids;
  }
  if (max_act == 0 && max_rate == 0 && max_bss == 0){ g_quietest = 1; return; }
  uint32_t best = UINT32_MAX;
  uint8_t  bestch = 1;
  for (int i=0;i<13;i++){
    uint64_t score = 0;
    if (max_act)  score += (uint64_t)m[i].act    * 5000ULL / max_act;
    if (max_rate) score += (uint64_t)m[i].rate   * 3000ULL / max_rate;
    if (max_bss)  score += (uint64_t)m[i].bssids * 2000ULL / max_bss;
    if (score < best){ best = score; bestch = (uint8_t)(i+1); }
  }
  g_quietest = bestch;
}
// Called while holding g_mux (at sweep completion).
static void sweep_store_baseline(){
  for (int i=0;i<13;i++){
    memcpy(g_base[i], g_sweep_ch[i].bss, sizeof(g_base[i]));
    g_base_n[i] = g_sweep_ch[i].bss_n;
  }
  g_have_baseline = true;
}
// Returns 0 started, 1 busy, 2 hop failed.
static int sweep_start(uint8_t dwell_s){
  uint8_t st = g_sw_state;
  if (st != SW_IDLE && st != SW_DONE) return 1;
  uint32_t now = millis();
  portENTER_CRITICAL(&g_mux);
  sweep_reset_tables();
  g_sw_dwell_s = dwell_s;
  g_sw_start_ms = now;
  g_sw_done_ms = 0;
  g_sw_last_frame_ms = 0;
  g_sw_tick_ms = 0;
  g_sw_home_action = HA_NONE;
  portEXIT_CRITICAL(&g_mux);
  Serial.printf("[sweep] start: home ch %u -> ch 1 (dwell %u s)\n", (unsigned)g_home_ch, (unsigned)dwell_s);
  if (g_channel != g_home_ch){
    if (!wifi_hop(g_home_ch)) return 2;
    g_sw_state = SW_HOME; g_sw_home_action = HA_BEGIN_SWEEP; g_sw_phase_ms = now;
    return 0;
  }
  if (!g_have_baseline){
    portENTER_CRITICAL(&g_mux); g_sw_active = (uint8_t)(128 + g_home_ch); portEXIT_CRITICAL(&g_mux);
    g_sw_state = SW_PRIME; g_sw_phase_ms = now;
    Serial.printf("[sweep] pre-observe %u s on home ch %u (first-sweep baseline)\n",
                  (unsigned)(PRIME_MS/1000), (unsigned)g_home_ch);
  } else {
    if (!wifi_hop(1)) return 2;
    g_sw_ch = 1; g_sw_state = SW_SETTLE; g_sw_phase_ms = now;
  }
  return 0;
}
// Returns 0 stopped a running sweep, 1 nothing running, 2 canceled pending start.
static int sweep_stop(){
  uint8_t st = g_sw_state;
  if (st != SW_PRIME && st != SW_SETTLE && st != SW_DWELL){
    if (st == SW_HOME && g_sw_home_action == HA_BEGIN_SWEEP){
      g_sw_home_action = HA_ABORT;
      return 2;
    }
    return 1;
  }
  uint32_t now = millis();
  portENTER_CRITICAL(&g_mux);
  if (st == SW_PRIME){
    // Aborted mid-observation: the partial baseline is discarded.
    memset(g_base, 0, sizeof(g_base));
    memset(g_base_n, 0, sizeof(g_base_n));
    g_have_baseline = false;
  }
  g_sw_active = 0;
  sweep_reset_tables();
  g_sw_done_ms = 0;
  portEXIT_CRITICAL(&g_mux);
  Serial.printf("[sweep] aborted at ch %u, returning to home ch %u\n",
                (unsigned)(st == SW_PRIME ? g_home_ch : g_sw_ch), (unsigned)g_home_ch);
  if (g_channel != g_home_ch){
    if (wifi_hop(g_home_ch)){ g_sw_state = SW_HOME; g_sw_home_action = HA_ABORT; g_sw_phase_ms = now; }
    else g_sw_state = SW_IDLE;
  } else {
    g_sw_state = SW_IDLE;
  }
  return 0;
}
// Returns 0 ok / 1 aborted a sweep / 2 hop failed.
static int cmd_home(){
  uint8_t st = g_sw_state;
  if (st == SW_PRIME || st == SW_SETTLE || st == SW_DWELL){
    sweep_stop();
    return 1;
  }
  if (st == SW_HOME && g_sw_home_action == HA_BEGIN_SWEEP){
    g_sw_home_action = HA_ABORT;
    return 1;
  }
  if (g_channel != g_home_ch && !wifi_hop(g_home_ch)) return 2;
  return 0;
}
// Loop-tick state machine: IDLE | PRIME | SETTLE | DWELL | HOME | DONE.
static void sweep_tick(){
  uint32_t now = millis();
  uint8_t st = g_sw_state;
  if (st == SW_PRIME){
    if (now - g_sw_phase_ms >= PRIME_MS){
      portENTER_CRITICAL(&g_mux);
      g_have_baseline = true;
      g_sw_active = 0;
      portEXIT_CRITICAL(&g_mux);
      Serial.printf("[sweep] pre-observe done on home ch %u -> ch 1\n", (unsigned)g_home_ch);
      if (wifi_hop(1)){ g_sw_ch = 1; g_sw_state = SW_SETTLE; g_sw_phase_ms = now; }
      else            { g_sw_state = SW_HOME; g_sw_home_action = HA_ABORT; g_sw_phase_ms = now; }
    }
  } else if (st == SW_SETTLE){
    if (now - g_sw_phase_ms >= SETTLE_MS){
      portENTER_CRITICAL(&g_mux);
      g_sw_active = g_sw_ch;
      g_sw_last_frame_ms = 0;
      g_sw_state = SW_DWELL;
      g_sw_phase_ms = now;
      portEXIT_CRITICAL(&g_mux);
    }
  } else if (st == SW_DWELL){
    // activity_pct: accumulate ms of the dwell during which at least one
    // frame was seen within the last 250 ms (occupancy estimate, NOT a noise
    // floor). loop() ticks ~every 2 ms, so sampling is ~0.1% resolution.
    uint32_t dt = now - g_sw_tick_ms;
    g_sw_tick_ms = now;
    if (dt > 0 && dt < 500){
      uint32_t lf = g_sw_last_frame_ms;
      if (lf && (now - lf) <= 250){
        portENTER_CRITICAL(&g_mux);
        uint32_t* am = &g_sweep_ch[g_sw_ch-1].active_ms;
        if (*am < UINT32_MAX) *am += dt;
        portEXIT_CRITICAL(&g_mux);
      }
    }
    if (now - g_sw_phase_ms >= (uint32_t)g_sw_dwell_s * 1000){
      portENTER_CRITICAL(&g_mux);
      g_sw_active = 0;
      ChMetrics m;
      sweep_channel_metrics(&g_sweep_ch[g_sw_ch-1], (uint32_t)g_sw_dwell_s * 1000, &m);
      uint8_t donech = g_sw_ch;
      portEXIT_CRITICAL(&g_mux);
      Serial.printf("[sweep] ch %u: frames=%lu rate=%u pps bssids=%u activity=%u%%\n",
                    (unsigned)donech, (unsigned long)m.frames, (unsigned)m.rate,
                    (unsigned)m.bssids, (unsigned)m.act);
      uint32_t now2 = millis();
      if (donech < 13){
        if (wifi_hop((uint8_t)(donech+1))){
          g_sw_ch = (uint8_t)(donech+1); g_sw_state = SW_SETTLE; g_sw_phase_ms = now2;
        } else {
          g_sw_state = SW_HOME; g_sw_home_action = HA_ABORT; g_sw_phase_ms = now2;
        }
      } else {
        // Sweep complete: finalize new/moved + quietest, store the baseline,
        // then hop home.
        portENTER_CRITICAL(&g_mux);
        sweep_compute_new_moved();
        sweep_compute_quietest();
        sweep_store_baseline();
        g_sw_done_ms = now2 - g_sw_start_ms;
        portEXIT_CRITICAL(&g_mux);
        Serial.printf("[sweep] done: %lu ms, quietest ch %u, new=%u moved=%u\n",
                      (unsigned long)g_sw_done_ms, (unsigned)g_quietest,
                      (unsigned)g_new_n, (unsigned)g_moved_n);
        if (wifi_hop(g_home_ch)){ g_sw_state = SW_HOME; g_sw_home_action = HA_DONE; g_sw_phase_ms = now2; }
        else                     { g_sw_state = SW_DONE; }
      }
    }
  } else if (st == SW_HOME){
    if (now - g_sw_phase_ms >= SETTLE_MS){
      uint8_t act = g_sw_home_action;
      g_sw_home_action = HA_NONE;
      if (act == HA_BEGIN_SWEEP){
        if (!g_have_baseline){
          portENTER_CRITICAL(&g_mux); g_sw_active = (uint8_t)(128 + g_home_ch); portEXIT_CRITICAL(&g_mux);
          g_sw_state = SW_PRIME; g_sw_phase_ms = now;
          Serial.printf("[sweep] pre-observe %u s on home ch %u (first-sweep baseline)\n",
                        (unsigned)(PRIME_MS/1000), (unsigned)g_home_ch);
        } else if (wifi_hop(1)){
          g_sw_ch = 1; g_sw_state = SW_SETTLE; g_sw_phase_ms = now;
        } else {
          g_sw_state = SW_IDLE;
        }
      } else if (act == HA_DONE){
        g_sw_state = SW_DONE;
      } else {
        g_sw_state = SW_IDLE;
      }
    }
  }
}

// ----------------------------- session logging (S5) ----------------------
// One open session at a time. All content is snapshotted from the EXISTING
// bounded structures (g_bss, g_ssid, g_ev_ring, g_sweep_ch) at flush/stop
// time - no new unbounded stores. littleFS writes happen only from loop()
// (debounced) and HTTP-handler (loop-context) code paths, never from the
// frame callback. Closed sessions persist as /sN.json + /sN.csv; N comes
// from /sess.idx (littleFS text counter - NVS intentionally not used).
// Rotation keeps the newest SESSION_KEEP closed sessions.
// Globals live with the other bounded state above; functions here are called
// from loop(), the serial console and the web handlers only.

// Compact per-BSS row (~32 B) snapshotted under g_mux: avoids copying the
// full BSS table (hist rings) and keeps the critical section short.
struct SessBss {
  uint8_t  mac[6];
  uint8_t  ssid_idx, sec, ch;
  int8_t   rssi, rmin, rmax;
  uint8_t  has_rssi;        // 1 when rsum_n > 0 (mgmt RSSI samples exist)
  int16_t  ravg;            // rsum / rsum_n, dBm (0 when no sample)
  uint32_t frames;
  uint32_t first_ms, last_ms;
  uint16_t beacon_int;
};
// Compact per-channel scalars (only what channels[] needs).
struct SessCh {
  uint32_t frames, ctrl, active_ms;
  uint8_t  bss_n;
};
struct SessSnap {
  int       nb;
  SessBss   bss[SESSION_CSV_BSS_CAP];
  SSIDEntry ssid[SSID_MAX];
  int       nev;
  EvEntry   ev[EVENT_RING_SIZE];   // newest first
  SessCh    ch[13];
  bool      have_base;
  uint8_t   dwell_s;
};

static void sess_paths(uint8_t id, char* json, char* csv){
  snprintf(json, 16, "/s%u.json", (unsigned)id);
  snprintf(csv, 16, "/s%u.csv", (unsigned)id);
}
static uint8_t sess_read_idx(){
  if (!LittleFS.exists(SESSION_IDX_FILE)) return 0;
  File f = LittleFS.open(SESSION_IDX_FILE, "r");
  if (!f) return 0;
  char buf[8];
  int n = (int)f.read((uint8_t*)buf, 7);
  f.close();
  if (n <= 0) return 0;
  buf[n] = '\0';
  long v = strtol(buf, nullptr, 10);
  return (v >= 0 && v <= 255) ? (uint8_t)v : 0;
}
// Write via tmp + rename: lfs_rename() is atomic on littleFS (a reader sees
// the old file or the new one, never a mix; an existing destination is
// atomically replaced), so this implements the design's "remove old + write
// new" in the strictly stronger rename form - a crash mid-write leaves the
// intact previous file plus a discarded .tmp.
static bool sess_write_file(const char* path, const String& data){
  char tmp[24];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  File f = LittleFS.open(tmp, "w");
  if (!f) return false;
  size_t w = f.print(data);
  f.close();
  if (w != data.length()){ LittleFS.remove(tmp); return false; }
  if (!LittleFS.rename(tmp, path)){ LittleFS.remove(tmp); return false; }
  return true;
}
// Copy the bounded structures into a SessSnap under g_mux (loop context).
static void sess_snapshot(SessSnap& sn, uint32_t& now_out){
  now_out = millis();
  portENTER_CRITICAL(&g_mux);
  sn.nb = 0;
  for (int i = 0; i < BSS_MAX && sn.nb < SESSION_CSV_BSS_CAP; i++) if (g_bss[i].used){
    SessBss* r = &sn.bss[sn.nb++];
    const BSS* b = &g_bss[i];
    memcpy(r->mac, b->mac, 6);
    r->ssid_idx = b->ssid_idx; r->sec = b->sec; r->ch = b->ch;
    r->rssi = b->rssi; r->rmin = b->rmin; r->rmax = b->rmax;
    r->has_rssi = (b->rsum_n > 0) ? 1 : 0;
    r->ravg = (b->rsum_n > 0) ? (int16_t)(b->rsum / (int64_t)b->rsum_n) : 0;
    r->frames = b->frames; r->first_ms = b->first_ms; r->last_ms = b->last_ms;
    r->beacon_int = b->beacon_int;
  }
  for (int i = 0; i < SSID_MAX; i++) sn.ssid[i] = g_ssid[i];
  sn.nev = (int)g_ev_fill;
  for (int i = 0; i < (int)g_ev_fill; i++){
    uint32_t idx = (g_ev_head + EVENT_RING_SIZE - 1 - i) % EVENT_RING_SIZE; // newest first
    sn.ev[i] = g_ev_ring[idx];
  }
  sn.have_base = g_have_baseline;
  sn.dwell_s = g_sw_dwell_s;
  for (int i = 0; i < 13; i++){
    sn.ch[i].frames = g_sweep_ch[i].frames;
    sn.ch[i].ctrl = g_sweep_ch[i].ctrl;
    sn.ch[i].active_ms = g_sweep_ch[i].active_ms;
    sn.ch[i].bss_n = g_sweep_ch[i].bss_n;
  }
  portEXIT_CRITICAL(&g_mux);
}
static void sess_build_meta(String& s, uint8_t id, uint32_t dur_s, uint32_t frames, uint32_t closed_ms){
  s += "{\"meta\":{\"id\":"; s += (int)id;
  s += ",\"fw\":\""; s += FW_VERSION; s += "\"";
  s += ",\"start_uptime_ms\":"; s += (unsigned)g_sess_start_ms;
  s += ",\"dur_s\":"; s += (unsigned)dur_s;
  s += ",\"frames\":"; s += (unsigned)frames;
  s += ",\"home_ch\":"; s += (int)g_home_ch;
  s += ",\"ap_ssid\":\""; s += AP_SSID; s += "\"";
  s += ",\"chip_mac\":\""; s += g_ap_mac_str; s += "\"";
  s += ",\"heap\":"; s += (unsigned)ESP.getFreeHeap();
  s += ",\"events_n\":"; s += (int)g_ev_fill;
  s += ",\"closed_uptime_ms\":"; s += (unsigned)closed_ms;
  s += "}";
}
static void sess_build_json(String& s, uint8_t id, uint32_t dur_s, uint32_t frames,
                            uint32_t closed_ms, const SessSnap& sn, int rows){
  s.reserve(6144);
  sess_build_meta(s, id, dur_s, frames, closed_ms);
  // channels[13]: last completed sweep when a baseline exists, else live
  // counters derived from g_bss (per-channel BSSID count + summed per-BSS
  // frames; activity_pct stays 0 - occupancy is sweep-only data).
  s += ",\"channels\":[";
  for (int ch = 1; ch <= 13; ch++){
    if (ch > 1) s += ",";
    uint32_t fr = 0; uint8_t bssn = 0; uint8_t act = 0;
    if (sn.have_base){
      const SessCh* c = &sn.ch[ch-1];
      fr = c->frames; bssn = c->bss_n;
      uint32_t dwell_ms = (uint32_t)sn.dwell_s * 1000;
      uint32_t a = dwell_ms ? (c->active_ms * 100ULL / dwell_ms) : 0;
      act = (a > 100) ? 100 : (uint8_t)a;
    } else {
      for (int i = 0; i < rows; i++){
        if (sn.bss[i].ch == (uint8_t)ch){ bssn++; fr += sn.bss[i].frames; }
      }
    }
    s += "{\"ch\":"; s += ch;
    s += ",\"frames\":"; s += (unsigned)fr;
    s += ",\"bssids\":"; s += (int)bssn;
    s += ",\"activity_pct\":"; s += (int)act;
    s += "}";
  }
  s += "],\"bss\":[";
  for (int a = 0; a < rows; a++){
    const SessBss* b = &sn.bss[a];
    if (a) s += ",";
    s += "{\"bssid\":\""; appendMac(s, b->mac); s += "\"";
    s += ",\"ssid\":";
    if (b->ssid_idx < 255 && b->ssid_idx < SSID_MAX && sn.ssid[b->ssid_idx].used){
      s += "\""; appendSsid(s, sn.ssid[b->ssid_idx].data, sn.ssid[b->ssid_idx].len); s += "\"";
    } else s += "null";
    s += ",\"sec\":\""; s += sec_name[b->sec <= SEC_UNKNOWN ? b->sec : SEC_UNKNOWN]; s += "\"";
    s += ",\"ch\":"; s += (int)b->ch;
    if (b->has_rssi){
      s += ",\"rssi\":"; s += (int)b->rssi;
      s += ",\"rmin\":"; s += (int)b->rmin;
      s += ",\"rmax\":"; s += (int)b->rmax;
      s += ",\"avg\":"; s += (int)b->ravg;
    } else s += ",\"rssi\":null,\"rmin\":null,\"rmax\":null,\"avg\":null";
    s += ",\"count\":"; s += (unsigned)b->frames;
    s += ",\"first\":"; s += (unsigned)b->first_ms;
    s += ",\"last\":"; s += (unsigned)b->last_ms;
    s += ",\"interval_ms\":"; s += (unsigned)(b->beacon_int * 1024UL / 1000UL);
    s += "}";
  }
  s += "],\"ssids\":[";
  // Current SSID pool; bssid/ch resolved from the first BSS row advertising
  // the SSID (g_ssid itself carries no bssid/channel).
  bool firsts = true;
  for (int i = 0; i < SSID_MAX; i++){
    if (!sn.ssid[i].used) continue;
    if (!firsts) s += ",";
    firsts = false;
    const SessBss* owner = nullptr;
    for (int a = 0; a < rows; a++) if (sn.bss[a].ssid_idx == (uint8_t)i){ owner = &sn.bss[a]; break; }
    s += "{\"ssid\":\""; appendSsid(s, sn.ssid[i].data, sn.ssid[i].len); s += "\",\"bssid\":";
    if (owner){ s += "\""; appendMac(s, owner->mac); s += "\""; } else s += "null";
    s += ",\"ch\":"; s += (int)(owner ? owner->ch : 0);
    s += "}";
  }
  s += "],\"events\":[";
  for (int i = 0; i < sn.nev; i++){          // newest first, same shape as /api/events
    const EvEntry* e = &sn.ev[i];
    if (i) s += ",";
    s += "{\"ts\":"; s += (unsigned)e->ts_s;
    s += ",\"type\":\""; s += ev_type_name(e->type); s += "\"";
    s += ",\"ch\":"; s += (int)(e->ch ? e->ch : 0);
    s += ",\"detail\":\"";
    appendSsid(s, (const uint8_t*)e->detail, (uint8_t)strlen(e->detail));
    s += "\"}";
  }
  s += "]}";
}
// CSV field: always quoted; embedded quotes doubled; control chars replaced
// so the file stays strictly line-per-record.
static void sess_csv_field(String& s, const uint8_t* d, uint8_t len){
  s += '"';
  for (int i = 0; i < (int)len; i++){
    uint8_t c = d[i];
    if (c == '"') s += "\"\"";
    else if (c == '\n' || c == '\r') s += ' ';
    else if (c < 0x20 || c == 0x7F) s += '.';
    else s += (char)c;
  }
  s += '"';
}
static void sess_build_csv(String& s, uint8_t id, uint32_t dur_s, uint32_t frames,
                           uint32_t closed_ms, const SessSnap& sn, int rows){
  s.reserve(4096);
  s += "# session id="; s += (int)id;
  s += " fw="; s += FW_VERSION;
  s += " start_uptime_ms="; s += (unsigned)g_sess_start_ms;
  s += " dur_s="; s += (unsigned)dur_s;
  s += " frames="; s += (unsigned)frames;
  s += " home_ch="; s += (int)g_home_ch;
  s += " ap_ssid="; s += AP_SSID;
  s += " chip_mac="; s += g_ap_mac_str;
  s += " heap="; s += (unsigned)ESP.getFreeHeap();
  s += " closed_uptime_ms="; s += (unsigned)closed_ms;
  s += " events_n="; s += (int)sn.nev;
  s += "\n# columns=bssid,ssid,sec,ch,rssi,rmin,avg,count,first,last,interval_ms\n";
  for (int a = 0; a < rows; a++){
    const SessBss* b = &sn.bss[a];
    char mac[18];
    hexmac(b->mac, mac);
    s += mac; s += ',';
    if (b->ssid_idx < 255 && b->ssid_idx < SSID_MAX && sn.ssid[b->ssid_idx].used)
      sess_csv_field(s, sn.ssid[b->ssid_idx].data, sn.ssid[b->ssid_idx].len);
    else s += "\"\"";
    s += ','; s += sec_name[b->sec <= SEC_UNKNOWN ? b->sec : SEC_UNKNOWN];
    s += ','; s += (int)b->ch;
    if (b->has_rssi){
      s += ','; s += (int)b->rssi;
      s += ','; s += (int)b->rmin;
      s += ','; s += (int)b->ravg;
    } else s += ",,,";
    s += ','; s += (unsigned)b->frames;
    s += ','; s += (unsigned)b->first_ms;
    s += ','; s += (unsigned)b->last_ms;
    s += ','; s += (unsigned)(b->beacon_int * 1024UL / 1000UL);
    s += '\n';
  }
}
// Build both session files, shrinking the bss row count until each fits
// SESSION_FILE_MAX_BYTES (with rows <= 64, events <= 32, ssids <= 32 and a
// fixed 13-channel block the cap is a safety net, not the norm).
static bool sess_write_pair(uint8_t id){
  static SessSnap sn;                       // ~4.8 KB static, same pattern as handle_packets
  uint32_t now;
  sess_snapshot(sn, now);
  uint32_t dur_s = (now >= g_sess_start_ms) ? ((now - g_sess_start_ms) / 1000) : 0;
  uint32_t gt = g_total;                    // 32-bit reads are atomic; wrap-safe delta
  uint32_t frames = (gt >= g_sess_total0) ? (gt - g_sess_total0) : gt;
  int rows = sn.nb;
  String js, cs;
  for (;;){
    js = String(); cs = String();
    sess_build_json(js, id, dur_s, frames, now, sn, rows);
    sess_build_csv(cs, id, dur_s, frames, now, sn, rows);
    if ((int)js.length() <= SESSION_FILE_MAX_BYTES &&
        (int)cs.length() <= SESSION_FILE_MAX_BYTES) break;
    if (rows == 0) break;                   // meta only; write anyway
    rows--;
  }
  char jp[16], cp[16];
  sess_paths(id, jp, cp);
  return sess_write_file(jp, js) && sess_write_file(cp, cs);
}
// Shared entry points (serial console AND HTTP funnel here). One active
// session at a time; starting while active prints 'already recording'.
static bool session_start(void){
  if (g_sess_active){
    Serial.println("[session] already recording");
    return false;
  }
  g_sess_open_id = (uint8_t)(g_sess_last_closed + 1);   // id reserved for this session
  g_sess_start_ms = millis();
  g_sess_total0 = g_total;
  g_sess_last_flush_ms = millis();
  g_sess_active = true;
  Serial.println("[session] recording started");
  return true;
}
// Returns the closed id (>=1), -1 when nothing was recording (no-op message),
// or 0 when the LittleFS persist failed (session stays open for retry).
static int session_stop(void){
  if (!g_sess_active){
    Serial.println("[session] not recording");
    return -1;
  }
  uint8_t id = g_sess_open_id;
  if (!sess_write_pair(id)){
    Serial.println("[session] stop: LittleFS write FAILED (still recording; retry stop)");
    return 0;
  }
  g_sess_active = false;
  g_sess_last_closed = id;
  char ibuf[8];
  snprintf(ibuf, sizeof(ibuf), "%u", (unsigned)id);
  if (!sess_write_file(SESSION_IDX_FILE, String(ibuf)))
    Serial.println("[session] warn: /sess.idx write failed (counter may reset on reboot)");
  // Rotation: on write of sN delete s(N-3) (keep newest SESSION_KEEP closed).
  char jp[16], cp[16];
  sess_paths((uint8_t)(id - SESSION_KEEP), jp, cp);
  LittleFS.remove(jp);
  LittleFS.remove(cp);
  Serial.printf("[session] stopped: id=%u -> %s + %s\n", (unsigned)id, jp, cp);
  return (int)id;
}
// 60 s debounced rewrite of the OPEN session snapshot to the reserved id's
// files (crash-safe-ish; called from loop() only). Silent on success, same
// as the S4 events flush.
static void session_flush_open(void){
  if (!sess_write_pair(g_sess_open_id))
    Serial.println("[session] flush: LittleFS write failed (retry next period)");
}
// Shared list builder (console + HTTP): newest SESSION_KEEP closed sessions.
// id/bytes from the files; closed_uptime_ms recovered from the JSON meta
// (meta is written first, so the leading 512 bytes always contain it).
static void session_list(String& out){
  out = "{\"sessions\":[";
  uint8_t hi = g_sess_last_closed;
  uint8_t lo = (hi >= SESSION_KEEP) ? (uint8_t)(hi - SESSION_KEEP + 1) : (uint8_t)1;
  bool firsts = true;
  for (uint8_t id = lo; id <= hi; id++){
    char jp[16], cp[16];
    sess_paths(id, jp, cp);
    (void)cp;
    if (!LittleFS.exists(jp)) continue;
    File f = LittleFS.open(jp, "r");
    if (!f) continue;
    size_t bytes = f.size();
    char head[513];
    int n = (int)f.read((uint8_t*)head, 512);
    f.close();
    if (n < 0) n = 0;
    head[n] = '\0';
    uint32_t start_ms = 0, dur_s = 0;
    const char* p = strstr(head, "\"start_uptime_ms\":");
    if (p) start_ms = strtoul(p + 18, nullptr, 10);
    p = strstr(head, "\"dur_s\":");
    if (p) dur_s = strtoul(p + 8, nullptr, 10);
    if (!firsts) out += ",";
    firsts = false;
    out += "{\"id\":"; out += (int)id;
    out += ",\"closed_uptime_ms\":"; out += (unsigned)(start_ms + dur_s * 1000UL);
    out += ",\"bytes\":"; out += (unsigned)bytes;
    out += "}";
  }
  out += "]}";
}
static void session_print_state_console(void){
  if (g_sess_active){
    uint32_t dur = (millis() >= g_sess_start_ms) ? ((millis() - g_sess_start_ms) / 1000) : 0;
    uint32_t gt = g_total;
    uint32_t frames = (gt >= g_sess_total0) ? (gt - g_sess_total0) : gt;
    Serial.printf("[session] REC id=%u elapsed=%lus frames=%lu\n",
                  (unsigned)g_sess_open_id, (unsigned long)dur, (unsigned long)frames);
  } else {
    Serial.printf("[session] IDLE (last closed id=%u)\n", (unsigned)g_sess_last_closed);
  }
}

// ----------------------------- serial console ----------------------------
static void start_sweep_console(uint8_t dwell){
  int r = sweep_start(dwell);
  if (r == 0)
    Serial.printf("[console] sweep: started (dwell %u s, home ch %u)\n", (unsigned)dwell, (unsigned)g_home_ch);
  else if (r == 1)
    Serial.printf("[console] sweep: already in progress (ch %u)\n",
                  (unsigned)(g_sw_state == SW_PRIME ? g_home_ch : g_sw_ch));
  else
    Serial.println("[console] sweep: start failed (channel hop error)");
}
static void print_diagnostics();  // fwd decl (defined later, ~L1496)
static void process_command(const String& raw){
  String line = raw;
  line.trim();
  if (!line.length()) return;
  int sp = line.indexOf(' ');
  String cmd = (sp < 0) ? line : line.substring(0, sp);
  String arg = (sp < 0) ? String() : line.substring(sp + 1);
  arg.trim();
  String cmd_l = cmd; cmd_l.toLowerCase();
  if (cmd_l == "sweep"){
    String arg_l = arg; arg_l.toLowerCase();
    if (arg_l == "stop"){
      int r = sweep_stop();
      if (r == 0)      Serial.println("[console] sweep: stopped, returning to home");
      else if (r == 2) Serial.println("[console] sweep: pending start canceled");
      else             Serial.println("[console] sweep: nothing running");
    } else if (arg.length() == 0){
      start_sweep_console(4);
    } else {
      int d = arg.toInt();
      if (d < 2 || d > 10)
        Serial.printf("[console] sweep: dwell must be 2-10 s (got %d)\n", d);
      else
        start_sweep_console((uint8_t)d);
    }
  } else if (cmd_l == "home"){
    int r = cmd_home();
    if (r == 0)  Serial.printf("[console] home: now on ch %u\n", (unsigned)g_channel);
    else if (r == 1) Serial.printf("[console] home: sweep aborted, now on ch %u\n", (unsigned)g_channel);
    else Serial.println("[console] home: channel hop failed");
  } else if (cmd_l == "ch"){
    int n = arg.toInt();
    if (n < 1 || n > 13){
      Serial.println("[console] ch: channel must be 1-13");
    } else {
      g_home_ch = (uint8_t)n;
      nvs_save_home(g_home_ch);
      Serial.printf("[console] home channel set to %d (persisted)\n", n);
    }
  } else if (cmd_l == "diag"){
    print_diagnostics();
  } else if (cmd_l == "events"){
    String arg_l = arg; arg_l.toLowerCase();
    if (arg_l == "clear"){
      events_clear();
      Serial.println("[console] events: ring cleared, /events.json truncated");
    } else if (arg_l.length() == 0){
      events_print_console();
    } else {
      Serial.println("[console] events: usage: events | events clear");
    }
  } else if (cmd_l == "session"){
    String arg_l = arg; arg_l.toLowerCase();
    if (arg_l == "start"){
      session_start();                      // echoes '[session] recording started' / 'already recording'
    } else if (arg_l == "stop"){
      session_stop();                       // persists + closes; no-op message when idle
    } else if (arg_l == "list"){
      String s; session_list(s);
      Serial.printf("[session] %s\n", s.c_str());
    } else if (arg_l.length() == 0){
      session_print_state_console();
    } else {
      Serial.println("[console] session: usage: session | session start | session stop | session list");
    }
  } else {
    Serial.printf("[console] unknown command: \"%s\" - try: sweep [2-10] | sweep stop | home | ch <1-13> | diag | events | events clear | session [start|stop|list]\n",
                  cmd.c_str());
  }
}
static void serial_console(){
  static String line;
  while (Serial.available()){
    int c = Serial.read();
    if (c < 0) continue;
    if (c == '\n'){
      if (line.length()) process_command(line);
      line = String();
    } else if (c == '\r'){
      // CRLF: '\r' is a line-ending half, skipped; '\n' commits.
    } else if (c == 0x7F){
      if (line.length()) line.remove(line.length() - 1);   // DEL backspace
    } else {
      if (line.length() < 63) line += (char)c;
    }
  }
}

// ----------------------------- JSON handlers -----------------------------
void handle_index(){
  if (LittleFS.exists("/index.html")){
    File f = LittleFS.open("/index.html","r");
    if (f){ server.streamFile(f,"text/html"); f.close(); return; }
  }
  server.send(200,"text/html",
    "<!doctype html><meta charset=utf-8><title>ESP32-SNIFFER</title>"
    "<body style='background:#0d1117;color:#c9d1d9;font-family:monospace;padding:24px'>"
    "<h1>ESP32-C3 Sniffer</h1>"
    "<p>The dashboard file <code>/index.html</code> is missing from LittleFS.</p>"
    "<p>Flash it with: <code>pio run -t uploadfs</code></p>"
    "<p>API still available: <a href='/api/stats' style='color:#58a6ff'>/api/stats</a></p></body>");
}
void handle_stats() {
  uint32_t flash = ESP.getFlashChipSize();
  uint32_t lfsfree = (LittleFS.totalBytes() >= LittleFS.usedBytes())
                       ? (LittleFS.totalBytes() - LittleFS.usedBytes()) : 0;

  uint16_t rate;
  uint32_t total, dropped, ring_overwrites;
  uint32_t rate_window_ms;
  uint8_t channel;
  bool promisc;
  uint8_t bss_count = 0;
  uint8_t ssid_count = 0;

  portENTER_CRITICAL(&g_mux);
  rate = g_rate[(g_rate_idx + RATE_SLOTS - 1) % RATE_SLOTS];
  total = g_total;
  dropped = g_dropped;
  ring_overwrites = g_dropped;
  rate_window_ms = g_rate_window_ms;
  channel = g_channel;
  promisc = g_promisc;
  for (int i = 0; i < BSS_MAX; i++) {
    if (g_bss[i].used) bss_count++;
  }
  ssid_count = g_ssid_used;
  portEXIT_CRITICAL(&g_mux);

  String s;
  s.reserve(320);
  s += "{\"fw\":\""; s += FW_VERSION;
  s += "\",\"chip\":\""; s += CHIP_NAME;
  s += "\",\"cpu_mhz\":"; s += (int)ESP.getCpuFreqMHz();
  s += ",\"flash_bytes\":"; s += (unsigned)flash;
  s += ",\"lfs_free\":"; s += (unsigned)lfsfree;
  s += ",\"heap\":"; s += (unsigned)ESP.getFreeHeap();
  s += ",\"uptime_s\":"; s += (millis() / 1000);
  s += ",\"channel\":"; s += (int)channel;
  s += ",\"ap_ssid\":\""; s += AP_SSID; s += "\"";
  s += ",\"ap_mac\":\""; s += g_ap_mac_str; s += "\"";
  s += ",\"ap_ip\":\""; s += g_ap_ip; s += "\"";
  s += ",\"total\":"; s += (unsigned)total;
  s += ",\"dropped\":"; s += (unsigned)dropped;
  s += ",\"ring_overwrites\":"; s += (unsigned)ring_overwrites;
  s += ",\"rate_pps\":"; s += (int)rate;
  s += ",\"rate_window_ms\":"; s += (unsigned)rate_window_ms;
  s += ",\"bss_count\":"; s += (int)bss_count;
  s += ",\"ssid_count\":"; s += (int)ssid_count;
  s += ",\"promisc\":"; s += (promisc ? "true" : "false");
  s += "}";
  server.send(200, "application/json", s);
}
void handle_packets() {
  int n = 80;
  if (server.hasArg("n")) n = server.arg("n").toInt();
  if (n < 1) n = 1;
  if (n > 80) n = 80;

  static RingEntry snap_ring[80];
  static SSIDEntry snap_ssid[SSID_MAX];

  uint32_t head, total;
  portENTER_CRITICAL(&g_mux);
  head = g_ring_head;
  total = g_ring_total;
  uint32_t avail = total < RING_SIZE ? total : RING_SIZE;
  if (n > (int)avail) n = (int)avail;
  for (int i = 0; i < n; i++) {
    uint32_t idx = (head + RING_SIZE - 1 - i) % RING_SIZE;
    snap_ring[i] = g_ring[idx];
  }
  for (int i = 0; i < SSID_MAX; i++) {
    snap_ssid[i] = g_ssid[i];
  }
  portEXIT_CRITICAL(&g_mux);

  String s;
  s.reserve((size_t)n * 150 + 32);
  s += "{\"packets\":[";
  for (int i = 0; i < n; i++) {
    RingEntry e = snap_ring[i];
    if (i) s += ",";
    s += "{\"ts\":"; s += (unsigned)e.ts;
    s += ",\"ch\":"; s += (int)e.ch;
    s += ",\"rssi\":"; s += (int)e.rssi;
    s += ",\"t\":"; s += (int)e.type;
    s += ",\"s\":"; s += (int)e.subtype;
    s += ",\"rate\":"; s += (unsigned)e.rate;
    s += ",\"phy\":"; s += (int)e.phy;
    s += ",\"src\":\""; appendMac(s, e.src); s += "\"";
    s += ",\"bssid\":\""; appendMac(s, e.bssid); s += "\"";
    s += ",\"ssid\":";
    if (e.ssid_idx < 255 && e.ssid_idx < SSID_MAX && snap_ssid[e.ssid_idx].used) {
      int len = snap_ssid[e.ssid_idx].len > SSID_MAXLEN ? SSID_MAXLEN : snap_ssid[e.ssid_idx].len;
      s += "\""; appendSsid(s, snap_ssid[e.ssid_idx].data, (uint8_t)len); s += "\"";
    } else {
      s += "null";
    }
    s += "}";
  }
  s += "]}";
  server.send(200, "application/json", s);
}
void handle_ssids() {
  static BSS snap_bss[BSS_MAX];
  static SSIDEntry snap_ssid[SSID_MAX];

  int idx[BSS_MAX];
  int n = 0;
  portENTER_CRITICAL(&g_mux);
  for (int i = 0; i < BSS_MAX; i++) {
    if (g_bss[i].used) {
      snap_bss[i] = g_bss[i];
      idx[n++] = i;
    }
  }
  for (int i = 0; i < SSID_MAX; i++) {
    snap_ssid[i] = g_ssid[i];
  }
  portEXIT_CRITICAL(&g_mux);

  for (int a = 1; a < n; a++) {
    int key = idx[a];
    int b = a - 1;
    while (b >= 0 && snap_bss[idx[b]].rssi < snap_bss[key].rssi) {
      idx[b + 1] = idx[b];
      b--;
    }
    idx[b + 1] = key;
  }

  String s;
  s.reserve((size_t)n * 150 + 32);
  s += "{\"bss\":[";
  for (int a = 0; a < n; a++) {
    BSS* b = &snap_bss[idx[a]];
    if (a) s += ",";
    s += "{\"bssid\":\""; appendMac(s, b->mac); s += "\",\"ssid\":";
    if (b->ssid_idx < 255 && b->ssid_idx < SSID_MAX && snap_ssid[b->ssid_idx].used) {
      int len = snap_ssid[b->ssid_idx].len > SSID_MAXLEN ? SSID_MAXLEN : snap_ssid[b->ssid_idx].len;
      s += "\""; appendSsid(s, snap_ssid[b->ssid_idx].data, (uint8_t)len); s += "\"";
    } else {
      s += "null";
    }
    s += ",\"sec\":\""; s += sec_name[b->sec <= SEC_UNKNOWN ? b->sec : SEC_UNKNOWN]; s += "\"";
    s += ",\"rssi\":";
    if (b->rsum_n > 0) {
      s += (int)b->rssi; s += ",\"rmin\":"; s += (int)b->rmin; s += ",\"rmax\":"; s += (int)b->rmax;
    } else {
      s += "null,\"rmin\":null,\"rmax\":null";
    }
    s += ",\"rsum\":"; s += (long long)b->rsum;
    s += ",\"rsum_n\":"; s += (unsigned)b->rsum_n;
    s += ",\"count\":"; s += (unsigned)b->frames;
    s += ",\"first\":"; s += (unsigned)b->first_ms;
    s += ",\"last\":"; s += (unsigned)b->last_ms;
    s += ",\"interval_ms\":"; s += (double)b->beacon_int * 1.024;
    s += "}";
  }
  s += "]}";
  server.send(200, "application/json", s);
}
void handle_rssi() {
  String bstr = server.hasArg("bssid") ? server.arg("bssid") : String("");
  uint8_t mac[6] = {0};
  bool ok = parse_mac(bstr, mac);

  if (!ok) {
    String s;
    s.reserve(64);
    s += "{\"bssid\":\"\",\"vals\":[]}";
    server.send(400, "application/json", s);
    return;
  }

  static int8_t snap_hist[RSSI_HIST];
  uint8_t snap_head = 0;
  uint8_t snap_count = 0;
  uint8_t snap_mac[6];
  memcpy(snap_mac, mac, 6);
  bool found = false;

  portENTER_CRITICAL(&g_mux);
  for (int i = 0; i < BSS_MAX; i++) {
    if (g_bss[i].used) {
      bool match = true;
      for (int j = 0; j < 6; j++) {
        if (g_bss[i].mac[j] != mac[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        found = true;
        memcpy(snap_mac, g_bss[i].mac, 6);
        memcpy(snap_hist, g_bss[i].hist, sizeof(snap_hist));
        snap_head = g_bss[i].hist_head;
        snap_count = g_bss[i].hist_count;
        break;
      }
    }
  }
  portEXIT_CRITICAL(&g_mux);

  String s;
  s.reserve(400);
  s += "{\"bssid\":\"";
  appendMac(s, snap_mac);
  s += "\",\"vals\":[";
  if (found) {
    uint8_t start = (snap_head + RSSI_HIST - snap_count) % RSSI_HIST;
    for (int i = 0; i < snap_count; i++) {
      if (i) s += ",";
      s += (int)snap_hist[(start + i) % RSSI_HIST];
    }
  }
  s += "]}";
  server.send(200, "application/json", s);
}
void handle_rate(){
  uint16_t local[RATE_SLOTS]; uint32_t idx;
  portENTER_CRITICAL(&g_mux); memcpy(local,g_rate,sizeof(local)); idx=g_rate_idx; portEXIT_CRITICAL(&g_mux);
  const int W=120;                       // 2 minutes of 1 s buckets
  uint32_t newest = (idx + RATE_SLOTS - 1) % RATE_SLOTS;
  int32_t  start = (int32_t)newest - (W-1);
  String s; s.reserve(W*4+16);
  s += "{\"vals\":[";
  for (int i=0;i<W;i++){
    int32_t k = (start + i) % RATE_SLOTS; if (k<0) k+=RATE_SLOTS;
    if (i) s += ",";
    s += (unsigned)local[k];
  }
  s += "]}";
  server.send(200,"application/json",s);
}
void handle_frames(){
  uint32_t tc[4]; uint32_t sc[4][16];
  portENTER_CRITICAL(&g_mux); memcpy(tc,g_type_cnt,sizeof(tc)); memcpy(sc,g_sub_cnt,sizeof(sc)); portEXIT_CRITICAL(&g_mux);
  String s; s.reserve(512);
  s += "{\"types\":[";
  for (int i=0;i<4;i++){ if (i) s += ","; s += (unsigned)tc[i]; }
  s += "],\"sub\":[";
  for (int i=0;i<4;i++){
    s += "[";
    for (int j=0;j<16;j++){ if (j) s += ","; s += (unsigned)sc[i][j]; }
    s += "]";
    if (i<3) s += ",";
  }
  s += "]}";
  server.send(200,"application/json",s);
}

// ---- events API (S4; additive; existing endpoints unchanged) ----
void handle_events(){
  static EvEntry snap[EVENT_RING_SIZE];
  uint8_t fill = 0;
  uint32_t head = 0;
  portENTER_CRITICAL(&g_mux);
  fill = g_ev_fill;
  head = g_ev_head;
  for (int i = 0; i < (int)fill; i++){
    uint32_t idx = (head + EVENT_RING_SIZE - 1 - i) % EVENT_RING_SIZE; // newest first
    snap[i] = g_ev_ring[idx];
  }
  portEXIT_CRITICAL(&g_mux);
  String s;
  s.reserve((size_t)fill * 110 + 64);
  s += "{\"count\":"; s += (int)fill;
  s += ",\"events\":[";
  for (int i = 0; i < (int)fill; i++){
    const EvEntry* e = &snap[i];
    if (i) s += ",";
    s += "{\"ts\":"; s += (unsigned)e->ts_s;
    s += ",\"type\":"; s += "\""; s += ev_type_name(e->type); s += "\"";
    s += ",\"ch\":"; s += (int)(e->ch ? e->ch : 0);
    s += ",\"detail\":"; s += "\"";
    appendSsid(s, (const uint8_t*)e->detail, (uint8_t)strlen(e->detail));
    s += "\"}";
  }
  s += "]}";
  server.send(200, "application/json", s);
}

// ---- sweep API (additive; existing endpoints unchanged) ----
static bool sweep_is_done(uint8_t st){
  return (st == SW_DONE) || (st == SW_HOME && g_sw_home_action == HA_DONE);
}
static bool sweep_is_sweeping(uint8_t st){
  return (st == SW_PRIME || st == SW_SETTLE || st == SW_DWELL);
}
static uint8_t sweep_active_ch(uint8_t st){
  switch (st){
    case SW_PRIME:  return g_home_ch;
    case SW_SETTLE:
    case SW_DWELL:  return g_sw_ch;
    case SW_HOME:
    case SW_DONE:   return g_home_ch;
    default:        return 0;
  }
}
static void build_sweep_json(String& s){
  static SweepCh snap[13];
  static SSIDEntry snap_ssid[SSID_MAX];
  static uint8_t snap_new_mac[SWEEP_LIST_CAP][6];
  static uint8_t snap_new_ssid[SWEEP_LIST_CAP];
  static uint8_t snap_new_ch[SWEEP_LIST_CAP];
  static uint8_t snap_moved_mac[SWEEP_LIST_CAP][6];
  static uint8_t snap_moved_from[SWEEP_LIST_CAP];
  static uint8_t snap_moved_to[SWEEP_LIST_CAP];

  uint8_t st, ch_now, active, dwell_s, quietest, new_n, moved_n;
  uint32_t start_ms, done_ms, phase_ms;
  portENTER_CRITICAL(&g_mux);
  st = g_sw_state;
  ch_now = g_sw_ch;
  active = sweep_active_ch(st);
  dwell_s = g_sw_dwell_s;
  quietest = g_quietest;
  start_ms = g_sw_start_ms;
  done_ms = g_sw_done_ms;
  phase_ms = g_sw_phase_ms;
  memcpy(snap, g_sweep_ch, sizeof(snap));
  new_n = g_new_n; moved_n = g_moved_n;
  memcpy(snap_new_mac, g_new_mac, sizeof(snap_new_mac));
  memcpy(snap_new_ssid, g_new_ssid, sizeof(snap_new_ssid));
  memcpy(snap_new_ch, g_new_ch, sizeof(snap_new_ch));
  memcpy(snap_moved_mac, g_moved_mac, sizeof(snap_moved_mac));
  memcpy(snap_moved_from, g_moved_from, sizeof(snap_moved_from));
  memcpy(snap_moved_to, g_moved_to, sizeof(snap_moved_to));
  for (int i = 0; i < SSID_MAX; i++) snap_ssid[i] = g_ssid[i];
  portEXIT_CRITICAL(&g_mux);

  uint32_t now = millis();
  uint32_t duration;
  if (sweep_is_done(st))      duration = done_ms;
  else if (sweep_is_sweeping(st)) duration = (now >= start_ms) ? (now - start_ms) : 0;
  else                          duration = 0;

  s += "{\"state\":\"";
  if (sweep_is_sweeping(st)) s += "sweeping";
  else if (sweep_is_done(st)) s += "done";
  else s += "idle";
  s += "\",\"home_channel\":"; s += (int)g_home_ch;
  s += ",\"dwell_s\":"; s += (int)dwell_s;
  s += ",\"active_channel\":"; s += (int)active;
  s += ",\"started_ms\":"; s += (unsigned)((st == SW_IDLE) ? 0 : start_ms);
  s += ",\"duration_ms\":"; s += (unsigned)duration;
  s += ",\"quietest\":"; s += (int)quietest;
  s += ",\"channels\":{";
  for (int ch = 1; ch <= 13; ch++){
    ChMetrics m;
    uint32_t elapsed;
    bool live = (st == SW_DWELL && ch_now == (uint8_t)ch);
    elapsed = live ? ((now >= phase_ms) ? (now - phase_ms) : 0)
                   : ((uint32_t)dwell_s * 1000);
    sweep_channel_metrics(&snap[ch-1], elapsed, &m);
    if (ch > 1) s += ",";
    s += "\""; s += ch; s += "\":{\"frames\":"; s += (unsigned)m.frames;
    s += ",\"rate\":"; s += (unsigned)m.rate;
    s += ",\"bssids\":"; s += (unsigned)m.bssids;
    s += ",\"ssids\":"; s += (unsigned)m.ssids;
    s += ",\"sec_open\":"; s += (unsigned)m.sec_open;
    s += ",\"sec_wpa2\":"; s += (unsigned)m.sec_wpa2;
    s += ",\"sec_wpa3\":"; s += (unsigned)m.sec_wpa3;
    s += ",\"sec_other\":"; s += (unsigned)m.sec_other;
    s += ",\"rssi_max\":";
    if (m.rmax != -127) s += (int)m.rmax; else s += "null";
    s += ",\"rssi_avg\":";
    if (m.rmax != -127) s += (int)m.ravg; else s += "null";
    s += ",\"ctrl_frames\":"; s += (unsigned)m.ctrl;
    s += ",\"activity_pct\":"; s += (unsigned)m.act;
    s += "}";
  }
  s += "},\"new\":[";
  for (int i = 0; i < (int)new_n; i++){
    if (i) s += ",";
    s += "{\"bssid\":\""; appendMac(s, snap_new_mac[i]); s += "\",\"ssid\":";
    uint8_t si = snap_new_ssid[i];
    if (si < 255 && si < SSID_MAX && snap_ssid[si].used){
      int len = snap_ssid[si].len > SSID_MAXLEN ? SSID_MAXLEN : snap_ssid[si].len;
      s += "\""; appendSsid(s, snap_ssid[si].data, (uint8_t)len); s += "\"";
    } else s += "null";
    s += ",\"ch\":"; s += (int)snap_new_ch[i];
    s += "}";
  }
  s += "],\"moved\":[";
  for (int i = 0; i < (int)moved_n; i++){
    if (i) s += ",";
    s += "{\"bssid\":\""; appendMac(s, snap_moved_mac[i]); s += "\"";
    s += ",\"from\":"; s += (int)snap_moved_from[i];
    s += ",\"to\":"; s += (int)snap_moved_to[i];
    s += "}";
  }
  s += "]}";
}
void handle_sweep(){
  String s;
  s.reserve(3000);
  build_sweep_json(s);
  server.send(200, "application/json", s);
}
void handle_sweep_start(){
  uint8_t dwell = 4;
  if (server.hasArg("dwell")){
    int d = server.arg("dwell").toInt();
    if (d < 2 || d > 10){
      server.send(400, "application/json", "{\"error\":\"dwell out of range (2-10)\"}");
      return;
    }
    dwell = (uint8_t)d;
  }
  int r = sweep_start(dwell);
  if (r == 1){
    server.send(409, "application/json", "{\"error\":\"sweep already in progress\"}");
    return;
  }
  if (r == 2){
    server.send(500, "application/json", "{\"error\":\"channel hop failed\"}");
    return;
  }
  String s;
  s.reserve(3000);
  build_sweep_json(s);
  server.send(200, "application/json", s);
}
void handle_sweep_stop(){
  sweep_stop(); // idempotent: 409-free stop of a non-running sweep
  String s;
  s.reserve(3000);
  build_sweep_json(s);
  server.send(200, "application/json", s);
}
void handle_404(){
  server.send(404,"application/json","{\"error\":404,\"message\":\"not found\"}");
}

// ---- session API (S5; additive; existing endpoints unchanged) ----
void handle_session(){
  bool active = g_sess_active;
  uint32_t start_ms = g_sess_start_ms;
  uint32_t t0 = g_sess_total0;
  uint32_t gt = g_total;
  uint32_t frames = (gt >= t0) ? (gt - t0) : gt;
  uint32_t dur_s = active ? ((millis() - start_ms) / 1000) : 0;
  String s; s.reserve(96);
  s += "{\"active\":"; s += (active ? "true" : "false");
  s += ",\"start_ms\":"; s += (unsigned)start_ms;
  s += ",\"dur_s\":"; s += (unsigned)dur_s;
  s += ",\"frames\":"; s += (unsigned)frames;
  s += "}";
  server.send(200, "application/json", s);
}
void handle_session_start(){
  if (!session_start()){                    // serial echo '[session] already recording'
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"already recording\"}");
    return;
  }
  String s; s.reserve(96);
  s += "{\"ok\":true,\"start_ms\":"; s += (unsigned)g_sess_start_ms;
  s += ",\"frames\":0}";
  server.send(200, "application/json", s);
}
void handle_session_stop(){
  int id = session_stop();
  if (id < 0){                              // serial echo '[session] not recording'
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"not recording\"}");
    return;
  }
  if (id == 0){
    server.send(500, "application/json", "{\"ok\":false,\"error\":\"LittleFS write failed\"}");
    return;
  }
  char jp[16], cp[16];
  sess_paths((uint8_t)id, jp, cp);
  String s; s.reserve(160);
  s += "{\"ok\":true,\"id\":"; s += id;
  s += ",\"csv\":\""; s += cp;
  s += "\",\"json\":\""; s += jp; s += "\"}";
  server.send(200, "application/json", s);
}
void handle_session_list(){
  String s;
  session_list(s);
  server.send(200, "application/json", s);
}
void handle_session_export(){
  String fmt = server.hasArg("fmt") ? server.arg("fmt") : String("json");
  fmt.toLowerCase();
  if (fmt != "csv" && fmt != "json"){
    server.send(400, "application/json", "{\"error\":\"fmt must be csv|json\"}");
    return;
  }
  int id = server.hasArg("id") ? server.arg("id").toInt() : (int)g_sess_last_closed;
  if (id < 1 || id > 255){
    server.send(404, "application/json", "{\"error\":\"no such session\"}");
    return;
  }
  char path[16];
  snprintf(path, sizeof(path), "/s%u.%s", (unsigned)id, (fmt == "csv") ? "csv" : "json");
  if (!LittleFS.exists(path)){
    server.send(404, "application/json", "{\"error\":\"session file not found\"}");
    return;
  }
  File f = LittleFS.open(path, "r");
  if (!f){
    server.send(500, "application/json", "{\"error\":\"file open failed\"}");
    return;
  }
  // Streamed from LittleFS with bounded heap: streamFile() sends the headers
  // (incl. our extra Content-Disposition) and then WiFiClient::write(File&)
  // pumps the file in 256-byte chunks - the same proven path handle_index
  // uses for /index.html.
  String disp = "attachment; filename=\"s" + String(id) + "." + fmt + "\"";
  server.sendHeader("Content-Disposition", disp);
  server.sendHeader("Cache-Control", "no-store");
  server.streamFile(f, (fmt == "csv") ? "text/csv" : "application/json");
  f.close();
}

// ----------------------------- BOOT button -------------------------------
static void reset_stats(){
  portENTER_CRITICAL(&g_mux);
  memset(g_ring,0,sizeof(g_ring));
  g_ring_head=0; g_ring_total=0;
  g_total=0; g_dropped=0;
  memset(g_type_cnt,0,sizeof(g_type_cnt));
  memset(g_sub_cnt,0,sizeof(g_sub_cnt));
  memset(g_bss,0,sizeof(g_bss));
  memset(g_ssid,0,sizeof(g_ssid));
  g_ssid_used=0;
  memset(g_rate,0,sizeof(g_rate));
  g_rate_idx=0; g_rate_in_progress=0; g_rate_bucket_start=millis(); g_rate_window_ms=0;
  portEXIT_CRITICAL(&g_mux);
  Serial.println("[sniffer] statistics reset (capture continues)");
}
static void print_diagnostics(){
  uint32_t lfsfree = (LittleFS.totalBytes() >= LittleFS.usedBytes())
                       ? (LittleFS.totalBytes()-LittleFS.usedBytes()) : 0;
  uint16_t rate;
  portENTER_CRITICAL(&g_mux); rate=g_rate[(g_rate_idx + RATE_SLOTS - 1) % RATE_SLOTS]; portEXIT_CRITICAL(&g_mux);
  Serial.printf("[diag] up=%lums total=%lu drops=%lu rate=%dpps bss=%d ssids=%d heap=%lu lfs_free=%lu ch=%d events=%u ssid baseline=%u\n",
    (unsigned long)millis(), (unsigned long)g_total, (unsigned long)g_dropped, (int)rate,
    bss_count(), (int)g_ssid_used, (unsigned long)ESP.getFreeHeap(),
    (unsigned long)lfsfree, (int)g_channel, (unsigned)g_ev_fill, (unsigned)g_ev_baseline_cnt);
}
static bool     btn_was = false;
static uint32_t btn_press_ms = 0;
static bool     btn_long_done = false;
static void button_check(){
  bool pressed = (digitalRead(BTN_PIN) == LOW);   // INPUT_PULLUP -> LOW = pressed
  uint32_t now = millis();
  if (pressed && !btn_was){ btn_press_ms=now; btn_long_done=false; }
  if (pressed && !btn_long_done && (now - btn_press_ms) >= 4000){ reset_stats(); btn_long_done=true; }
  if (!pressed && btn_was){
    uint32_t dur = now - btn_press_ms;
    if (!btn_long_done && dur >= 80) print_diagnostics();
  }
  btn_was = pressed;
}

// ----------------------------- banner / setup / loop ---------------------
static void banner(){
  uint32_t flash = ESP.getFlashChipSize();
  uint32_t lfsfree = (LittleFS.totalBytes() >= LittleFS.usedBytes())
                       ? (LittleFS.totalBytes()-LittleFS.usedBytes()) : 0;
  Serial.println();
  Serial.println("================ ESP32-C3 SNIFFER ================");
  Serial.printf("fw=%s chip=%s cpu=%dMHz\n", FW_VERSION, CHIP_NAME, (int)ESP.getCpuFreqMHz());
  Serial.printf("flash=%u bytes (%.1f MB)%s\n", (unsigned)flash, (float)flash/1048576.0f,
                 (flash==4194304)?"":"   [WARN: expected 4 MB flash]");
  Serial.printf("lfs_free=%u B heap=%u B\n", (unsigned)lfsfree, (unsigned)ESP.getFreeHeap());
  if (!LittleFS.exists("/index.html"))
    Serial.println("warn: /index.html missing in LittleFS - run 'pio run -t uploadfs'");
  Serial.printf("AP ssid=%s channel=%d ip=%s mac=%s\n", AP_SSID, (int)g_channel,
                 g_ap_ip.c_str(), g_ap_mac_str);
  Serial.printf("home channel=%u (NVS-persisted)\n", (unsigned)g_home_ch);
  Serial.printf("events ready (loaded=%u)\n", (unsigned)g_ev_loaded_boot);
  Serial.printf("sessions: last closed id=%u (/sess.idx) - newest %u kept\n",
                 (unsigned)g_sess_last_closed, (unsigned)SESSION_KEEP);
  Serial.println("console commands: sweep [2-10] | sweep stop | home | ch <1-13> | diag | events | events clear | session [start|stop|list]");
}
void setup(){
  Serial.begin(MONITOR_BAUD);
  delay(200);

  pinMode(BTN_PIN, INPUT_PULLUP);

  nvs_load_home();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, nullptr, g_home_ch, false, 4);
  delay(50);
  g_ap_ip = WiFi.softAPIP().toString();
  String apmacstr = WiFi.softAPmacAddress();   // returns "AA:BB:CC:DD:EE:FF" (String)
  parse_mac(apmacstr, g_ap_mac);
  hexmac(g_ap_mac, g_ap_mac_str);
  g_channel = g_home_ch;

  if (!LittleFS.begin(false, "/littlefs", 10, "lfs")) {
    Serial.println("[sniffer] LittleFS mount failed; not formatted; API/fallback available");
  }

  g_ev_loaded_boot = events_load();   // S4: load persisted events (missing/corrupt -> empty)

  g_sess_last_closed = sess_read_idx();  // S5: session id counter (LittleFS /sess.idx)

  server.on("/", HTTP_GET, handle_index);
  server.on("/api/stats", HTTP_GET, handle_stats);
  server.on("/api/packets", HTTP_GET, handle_packets);
  server.on("/api/ssids", HTTP_GET, handle_ssids);
  server.on("/api/rssi", HTTP_GET, handle_rssi);
  server.on("/api/rate", HTTP_GET, handle_rate);
  server.on("/api/frames", HTTP_GET, handle_frames);
  server.on("/api/events", HTTP_GET, handle_events);
  server.on("/api/sweep", HTTP_GET, handle_sweep);
  server.on("/api/sweep/start", HTTP_GET, handle_sweep_start);
  server.on("/api/sweep/stop", HTTP_GET, handle_sweep_stop);
  server.on("/api/session", HTTP_GET, handle_session);
  server.on("/api/session/start", HTTP_GET, handle_session_start);
  server.on("/api/session/stop", HTTP_GET, handle_session_stop);
  server.on("/api/session/list", HTTP_GET, handle_session_list);
  server.on("/api/session/export", HTTP_GET, handle_session_export);
  server.onNotFound(handle_404);
  server.begin();

  wifi_promiscuous_filter_t pfilter;
  pfilter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
  esp_err_t e1 = esp_wifi_set_promiscuous_filter(&pfilter);
  esp_err_t e2 = esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
  esp_err_t e3 = esp_wifi_set_promiscuous(true);
  g_promisc = (e1==ESP_OK && e2==ESP_OK && e3==ESP_OK);

  g_rate_bucket_start = millis();

  banner();
  Serial.printf("capture=promiscuous channel=%d filter=ALL enabled=%s (e1=%d e2=%d e3=%d)\n",
                 (int)g_channel, g_promisc?"yes":"no", (int)e1, (int)e2, (int)e3);
}
void loop(){
  server.handleClient();
  button_check();
  serial_console();
  sweep_tick();
  uint32_t now = millis();
  uint32_t elapsed = now - g_rate_bucket_start;
  if (elapsed >= 1000){
    portENTER_CRITICAL(&g_mux);
    uint64_t pps = (uint64_t)g_rate_in_progress * 1000ULL / elapsed;
    if (pps > 65535) pps = 65535;
    g_rate[g_rate_idx] = (uint16_t)pps;
    g_rate_window_ms = elapsed;
    // S4: snapshot the trailing baseline (the EVENT_SPIKE_BASE_S buckets
    // before the one just committed) for the RATE_SPIKE check.
    static uint16_t ev_base[EVENT_SPIKE_BASE_S];
    uint32_t ev_bn = 0;
    for (int i = 0; i < EVENT_SPIKE_BASE_S && i + 1 < (int)g_rate_idx; i++){
      ev_base[ev_bn++] = g_rate[g_rate_idx - 1 - i];
    }
    g_rate_idx = (g_rate_idx + 1) % RATE_SLOTS;
    g_rate_in_progress = 0;
    g_rate_bucket_start = now;
    portEXIT_CRITICAL(&g_mux);
    ev_rate_check((uint16_t)pps, ev_base, ev_bn);
  }
  // S4: debounced write-through of the event ring to LittleFS.
  if (g_ev_pending && (millis() - g_ev_last_flush_ms) >= EVENT_FLUSH_DEBOUNCE_MS){
    portENTER_CRITICAL(&g_mux); g_ev_pending = 0; portEXIT_CRITICAL(&g_mux);
    events_flush();
    g_ev_last_flush_ms = millis();
  }
  // S5: debounced crash-safe rewrite of the OPEN session snapshot (loop-side
  // LittleFS writes only; same gate pattern as the events flush above).
  if (g_sess_active && (millis() - g_sess_last_flush_ms) >= SESSION_FLUSH_DEBOUNCE_MS){
    g_sess_last_flush_ms = millis();
    session_flush_open();
  }
  delay(2);
}
