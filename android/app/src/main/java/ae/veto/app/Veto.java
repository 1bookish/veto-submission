package ae.veto.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.telecom.Connection;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The brain on the phone. Gathers what the phone KNOWS (contacts, chat history counts, call state,
 * which app is open) and asks the engine whether it CONTRADICTS what a message or caller CLAIMS.
 * Kiki appears only when there is something to do. Everything stays in memory on this phone.
 */
final class Veto {
  private static Veto I;

  static synchronized Veto get(Context c) {
    if (I == null) I = new Veto(c.getApplicationContext());
    return I;
  }

  final Context app;
  final Engine engine;
  final Overlay overlay;
  final Store store;
  final Handler main = new Handler(Looper.getMainLooper());
  private final ExecutorService bg = Executors.newSingleThreadExecutor();

  // call state, memory only
  private String callNumber;
  private boolean callUnknown, inCall, ringing, answered;
  private long ringStart, lastUnknownEnd;
  private String lastUnknownNumber;
  private final HashMap<String, Boolean> warnedThisCall = new HashMap<>();
  // chats Veto flagged: package -> {untilMillis, reason}
  private final HashMap<String, Object[]> hot = new HashMap<>();
  private long lastNudge;
  // "Before you pay": the last red warning, so opening a bank / wallet app soon after it brings Kiki back
  static final long PAY_WINDOW = 20 * 60 * 1000L;
  private long lastStopAt;
  private String lastStopSource, lastStopWhat, lastStopSender;
  private final HashSet<String> payWarned = new HashSet<>();
  private final HashMap<String, Long> dedupe = new HashMap<>();
  private boolean started;

  private Veto(Context app) {
    this.app = app;
    store = Store.get(app);
    engine = new Engine(app);
    overlay = new Overlay(app);
  }

  /** Idempotent: hooks call-state and new-app signals once the permissions exist. */
  void start() {
    Watchers.registerCallState(this);
    if (!started) { started = true; Watchers.registerPackages(this); }
  }

  boolean inUnknownCall() { return inCall && callUnknown; }

  boolean needsWatching() {
    if (inCall && callUnknown) return true;
    long now = System.currentTimeMillis();
    if (lastStopAt > 0 && now - lastStopAt < PAY_WINDOW) return true;
    for (Object[] h : hot.values()) if ((Long) h[0] > now) return true;
    return false;
  }

  private static void put(JSONObject o, String k, Object v) { try { o.put(k, v); } catch (JSONException ignored) { /* never */ } }

  // ================================================================ messages
  /**
   * @param appName  "WhatsApp", "SMS", "Telegram" …
   * @param title    what the notification shows as sender: a saved name, a number, or an SMS sender ID
   */
  void onMessage(final String appName, final String pkg, final String title, final String text) {
    if (store.paused() || text == null || text.trim().isEmpty() || title == null) return;
    long now = System.currentTimeMillis();
    String dk = pkg + "|" + title + "|" + text;
    Long t0 = dedupe.get(dk);
    if (t0 != null && now - t0 < 6 * 3600 * 1000L) return; // apps re-post old unread notifications: warn once per message
    if (dedupe.size() > 300) dedupe.clear();
    dedupe.put(dk, now);

    final boolean isNumber = Text.looksLikeNumber(title);
    final String number = isNumber ? title : Contacts.numberFor(app, title);
    String saved = isNumber ? Contacts.nameFor(app, title) : (number != null ? title : null);
    final boolean trusted = store.trusted(number != null ? number : title);
    final boolean inContacts = saved != null || trusted;
    final long[] seen = store.seen(number != null ? number : title);

    JSONObject ctx = new JSONObject();
    put(ctx, "sender", number != null ? number : title);
    put(ctx, "app", appName);
    if (isNumber || saved != null) put(ctx, "inContacts", inContacts);  // SMS sender IDs ("ADCB") are neither
    if (saved != null) put(ctx, "savedName", saved);
    put(ctx, "firstContact", seen[0] == 0 && !inContacts);
    put(ctx, "priorMessages", trusted ? Math.max(seen[0], 50) : seen[0]);
    put(ctx, "contactAgeDays", (now - seen[1]) / 86400000L);
    if (isNumber && !inContacts && ("WhatsApp".equals(appName) || "Telegram".equals(appName))) put(ctx, "verifiedSender", false);
    put(ctx, "savedContacts", Contacts.family(app));
    if (inCall && callUnknown) {
      JSONObject oc = new JSONObject();
      put(oc, "number", callNumber == null ? "" : callNumber);
      put(oc, "inContacts", false);
      put(ctx, "onCall", oc);
    }
    final JSONObject input = new JSONObject();
    put(input, "text", text);
    put(input, "sender", number != null ? number : title);
    put(input, "channel", "SMS".equals(appName) ? "sms" : "chat");
    put(input, "context", ctx);

    engine.triage(text, ctx, new Engine.Cb() {
      public void done(JSONObject tr) {
        // Trusted chat with nothing sensitive: not analysed, Kiki stays hidden.
        if (tr != null && "sleep".equals(tr.optString("mode"))) { Log.i("Veto", "trusted chat, asleep"); return; }
        engine.message(input, true, new Engine.Cb() {
          public void done(JSONObject r) { react(r, appName, pkg, title, number, text, isNumber, inContacts); }
        });
      }
    });
  }

  private static boolean has(JSONArray fs, String prefix) {
    if (fs == null) return false;
    for (int i = 0; i < fs.length(); i++) if (fs.optJSONObject(i) != null && fs.optJSONObject(i).optString("id").startsWith(prefix)) return true;
    return false;
  }

  private void react(JSONObject r, String appName, String pkg, String title, String number, String text, boolean isNumber, boolean inContacts) {
    if (r == null) return;
    String v = r.optString("verdict");
    Log.i("Veto", appName + " message -> " + v + " " + r.optDouble("risk"));
    String sender = number != null ? number : title;
    String source = appName + " · " + (isNumber ? Text.mask(title) : title)
        + (inContacts ? "" : Text.t(app, " · not in your contacts", " · ليس في جهات اتصالك"));
    Overlay.Alert a = describe(r, appName, source, sender, text);
    if (a != null) {
      ChatScreen.remember(text, a);
      overlay.card(a);
      overlay.pet(a.level, null, 0);
      overlay.quiet();
      if ("stop".equals(a.level)) {
        Alarm.alert(app, inCall, a.call);
        rememberStop(a.source, a.reasons.isEmpty() ? a.title : a.reasons.get(0), a.sender);

      } else Alarm.vibrate(app);
      markHot(pkg, a.reasons.isEmpty() ? a.title : a.reasons.get(0));
      // the scam's own "call us" numbers: if the user dials one later, the Fake-Number Interceptor stops the call
      JSONArray ph = r.optJSONArray("phones"), cl = r.optJSONArray("claims");
      String inst = cl != null && cl.length() > 0 ? cl.optJSONObject(0).optString("id") : "";
      String instName = cl != null && cl.length() > 0 ? Text.L(app, cl.optJSONObject(0).optJSONObject("name")) : "";
      if (ph != null) for (int i = 0; i < ph.length(); i++)
        store.flag(ph.optString(i), inst, "in a scam " + appName + " message" + (instName.isEmpty() ? "" : " pretending to be " + instName),
            "في رسالة احتيال" + (instName.isEmpty() ? "" : " تنتحل صفة " + instName), cl != null && cl.length() > 0 ? cl.optJSONObject(0) : null);
    } else if ("caution".equals(v)) {
      JSONObject why = r.optJSONObject("reason");
      overlay.pet("caution", why != null ? Text.L(app, why) : Text.L(app, r.optJSONObject("headline")), 14000);
      markHot(pkg, why != null ? Text.L(app, why) : "");
    } else if ("otp".equals(v) && inCall) {
      overlay.pet("caution", Text.t(app, "A code arrived during your call. Never read it out to anyone, not even “the bank”.",
          "وصل رمز أثناء مكالمتك. لا تقرأه لأي أحد، ولا حتى «البنك»."), 15000);
      Alarm.vibrate(app);
    }
  }

  /**
   * Turns an engine report into a warning card, or null when it doesn't deserve one. Red for scam, amber for
   * "high" and for a caution that matches a known scam script or carries a risky link. Used for new-message
   * notifications and for messages highlighted inside an open chat (ChatScreen).
   */
  Overlay.Alert describe(JSONObject r, String appName, String source, String sender, String text) {
    if (r == null) return null;
    String v = r.optString("verdict");
    JSONArray fs = r.optJSONArray("findings");
    JSONObject pb = r.optJSONObject("playbook");
    JSONObject pbL = pb == null ? null : pb.optJSONObject(Text.ar(app) ? "ar" : "en");
    // the riskiest non-official link in the message, if any
    String linkHost = null; double linkRisk = 0;
    JSONArray links = r.optJSONArray("links");
    for (int i = 0; links != null && i < links.length(); i++) {
      JSONObject l = links.optJSONObject(i);
      if (l != null && !l.optBoolean("official") && l.optDouble("risk") > linkRisk) { linkRisk = l.optDouble("risk"); linkHost = l.optString("host"); }
    }
    boolean badLink = linkHost != null && linkRisk >= 0.3;
    boolean caution = "caution".equals(v);
    if (!("scam".equals(v) || "high".equals(v) || (caution && (pbL != null || badLink)))) return null;
    Overlay.Alert a = new Overlay.Alert();
    a.level = "scam".equals(v) ? "stop" : "caution";
    a.title = caution
        ? (badLink && pbL == null
            ? (linkRisk >= 0.6 ? Text.t(app, "Don't open this link", "لا تفتح هذا الرابط") : Text.t(app, "Careful with this link", "انتبه لهذا الرابط"))
            : Text.t(app, "Careful: ", "انتبه: ") + pbL.optString("title"))
        : Text.L(app, r.optJSONObject("headline"));
    a.source = source;
    if (badLink && linkRisk >= 0.6) a.reasons.add(Text.t(app, "Don't open the link (" + linkHost + "). It is not an official website.", "لا تفتح الرابط (" + linkHost + "). إنه ليس موقعاً رسمياً."));
    for (int i = 0; fs != null && i < fs.length() && a.reasons.size() < 3; i++) {
      String s = Text.L(app, fs.optJSONObject(i).optJSONObject("title"));
      if (!s.isEmpty() && !a.reasons.contains(s)) a.reasons.add(s);
    }
    // "people are already doing this" + the one rule this scam breaks
    if (pbL != null && !pbL.optString("common").isEmpty()) a.reasons.add(Text.t(app, "Already happening: ", "يحدث فعلاً: ") + pbL.optString("common"));
    if (caution && pbL != null) a.detail = pbL.optString("tell");
    else if (fs != null && fs.length() > 0) a.detail = Text.L(app, fs.optJSONObject(0).optJSONObject("detail"));
    a.sender = sender;
    a.call = has(fs, "call_context") || has(fs, "fusion");
    a.evidence = evidence(appName, sender == null ? "unknown" : sender, text, a.reasons);
    a.smsReport = clip("Scam report (Veto): " + appName + (sender != null ? " from " + sender : "") + ". " + (a.reasons.isEmpty() ? a.title : a.reasons.get(0)), 300);
    a.familyText = Text.t(app,
        "⚠️ Scam warning from Veto: someone on " + appName + (sender != null ? " (" + Text.mask(sender) + ")" : "") + ", " + (a.reasons.isEmpty() ? a.title : a.reasons.get(0))
            + " If they contact you: don't reply, never share a code, call the institution on its official number.",
        "⚠️ تحذير احتيال من فيتو: شخص على " + appName + (sender != null ? " (" + Text.mask(sender) + ")" : "") + "، " + (a.reasons.isEmpty() ? a.title : a.reasons.get(0))
            + " إذا تواصل معك: لا ترد، لا تشارك أي رمز، واتصل بالجهة على رقمها الرسمي.");
    return a;
  }

  private void markHot(String pkg, String reason) {
    hot.put(pkg, new Object[] { System.currentTimeMillis() + 30 * 60 * 1000L, reason });
    Watchers.watchForeground(this);
  }

  private static String clip(String s, int n) { return s.length() <= n ? s : s.substring(0, n - 1) + "…"; }

  private String evidence(String channel, String from, String text, List<String> reasons) {
    StringBuilder b = new StringBuilder();
    b.append("Veto, scam report\n");
    b.append("Time: ").append(new SimpleDateFormat("d MMM yyyy HH:mm", Locale.UK).format(new Date())).append(" (phone time)\n");
    b.append("Channel: ").append(channel).append('\n');
    b.append("From: ").append(from).append('\n');
    if (text != null && !text.isEmpty()) b.append("Message: «").append(clip(text, 600)).append("»\n");
    b.append("Why Veto flagged it:\n");
    for (String r : reasons) b.append(" - ").append(r).append('\n');
    b.append("(Prepared on the phone by Veto. Nothing was sent automatically.)");
    return b.toString();
  }

  // ================================================================ calls
  /** From CallScreeningService, gets the number BEFORE the phone rings. Never blocks the call. */
  void onIncomingCall(final String number, final int verification) {
    if (store.paused()) return;
    ringing = true; answered = false;
    ringStart = System.currentTimeMillis();
    callNumber = number;
    warnedThisCall.clear();
    final String saved = Contacts.nameFor(app, number);
    callUnknown = saved == null && !store.trusted(number);
    if (!callUnknown) return; // a saved contact: Kiki stays away
    JSONObject o = new JSONObject();
    put(o, "inContacts", false);
    put(o, "reported", store.reported());
    engine.caller(number, o, new Engine.Cb() {
      public void done(JSONObject c) {
        if (c == null) return;
        String verdict = c.optString("verdict");
        JSONArray sig = c.optJSONArray("signals"), pos = c.optJSONArray("positives");
        String first = sig != null && sig.length() > 0 ? Text.L(app, sig.optJSONObject(0)) : "";
        if (verification == Connection.VERIFICATION_STATUS_FAILED)
          first = Text.t(app, "The network could not verify this caller ID. It may be faked. ", "لم تتمكّن الشبكة من التحقق من هوية المتصل، قد تكون مزوّرة. ") + first;
        if ("danger".equals(verdict)) {
          overlay.pet("stop", Text.t(app, "Don't answer. ", "لا ترد. ") + first, 0);
          Alarm.beep(app, false);
        } else if (pos != null && pos.length() > 0 && "official_number".equals(pos.optJSONObject(0).optString("id"))) {
          overlay.pet("advising", Text.L(app, pos.optJSONObject(0)), 20000);
        } else {
          overlay.pet("listening", (first.isEmpty() ? Text.t(app, "Unknown number. ", "رقم مجهول. ") : first + " ")
              + Text.t(app, "I'm watching this call: if a code arrives or you open your bank app, I'll warn you.",
                  "أراقب هذه المكالمة: إذا وصل رمز أو فتحت تطبيق البنك سأنبّهك."), 0);
        }
        if (store.online()) bg.execute(new Runnable() { public void run() { onlineCallerCheck(number); } });
      }
    });
  }

  private void onlineCallerCheck(final String number) {
    try {
      JSONObject j;
      if (!store.ipqsKey().isEmpty()) j = Net.ipqs(store.ipqsKey(), number);
      else if (Net.base(store.server()) != null) { j = Net.number(store.server(), number); j = j.optJSONObject("online") != null ? j.optJSONObject("online") : j; }
      else return;
      final double[] risk = new double[1];
      final List<String> s = Net.phoneSignals(app, j, risk);
      if (s.isEmpty()) return;
      main.post(new Runnable() { public void run() {
        if (!ringing && !inCall) return;
        if (risk[0] >= 0.7) {
          overlay.pet("stop", Text.t(app, "Online check: ", "فحص عبر الإنترنت: ") + s.get(0), 0);
          Alarm.alert(app, inCall, false);
        } else overlay.pet("caution", Text.t(app, "Online check: ", "فحص عبر الإنترنت: ") + s.get(0), 0);
      } });
    } catch (Exception e) {
      Log.w("Veto", "online caller check failed: " + e.getMessage());
    }
  }

  void onCallState(int state) {
    long now = System.currentTimeMillis();
    if (state == TelephonyManager.CALL_STATE_RINGING) {
      if (!ringing) { ringing = true; ringStart = now; answered = false; }
    } else if (state == TelephonyManager.CALL_STATE_OFFHOOK) {
      boolean incoming = ringing;
      ringing = false; inCall = true; answered = incoming;
      if (!incoming) { callUnknown = false; callNumber = null; } // an outgoing call you made
      if (callUnknown) { overlay.quiet(); Watchers.watchForeground(this); }
    } else if (state == TelephonyManager.CALL_STATE_IDLE) {
      if (ringing && !answered && callUnknown && callNumber != null && now - ringStart < 12000) oneRing(callNumber);
      if (callUnknown) { lastUnknownNumber = callNumber; lastUnknownEnd = now; }
      boolean wasUnknown = callUnknown;
      ringing = false; inCall = false; answered = false; callUnknown = false; callNumber = null;
      if (wasUnknown && "listening".equals(overlay.mood())) overlay.pet("listening", null, 1500);
    }
  }

  /** A short ring from a foreign number that stopped before you could answer = "one-ring" bait. */
  private void oneRing(final String number) {
    engine.caller(number, new JSONObject(), new Engine.Cb() {
      public void done(JSONObject c) {
        if (c == null || c.optJSONArray("signals") == null) return;
        JSONArray s = c.optJSONArray("signals");
        for (int i = 0; i < s.length(); i++) {
          String id = s.optJSONObject(i).optString("id");
          if ("one_ring".equals(id) || "foreign".equals(id)) {
            overlay.pet("caution", Text.t(app, "Missed a short call from " + Text.mask(number) + ". Don't call back, ",
                "مكالمة قصيرة فائتة من " + Text.mask(number) + ". لا تعاود الاتصال، ") + Text.L(app, s.optJSONObject(i)), 20000);
            return;
          }
        }
      }
    });
  }

  // ================================================================ device events during an unknown call
  void onForeground(String pkg) {
    if (pkg.equals(app.getPackageName())) return;
    long now = System.currentTimeMillis();
    if (inCall && callUnknown && !warnedThisCall.containsKey(pkg)) {
      String label = Watchers.label(app, pkg);
      boolean remote = Watchers.isRemoteApp(pkg, label);
      boolean bank = !remote && Watchers.isBankApp(app, pkg, label);
      if (bank || remote) { warnedThisCall.put(pkg, true); deviceAlert(label, bank, remote); return; }
    }
    if (lastStopAt > 0 && now - lastStopAt < PAY_WINDOW && !payWarned.contains(pkg)) {
      String label = Watchers.label(app, pkg);
      if (Watchers.isBankApp(app, pkg, label) || Watchers.isRemoteApp(pkg, label)) { payWarned.add(pkg); beforeYouPay(label); return; }
    }
    Object[] h = hot.get(pkg);
    if (h != null && (Long) h[0] > now && now - lastNudge > 60000) {
      lastNudge = now;
      overlay.pet("caution", Text.t(app, "Careful in this chat: ", "انتبه في هذه المحادثة: ") + h[1], 9000);
    }
  }

  void deviceAlert(final String appLabel, boolean bank, final boolean remote) {
    JSONObject ctx = new JSONObject(), oc = new JSONObject();
    put(oc, "number", callNumber == null ? "" : callNumber);
    put(oc, "inContacts", false);
    put(ctx, "onCall", oc);
    put(ctx, "bankAppOpen", bank);
    put(ctx, "screenSharing", remote);
    engine.device(ctx, new Engine.Cb() {
      public void done(JSONObject r) {
        if (r == null) return;
        Overlay.Alert a = new Overlay.Alert();
        a.level = "stop";
        a.call = true;
        a.title = remote ? Text.t(app, "“" + appLabel + "” is open during a call with an unknown number", "«" + appLabel + "» مفتوح أثناء مكالمة مع رقم مجهول")
            : Text.t(app, "Bank app opened during a call with an unknown number", "فتحت تطبيق البنك أثناء مكالمة مع رقم مجهول");
        a.source = Text.t(app, "Call · ", "مكالمة · ") + Text.mask(callNumber);
        JSONArray fs = r.optJSONArray("findings");
        for (int i = 0; fs != null && i < fs.length() && a.reasons.size() < 2; i++) {
          a.reasons.add(Text.L(app, fs.optJSONObject(i).optJSONObject("title")));
          String d = Text.L(app, fs.optJSONObject(i).optJSONObject("detail"));
          if (!d.isEmpty()) a.reasons.add(d);
        }
        if (remote) a.reasons.add(Text.t(app, "Remote-control apps let the caller watch your screen, your codes and your balance.", "تطبيقات التحكّم عن بُعد تتيح للمتصل رؤية شاشتك ورموزك ورصيدك."));
        a.sender = callNumber;
        a.evidence = evidence("Phone call", callNumber == null ? "unknown" : callNumber, null, a.reasons);
        a.smsReport = clip("Scam call report (Veto): caller " + callNumber + ": " + a.title, 300);
        overlay.card(a);
        overlay.pet("stop", null, 0);
        overlay.quiet();
        Alarm.alert(app, true, true);
      }
    });
  }

  void onPackageAdded(String pkg) {
    long now = System.currentTimeMillis();
    boolean during = (inCall && callUnknown) || (lastUnknownNumber != null && now - lastUnknownEnd < 15 * 60 * 1000L);
    if (!during || store.paused()) return;
    String label = Watchers.label(app, pkg);
    boolean remote = Watchers.isRemoteApp(pkg, label);
    String who = inCall && callUnknown ? callNumber : lastUnknownNumber;
    Overlay.Alert a = new Overlay.Alert();
    a.level = remote ? "stop" : "caution";
    a.call = true;
    a.title = remote ? Text.t(app, "You just installed “" + label + "”, a remote-control app", "ثبّتّ للتو «" + label + "»، تطبيق تحكّم عن بُعد")
        : Text.t(app, "A new app (“" + label + "”) was installed around a call with an unknown number", "تم تثبيت تطبيق جديد («" + label + "») خلال مكالمة مع رقم مجهول");
    a.source = Text.t(app, "Caller · ", "المتصل · ") + Text.mask(who);
    a.reasons.add(remote ? Text.t(app, "Scammers ask you to install it so they can watch your screen and your bank codes. Uninstall it and hang up.",
        "يطلب المحتالون تثبيته ليشاهدوا شاشتك ورموز البنك. احذفه وأنهِ المكالمة.")
        : Text.t(app, "Scammers talk people into installing apps while they stay on the line. Don't open it until you've checked it.",
            "يقنع المحتالون الضحايا بتثبيت تطبيقات وهم على الخط. لا تفتحه قبل التحقق منه."));
    a.sender = who;
    a.evidence = evidence("Phone call + app install", who == null ? "unknown" : who, "Installed: " + label + " (" + pkg + ")", a.reasons);
    a.smsReport = clip("Scam call report (Veto): caller " + who + " made me install " + label, 300);
    overlay.card(a);
    overlay.pet(a.level, null, 0);
    overlay.quiet();
    if (remote) Alarm.alert(app, inCall, inCall);
  }

  // ================================================================ "Before you pay"
  /** Remembers a red (stop) warning; a bank/wallet app opened within PAY_WINDOW brings Kiki back. */
  void rememberStop(String source, String what, String sender) {
    lastStopAt = System.currentTimeMillis();
    lastStopSource = source;
    lastStopWhat = what;
    lastStopSender = sender;
    payWarned.clear();
    Watchers.watchForeground(this);
  }

  /**
   * Many victims tap "Got it" on the first warning and then go and pay anyway, often coached by the
   * scammer. The moment they open a bank or wallet app is the last chance before money leaves, so Kiki
   * comes back once, says who asked and why, and offers the official-number check. Nothing is blocked.
   */
  void beforeYouPay(String appLabel) {
    if (store.paused() || lastStopAt == 0) return;
    long mins = Math.max(1, (System.currentTimeMillis() - lastStopAt) / 60000L);
    Overlay.Alert a = new Overlay.Alert();
    a.level = "caution";
    a.title = Text.t(app, "Before you pay: Veto warned you " + mins + " min ago", "قبل أن تدفع: حذّرك فيتو قبل " + mins + " دقيقة");
    a.source = Text.t(app, "You opened “" + appLabel + "”", "فتحت «" + appLabel + "»") + (lastStopSource != null ? " · " + lastStopSource : "");
    if (lastStopWhat != null && !lastStopWhat.isEmpty()) a.reasons.add(lastStopWhat);
    a.reasons.add(Text.t(app, "If you are about to send money or a code because of that message, stop. Call the bank or the person back on a number you already had.",
        "إذا كنت ستُرسل مالاً أو رمزاً بسبب تلك الرسالة فتوقّف. اتصل بالبنك أو بالشخص على رقم كان لديك من قبل."));
    a.reasons.add(Text.t(app, "A real bank, police officer or relative can wait ten minutes. Scammers can't.",
        "البنك أو الشرطة أو القريب الحقيقي يستطيع الانتظار عشر دقائق. المحتال لا يستطيع."));
    a.sender = lastStopSender;
    a.evidence = evidence("Bank app opened after a scam warning", lastStopSender == null ? "unknown" : lastStopSender, null, a.reasons);
    a.smsReport = clip("Scam report (Veto): " + (lastStopSource != null ? lastStopSource : "") + ". " + (lastStopWhat != null ? lastStopWhat : ""), 300);
    overlay.card(a);
    overlay.pet("caution", null, 0);
    overlay.quiet();
    Alarm.vibrate(app);
  }

  // ================================================================ fallback when "Display over other apps" is off
  static void notifyFallback(Context c, String title, String text) {
    NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
    if (nm == null) return;
    nm.createNotificationChannel(new NotificationChannel("alerts", "Scam warnings", NotificationManager.IMPORTANCE_HIGH));
    Notification n = new Notification.Builder(c, "alerts").setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle("Veto: " + title).setContentText(text).setStyle(new Notification.BigTextStyle().bigText(text)).setAutoCancel(true).build();
    try { nm.notify(7, n); } catch (SecurityException ignored) { /* notifications off */ }
  }
}
