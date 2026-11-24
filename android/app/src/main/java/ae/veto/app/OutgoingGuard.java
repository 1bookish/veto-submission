package ae.veto.app;

import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.telecom.CallRedirectionService;
import android.telecom.PhoneAccountHandle;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Fake-Number Interceptor (Android 10+, the "call redirection" role). Before an OUTGOING call is placed, Veto
 * checks the number on the phone: a number written in a scam message Veto stopped, a number the user reported,
 * or a contact saved under a bank's name that the bank does not publish. Then the call is held and Veto offers
 * the institution's REAL number instead. Every other call goes straight through, and when Veto is unsure or
 * slow (2.5 s) the call goes through too: Veto never stops a call it cannot explain.
 *
 * Two paths: numbers Veto already flagged are recognised instantly from its own memory (works even when the
 * app was not running); everything else (the contact-name check) asks the on-phone engine.
 *
 * Banking trojans (FakeCall, 2022-2025) abuse this same Android hook to send victims who dial their bank to the
 * criminals. Veto uses it the other way round: it sends people who dial the criminals back to their bank.
 */
public class OutgoingGuard extends CallRedirectionService {
  private static final long MAX_HOLD_MS = 2500;
  private final Handler main = new Handler(Looper.getMainLooper());

  @Override
  public void onPlaceCall(Uri handle, PhoneAccountHandle account, final boolean allowInteractiveResponse) {
    final AtomicBoolean answered = new AtomicBoolean(false);
    final String number = handle == null ? "" : String.valueOf(handle.getSchemeSpecificPart());
    final Runnable passThrough = new Runnable() { public void run() { if (answered.compareAndSet(false, true)) placeCallUnmodified(); } };
    final Veto k = Veto.get(this);
    if (number.replaceAll("\\D", "").length() < 7 || k.store.paused() || !k.store.intercept() || k.store.allowedOnce(number)) { passThrough.run(); return; }
    final boolean canShow = allowInteractiveResponse && Settings.canDrawOverlays(this);
    // 1. instant: a number Veto flagged in a scam, or one the user reported
    JSONObject fast = fastCheck(k.store, number);
    if (fast != null) {
      if (canShow) hold(k, number, fast, answered); else passThrough.run();
      return;
    }
    // 2. the engine (contact saved under an institution's name with a number it does not publish)
    main.postDelayed(passThrough, MAX_HOLD_MS);
    k.start();
    JSONObject o = new JSONObject();
    try {
      String saved = Contacts.nameFor(this, number);
      o.put("contactName", saved == null ? "" : saved);
      o.put("flagged", k.store.flagged());
      o.put("reported", k.store.reported());
    } catch (Exception ignored) { /* checks without context */ }
    k.engine.outgoing(number, o, new Engine.Cb() {
      public void done(JSONObject r) {
        boolean stop = r != null && "intercept".equals(r.optString("verdict"));
        if (!stop || !canShow) { passThrough.run(); return; }
        main.removeCallbacks(passThrough);
        hold(k, number, r, answered);
      }
    });
  }

  /** Builds the interceptor's answer straight from Veto's own memory, without waiting for the engine. */
  static JSONObject fastCheck(Store store, String number) {
    String d = Store.digits9(number);
    if (d.length() < 7) return null;
    try {
      JSONArray reasons = new JSONArray();
      JSONObject official = null;
      JSONArray fl = store.flagged();
      for (int i = 0; i < fl.length(); i++) {
        JSONObject f = fl.optJSONObject(i);
        if (f == null || !d.equals(f.optString("number"))) continue;
        reasons.put(new JSONObject().put("en", "Veto flagged this number (" + f.optString("why") + ").").put("ar", "سبق أن نبّه فيتو إلى هذا الرقم (" + f.optString("whyAr") + ")."));
        if (f.optString("offNumber").length() > 0)
          official = new JSONObject().put("number", f.optString("offNumber")).put("display", f.optString("offDisplay"))
              .put("name", new JSONObject().put("en", f.optString("instEn")).put("ar", f.optString("instAr")));
        break;
      }
      JSONArray rep = store.reported();
      for (int i = 0; i < rep.length(); i++) if (d.equals(rep.optString(i))) {
        reasons.put(new JSONObject().put("en", "You reported this number to Veto before.").put("ar", "سبق أن أبلغت فيتو عن هذا الرقم."));
        break;
      }
      if (reasons.length() == 0) return null;
      return new JSONObject().put("verdict", "intercept").put("reasons", reasons).put("official", official == null ? JSONObject.NULL : official);
    } catch (Exception e) { return null; }
  }

  private void hold(Veto k, String number, JSONObject r, AtomicBoolean answered) {
    if (!answered.compareAndSet(false, true)) return; // too late: the call already went through
    Log.i("Veto", "outgoing call held: " + Text.mask(number));
    cancelCall();
    // Kiki appears first: Android lets an app with a VISIBLE overlay window open a screen from the background
    // (it is also the fastest visible feedback), then the full explanation opens a moment later.
    try {
      k.overlay.hideCard(); // an older warning card must not cover this one
      k.overlay.pet("stop", Text.t(this, "Wait: check this number first.", "انتظر: تحقق من هذا الرقم أولاً."), 8000);
    } catch (RuntimeException ignored) { /* no overlay */ }
    final Intent i = new Intent(this, InterceptActivity.class)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP)
        .putExtra("number", number).putExtra("result", r.toString());
    main.postDelayed(new Runnable() { public void run() {
      try { startActivity(i); } catch (RuntimeException e) { Log.w("Veto", "intercept screen", e); }
    } }, 350);
  }
}
