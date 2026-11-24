package ae.veto.app;

import android.Manifest;
import android.app.AppOpsManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Process;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyCallback;
import android.telephony.TelephonyManager;

import java.util.regex.Pattern;

/**
 * Phone-state signals, never call audio (Android forbids it; Veto doesn't need it):
 *  - call state (ringing / on a call / idle),
 *  - which app is in front, polled ONLY while you are on a call with an unknown number or inside a
 *    chat Veto flagged (attention gating: no 24/7 tracking),
 *  - apps installed while an unknown caller is on the line.
 */
final class Watchers {
  private Watchers() {}

  private static boolean callRegistered, pkgRegistered;
  private static Runnable poll;
  private static String lastForeground;

  static final Pattern BANK = Pattern.compile("(?i)(bank|banking|بنك|mashreq|enbd|emirates ?nbd|emirates ?islamic|adcb|\\bfab\\b|adib|\\bdib\\b|rakbank|\\bcbd\\b|hsbc|citibank|standard ?chartered|\\bwio\\b|\\bliv\\b|\\bnbf\\b|al ?hilal|e& ?money|payit|botim ?money|careem ?pay|wallet)");
  static final Pattern REMOTE = Pattern.compile("(?i)(anydesk|teamviewer|quick ?support|rustdesk|airdroid|ultraviewer|supremo|splashtop|zoho ?assist|remote ?desktop|chromeremotedesktop|\\bvnc\\b)");

  static String label(Context c, String pkg) {
    try {
      PackageManager pm = c.getPackageManager();
      return pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
    } catch (Exception e) { return pkg; }
  }

  static boolean isRemoteApp(String pkg, String label) { return REMOTE.matcher(pkg).find() || REMOTE.matcher(label).find(); }

  static boolean isBankApp(Context c, String pkg, String label) {
    return BANK.matcher(label).find() || pkg.toLowerCase().contains("bank");
  }

  // ---------------------------------------------------------------- call state
  static void registerCallState(final Veto k) {
    if (callRegistered) return;
    if (k.app.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) return;
    TelephonyManager tm = (TelephonyManager) k.app.getSystemService(Context.TELEPHONY_SERVICE);
    if (tm == null) return;
    try {
      if (Build.VERSION.SDK_INT >= 31) tm.registerTelephonyCallback(k.app.getMainExecutor(), new CallCb(k));
      else legacyListen(tm, k);
      callRegistered = true;
    } catch (SecurityException ignored) { /* permission revoked */ }
  }

  @SuppressWarnings("deprecation")
  private static void legacyListen(TelephonyManager tm, final Veto k) {
    tm.listen(new PhoneStateListener() {
      @Override public void onCallStateChanged(int state, String number) { k.onCallState(state); }
    }, PhoneStateListener.LISTEN_CALL_STATE);
  }

  static final class CallCb extends TelephonyCallback implements TelephonyCallback.CallStateListener {
    private final Veto k;
    CallCb(Veto k) { this.k = k; }
    @Override public void onCallStateChanged(int state) { k.onCallState(state); }
  }

  // ---------------------------------------------------------------- new apps
  static void registerPackages(final Veto k) {
    if (pkgRegistered) return;
    pkgRegistered = true;
    IntentFilter f = new IntentFilter(Intent.ACTION_PACKAGE_ADDED);
    f.addDataScheme("package");
    BroadcastReceiver r = new BroadcastReceiver() {
      @Override public void onReceive(Context c, Intent i) {
        if (i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return;
        Uri d = i.getData();
        if (d != null) k.onPackageAdded(d.getSchemeSpecificPart());
      }
    };
    if (Build.VERSION.SDK_INT >= 33) k.app.registerReceiver(r, f, Context.RECEIVER_EXPORTED);
    else k.app.registerReceiver(r, f);
  }

  // ---------------------------------------------------------------- app in front (only while needed)
  static boolean usageAllowed(Context c) {
    AppOpsManager ops = (AppOpsManager) c.getSystemService(Context.APP_OPS_SERVICE);
    if (ops == null) return false;
    int mode = ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), c.getPackageName());
    return mode == AppOpsManager.MODE_ALLOWED;
  }

  static void watchForeground(final Veto k) {
    if (poll != null || !usageAllowed(k.app)) return;
    final UsageStatsManager usm = (UsageStatsManager) k.app.getSystemService(Context.USAGE_STATS_SERVICE);
    if (usm == null) return;
    lastForeground = null;
    poll = new Runnable() {
      public void run() {
        if (!k.needsWatching()) { poll = null; return; }
        long now = System.currentTimeMillis();
        String fg = null;
        try {
          UsageEvents ev = usm.queryEvents(now - 6000, now);
          UsageEvents.Event e = new UsageEvents.Event();
          while (ev.hasNextEvent()) {
            ev.getNextEvent(e);
            if (e.getEventType() == UsageEvents.Event.ACTIVITY_RESUMED) fg = e.getPackageName();
          }
        } catch (RuntimeException ignored) { /* not allowed any more */ }
        if (fg != null && !fg.equals(lastForeground)) { lastForeground = fg; k.onForeground(fg); }
        k.main.postDelayed(this, 1200);
      }
    };
    k.main.post(poll);
  }
}
