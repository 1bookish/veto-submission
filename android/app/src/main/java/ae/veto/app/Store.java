package ae.veto.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Settings and the on-device trust ledger. The ledger keeps only a message COUNT and a first-seen DATE
 * per sender, under a hashed key, never names, numbers or message text.
 */
final class Store {
  private static Store I;

  static synchronized Store get(Context c) {
    if (I == null) I = new Store(c.getApplicationContext());
    return I;
  }

  private final SharedPreferences p;

  private Store(Context c) { p = c.getSharedPreferences("veto", Context.MODE_PRIVATE); }

  String lang() { return p.getString("lang", "auto"); }
  void lang(String v) { p.edit().putString("lang", v).apply(); }
  boolean paused() { return p.getBoolean("paused", false); }
  void paused(boolean v) { p.edit().putBoolean("paused", v).apply(); }
  /** Online look-ups (caller reputation, link X-ray). OFF by default. */
  boolean online() { return p.getBoolean("online", false); }
  void online(boolean v) { p.edit().putBoolean("online", v).apply(); }
  /** Veto server for the link X-ray and the caller check, e.g. http://192.168.1.20:8787 */
  String server() { return p.getString("server", ""); }
  void server(String v) { p.edit().putString("server", v == null ? "" : v.trim()).apply(); }
  /** Optional IPQualityScore key (the user's own) for caller reputation straight from the phone. */
  String ipqsKey() { return p.getString("ipqs", ""); }
  void ipqsKey(String v) { p.edit().putString("ipqs", v == null ? "" : v.trim()).apply(); }
  /**
   * Which chat apps Veto may read. Only apps the user switched on are read; every other app is ignored.
   * Default: SMS, WhatsApp and Telegram (where most UAE scams arrive); the rest stay off until switched on.
   */
  boolean reads(String pkg) { return p.getBoolean("R:" + pkg, ChatListener.defaultOn(pkg)); }
  void reads(String pkg, boolean on) { p.edit().putBoolean("R:" + pkg, on).apply(); }

  static String digits9(String s) {
    String d = s == null ? "" : s.replaceAll("\\D", "");
    return d.length() > 9 ? d.substring(d.length() - 9) : d;
  }

  static String key(String sender) {
    String s = sender == null ? "" : sender.trim().toLowerCase();
    String d = digits9(s);
    String base = d.length() >= 7 ? d : s;
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] h = md.digest(("veto:" + base).getBytes(StandardCharsets.UTF_8));
      StringBuilder b = new StringBuilder();
      for (int i = 0; i < 8; i++) b.append(String.format("%02x", h[i]));
      return b.toString();
    } catch (Exception e) {
      return Integer.toHexString(base.hashCode());
    }
  }

  /** Returns {messagesBefore, firstSeenMillis} and counts this message. */
  synchronized long[] seen(String sender) {
    String k = "L" + key(sender);
    long n = 0, first = System.currentTimeMillis();
    String v = p.getString(k, null);
    if (v != null) {
      try {
        String[] a = v.split(",");
        n = Long.parseLong(a[0]);
        first = Long.parseLong(a[1]);
      } catch (RuntimeException ignored) { /* reset */ }
    }
    p.edit().putString(k, (n + 1) + "," + first).apply();
    return new long[] { n, first };
  }

  boolean trusted(String sender) { return sender != null && p.getBoolean("T" + key(sender), false); }
  void trust(String sender) { if (sender != null) p.edit().putBoolean("T" + key(sender), true).apply(); }

  /** Numbers the user reported (last 9 digits only), so Veto recognises them next time. */
  JSONArray reported() {
    try { return new JSONArray(p.getString("reported", "[]")); } catch (JSONException e) { return new JSONArray(); }
  }

  /** Numbers that appeared in a message Veto stopped, with the institution it claimed. 14 days, max 60. */
  synchronized JSONArray flagged() {
    JSONArray a, out = new JSONArray();
    try { a = new JSONArray(p.getString("flagged", "[]")); } catch (JSONException e) { a = new JSONArray(); }
    long cut = System.currentTimeMillis() - 14L * 86400000L;
    for (int i = 0; i < a.length(); i++) { org.json.JSONObject o = a.optJSONObject(i); if (o != null && o.optLong("t") > cut) out.put(o); }
    return out;
  }
  synchronized void flag(String number, String inst, String why, String whyAr, org.json.JSONObject claim) {
    String d = digits9(number);
    if (d.length() < 7) return;
    JSONArray a = flagged(), out = new JSONArray();
    for (int i = 0; i < a.length(); i++) if (!d.equals(a.optJSONObject(i).optString("number"))) out.put(a.optJSONObject(i));
    try {
      org.json.JSONObject o = new org.json.JSONObject().put("number", d).put("inst", inst == null ? "" : inst).put("why", why).put("whyAr", whyAr).put("t", System.currentTimeMillis());
      // the institution's real number, so the interceptor can offer it instantly (even before the engine is up)
      org.json.JSONObject ph = claim == null ? null : claim.optJSONObject("phone");
      if (ph != null) o.put("offNumber", ph.optString("n")).put("offDisplay", ph.optString("d"))
          .put("instEn", claim.optJSONObject("name") != null ? claim.optJSONObject("name").optString("en") : "").put("instAr", claim.optJSONObject("name") != null ? claim.optJSONObject("name").optString("ar") : "");
      out.put(o);
    } catch (JSONException ignored) { /* skip */ }
    while (out.length() > 60) out.remove(0);
    p.edit().putString("flagged", out.toString()).apply();
  }
  /** "Call anyway": the next call to this number in the next 2 minutes goes through untouched. */
  void allowOnce(String number) { p.edit().putString("allowOnce", digits9(number) + "," + System.currentTimeMillis()).apply(); }
  boolean allowedOnce(String number) {
    String[] v = p.getString("allowOnce", ",0").split(",");
    boolean ok = v.length == 2 && v[0].equals(digits9(number)) && System.currentTimeMillis() - Long.parseLong(v[1]) < 120000;
    if (ok) p.edit().remove("allowOnce").apply();
    return ok;
  }
  /** The Fake-Number Interceptor can be switched off without removing the role. */
  boolean intercept() { return p.getBoolean("intercept", true); }
  void intercept(boolean v) { p.edit().putBoolean("intercept", v).apply(); }

  synchronized void report(String number) {
    String d = digits9(number);
    if (d.length() < 7) return;
    JSONArray a = reported();
    for (int i = 0; i < a.length(); i++) if (d.equals(a.optString(i))) return;
    a.put(d);
    p.edit().putString("reported", a.toString()).apply();
  }
}
