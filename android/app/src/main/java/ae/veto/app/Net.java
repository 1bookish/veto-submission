package ae.veto.app;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The ONLY network code in the app, used only when the user switches "online checks" on:
 *  - Veto server: /api/xray (a link) and /api/number (a phone number)
 *  - IPQualityScore with the user's own key (a phone number)
 * Messages, names and contacts are never sent.
 */
final class Net {
  private Net() {}

  static String base(String server) {
    String s = server == null ? "" : server.trim();
    if (s.isEmpty()) return null;
    if (!s.matches("(?i)^https?://.*")) s = "http://" + s;
    while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
    return s;
  }

  static JSONObject post(String url, JSONObject body, int readTimeoutMs) throws Exception {
    HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
    c.setConnectTimeout(6000);
    c.setReadTimeout(readTimeoutMs);
    c.setRequestMethod("POST");
    c.setDoOutput(true);
    c.setRequestProperty("Content-Type", "application/json");
    try (OutputStream o = c.getOutputStream()) { o.write(body.toString().getBytes(StandardCharsets.UTF_8)); }
    return new JSONObject(read(c));
  }

  static JSONObject get(String url, int readTimeoutMs) throws Exception {
    HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
    c.setConnectTimeout(6000);
    c.setReadTimeout(readTimeoutMs);
    c.setRequestProperty("User-Agent", "Veto-anti-scam/0.2");
    return new JSONObject(read(c));
  }

  private static String read(HttpURLConnection c) throws Exception {
    InputStream in = c.getResponseCode() < 400 ? c.getInputStream() : c.getErrorStream();
    if (in == null) throw new Exception("HTTP " + c.getResponseCode());
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    byte[] buf = new byte[8192];
    int n;
    while ((n = in.read(buf)) > 0) { b.write(buf, 0, n); if (b.size() > 4_000_000) break; }
    in.close();
    return b.toString("UTF-8");
  }

  static JSONObject xray(String server, String link) throws Exception {
    return post(base(server) + "/api/xray", new JSONObject().put("url", link), 60000);
  }

  static JSONObject number(String server, String number) throws Exception {
    return post(base(server) + "/api/number", new JSONObject().put("number", number), 15000);
  }

  static JSONObject ipqs(String key, String number) throws Exception {
    String n = number.replaceAll("[^\\d+]", "");
    return get("https://www.ipqualityscore.com/api/json/phone/" + URLEncoder.encode(key, "UTF-8") + "/" + URLEncoder.encode(n, "UTF-8")
        + "?strictness=1&country%5B%5D=AE", 9000);
  }

  /** Same rules as server/intel.js phoneVerdict(): raw reputation fields -> plain sentences + a risk. */
  static List<String> phoneSignals(Context c, JSONObject j, double[] riskOut) {
    List<String> s = new ArrayList<>();
    double keep = 1;
    int score = j.optInt("fraud_score", j.optInt("fraudScore", 0));
    boolean abuse = j.optBoolean("recent_abuse", j.optBoolean("recentAbuse", false)) || j.optBoolean("spammer", false);
    if (abuse) { s.add(Text.t(c, "Reported recently for scam or spam calls.", "تم الإبلاغ عنه مؤخراً بسبب مكالمات احتيال أو إزعاج.")); keep *= 0.15; }
    else if (score >= 85) { s.add(Text.t(c, "Fraud score " + score + "/100, linked to fraud.", "درجة الاحتيال " + score + "/100، مرتبط بالاحتيال.")); keep *= 0.25; }
    else if (score >= 75) { s.add(Text.t(c, "Fraud score " + score + "/100, suspicious.", "درجة الاحتيال " + score + "/100، مشبوه.")); keep *= 0.55; }
    if (j.optBoolean("VOIP", j.optBoolean("voip", false))) { s.add(Text.t(c, "Internet (VoIP) number, anyone can get one anonymously.", "رقم إنترنت (VoIP)، يمكن لأي شخص الحصول عليه دون هوية.")); keep *= 0.7; }
    String line = j.optString("line_type", j.optString("lineType", ""));
    if (line.toLowerCase().contains("premium")) { s.add(Text.t(c, "Premium-rate number, calling back can cost a lot.", "رقم بتعرفة مرتفعة، معاودة الاتصال مكلفة.")); keep *= 0.3; }
    if (j.has("valid") && !j.optBoolean("valid", true)) { s.add(Text.t(c, "Not a valid number. It may be faked.", "ليس رقماً صالحاً، قد يكون مزوّراً.")); keep *= 0.5; }
    riskOut[0] = 1 - keep;
    return s;
  }
}
