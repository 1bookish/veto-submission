package ae.veto.app;

import android.content.Context;

import org.json.JSONObject;

import java.util.Locale;

/** English / Arabic. Follows the phone's language unless the user picked one in Veto. */
final class Text {
  private Text() {}

  static boolean ar(Context c) {
    String p = Store.get(c).lang();
    if ("ar".equals(p)) return true;
    if ("en".equals(p)) return false;
    return "ar".equals(Locale.getDefault().getLanguage());
  }

  static String t(Context c, String en, String ar) { return ar(c) ? ar : en; }

  /** Picks the right language from an engine object {en, ar}. */
  static String L(Context c, JSONObject o) {
    if (o == null) return "";
    String en = o.optString("en", "");
    return ar(c) ? o.optString("ar", en) : en;
  }

  /** "+92 ••• 4567", enough to recognise, without showing the whole number on screen. */
  static String mask(String number) {
    if (number == null) return "";
    String d = number.replaceAll("[^\\d+]", "");
    if (d.startsWith("00")) d = "+" + d.substring(2);
    if (d.replace("+", "").length() < 6) return number;
    String head = d.startsWith("+") ? d.substring(0, Math.min(4, d.length() - 4)) : d.substring(0, 3);
    return head + " ••• " + d.substring(d.length() - 4);
  }

  static boolean looksLikeNumber(String s) {
    return s != null && s.replaceAll("[\\s()\\-.+]", "").matches("\\d{6,15}") && s.trim().matches("[+\\d][\\d\\s()\\-.]+");
  }
}
