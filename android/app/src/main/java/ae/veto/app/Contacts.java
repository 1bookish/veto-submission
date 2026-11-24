package ae.veto.app;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.provider.ContactsContract;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.regex.Pattern;

/** Read-only look-ups in the phone's address book. Nothing here ever leaves the phone. */
final class Contacts {
  private Contacts() {}

  private static JSONArray familyCache;
  private static long familyAt;
  private static final Pattern FAMILY = Pattern.compile(
      "(?i)\\b(mum|mom|mama|mummy|mommy|mother|ammi|amma|dad|daddy|papa|baba|father|abba|abbu|son|daughter|bro|brother|sis|sister|wife|husband|hubby)\\b"
      + "|ماما|امي|أمي|بابا|ابي|أبي|ابوي|أبوي|ابني|ولدي|بنتي|ابنتي|اخي|أخي|اخوي|اختي|أختي|زوجتي|زوجي|والدتي|والدي");

  static boolean allowed(Context c) {
    return c.checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED;
  }

  /** Saved name for a phone number, or null. */
  /** Every saved contact as {name, number} (on the phone only), for the "contacts that pretend to be a bank" audit. */
  static org.json.JSONArray all(Context c) {
    org.json.JSONArray out = new org.json.JSONArray();
    if (!allowed(c)) return out;
    try (Cursor cur = c.getContentResolver().query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
        new String[] { ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME, ContactsContract.CommonDataKinds.Phone.NUMBER }, null, null, null)) {
      while (cur != null && cur.moveToNext() && out.length() < 5000) {
        try { out.put(new org.json.JSONObject().put("name", cur.getString(0)).put("number", cur.getString(1))); } catch (org.json.JSONException ignored) { /* skip */ }
      }
    } catch (RuntimeException ignored) { /* provider unavailable */ }
    return out;
  }

  static String nameFor(Context c, String number) {
    if (!allowed(c) || number == null || number.replaceAll("\\D", "").length() < 5) return null;
    Uri u = Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(number));
    try (Cursor cur = c.getContentResolver().query(u, new String[] { ContactsContract.PhoneLookup.DISPLAY_NAME }, null, null, null)) {
      if (cur != null && cur.moveToFirst()) return cur.getString(0);
    } catch (RuntimeException ignored) { /* provider unavailable */ }
    return null;
  }

  /** Number saved under exactly this name (chat apps show the saved NAME for contacts). */
  static String numberFor(Context c, String name) {
    if (!allowed(c) || name == null || name.trim().isEmpty()) return null;
    try (Cursor cur = c.getContentResolver().query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
        new String[] { ContactsContract.CommonDataKinds.Phone.NUMBER },
        ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + "=?", new String[] { name.trim() }, null)) {
      if (cur != null && cur.moveToFirst()) return cur.getString(0);
    } catch (RuntimeException ignored) { /* provider unavailable */ }
    return null;
  }

  /** Family members as saved ("Mum", "Ahmed (son)", "أمي")، used for the "Hi Mum, new number" check. */
  static synchronized JSONArray family(Context c) {
    long now = System.currentTimeMillis();
    if (familyCache != null && now - familyAt < 10 * 60 * 1000) return familyCache;
    JSONArray out = new JSONArray();
    if (allowed(c)) {
      try (Cursor cur = c.getContentResolver().query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
          new String[] { ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME, ContactsContract.CommonDataKinds.Phone.NUMBER }, null, null, null)) {
        while (cur != null && cur.moveToNext() && out.length() < 40) {
          String name = cur.getString(0), num = cur.getString(1);
          if (name != null && num != null && FAMILY.matcher(name).find()) out.put(new JSONObject().put("name", name).put("number", num));
        }
      } catch (Exception ignored) { /* provider unavailable */ }
    }
    familyCache = out;
    familyAt = now;
    return out;
  }
}
