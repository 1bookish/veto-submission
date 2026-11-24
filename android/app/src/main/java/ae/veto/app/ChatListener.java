package ae.veto.app;

import android.app.Notification;
import android.os.Bundle;
import android.os.Parcelable;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reads NEW message notifications (sender + text, exactly what the notification shows) ONLY from the
 * chat / SMS apps the user switched on in Veto, and hands them to the brain. Every other app's
 * notifications are dropped on arrival without being read. It never opens, replies to, dismisses or
 * forwards anything.
 */
public class ChatListener extends NotificationListenerService {
  /** Chat apps Veto knows how to read (package -> name shown to the user), in display order. */
  static final Map<String, String> APPS = new LinkedHashMap<>();
  static {
    APPS.put("com.whatsapp", "WhatsApp");
    APPS.put("com.whatsapp.w4b", "WhatsApp Business");
    APPS.put("org.telegram.messenger", "Telegram");
    APPS.put("org.telegram.messenger.web", "Telegram");
    APPS.put("com.google.android.apps.messaging", "Messages (SMS)");
    APPS.put("com.samsung.android.messaging", "Samsung Messages (SMS)");
    APPS.put("com.android.mms", "Messages (SMS)");
    APPS.put("com.android.messaging", "Messages (SMS)");
    APPS.put("org.thoughtcrime.securesms", "Signal");
    APPS.put("com.facebook.orca", "Messenger");
    APPS.put("com.instagram.android", "Instagram");
    APPS.put("im.thebot.messenger", "BOTIM");
    APPS.put("com.viber.voip", "Viber");
    APPS.put("com.imo.android.imoim", "imo");
    APPS.put("com.snapchat.android", "Snapchat");
  }

  /** On by default: SMS, WhatsApp and Telegram. Everything else is off until the user switches it on. */
  static boolean defaultOn(String pkg) {
    String n = APPS.get(pkg);
    return n != null && (n.contains("SMS") || n.startsWith("WhatsApp") || n.equals("Telegram"));
  }

  /** The short channel name the engine and the warning card use ("WhatsApp", "SMS", "Telegram" ...). */
  static String channel(String pkg) {
    String n = APPS.get(pkg);
    if (n == null) return "Chat";
    if (n.contains("SMS")) return "SMS";
    if (n.startsWith("WhatsApp")) return "WhatsApp";
    return n;
  }

  static volatile boolean connected;

  @Override public void onListenerConnected() {
    connected = true;
    Veto.get(this).start();
  }

  @Override public void onListenerDisconnected() { connected = false; }

  @Override public void onNotificationPosted(StatusBarNotification sbn) {
    String pkg = sbn.getPackageName();
    Notification n = sbn.getNotification();
    if (n == null) return;
    // only the apps the user switched on; anything else is dropped here, unread
    if (!APPS.containsKey(pkg) || !Store.get(this).reads(pkg)) return;
    if ((n.flags & Notification.FLAG_GROUP_SUMMARY) != 0 || (n.flags & Notification.FLAG_ONGOING_EVENT) != 0) return;
    Bundle x = n.extras;
    if (x == null) return;
    CharSequence title = x.getCharSequence(Notification.EXTRA_TITLE);
    CharSequence text = x.getCharSequence(Notification.EXTRA_BIG_TEXT);
    if (text == null) text = x.getCharSequence(Notification.EXTRA_TEXT);
    // MessagingStyle (WhatsApp, Google Messages): the newest message and who sent it
    Parcelable[] msgs = x.getParcelableArray(Notification.EXTRA_MESSAGES);
    if (msgs != null && msgs.length > 0 && msgs[msgs.length - 1] instanceof Bundle) {
      Bundle last = (Bundle) msgs[msgs.length - 1];
      CharSequence t = last.getCharSequence("text");
      if (t != null) text = t;
      CharSequence s = last.getCharSequence("sender");
      boolean group = x.getBoolean(Notification.EXTRA_IS_GROUP_CONVERSATION, false);
      if (s != null && !group) title = s;
    }
    if (title == null || text == null) return;
    String tt = title.toString().trim(), body = text.toString().trim();
    if (body.matches("(?i)^\\d+ new messages?.*|^checking for new messages.*")) return;
    Veto.get(this).onMessage(channel(pkg), pkg, tt, body);
  }
}
