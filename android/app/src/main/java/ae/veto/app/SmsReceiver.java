package ae.veto.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;

/**
 * Incoming SMS, checked directly when the user has switched on "Check SMS directly". A hidden or late notification
 * then cannot hide a scam text. The same checks as for a message notification; the text stays on the phone.
 */
public class SmsReceiver extends BroadcastReceiver {
  @Override public void onReceive(Context c, Intent i) {
    if (!Store.get(c).smsDirect()) return;
    SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
    if (msgs == null || msgs.length == 0) return;
    StringBuilder body = new StringBuilder();
    for (SmsMessage m : msgs) if (m != null && m.getMessageBody() != null) body.append(m.getMessageBody());
    if (body.length() == 0) return;
    String from = msgs[0] != null && msgs[0].getOriginatingAddress() != null ? msgs[0].getOriginatingAddress() : "";
    Veto.get(c).onMessage("SMS", "sms", from, body.toString());
  }
}
