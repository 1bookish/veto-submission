package ae.veto.app;

import android.net.Uri;
import android.os.Build;
import android.telecom.Call;
import android.telecom.CallScreeningService;

/**
 * Android's "Caller ID & spam" hook: the system shows Veto an incoming number from someone who is
 * NOT in your contacts before the phone rings. Veto never blocks, silences or records the call, 
 * it only decides whether Kiki should appear and watch.
 */
public class CallGuard extends CallScreeningService {
  @Override public void onScreenCall(Call.Details d) {
    respondToCall(d, new CallResponse.Builder().build()); // allow, always
    if (d.getCallDirection() != Call.Details.DIRECTION_INCOMING) return;
    Uri h = d.getHandle();
    String number = h != null ? h.getSchemeSpecificPart() : "";
    int verification = Build.VERSION.SDK_INT >= 30 ? d.getCallerNumberVerificationStatus() : 0;
    Veto k = Veto.get(this);
    k.start();
    k.onIncomingCall(number == null ? "" : number, verification);
  }
}
