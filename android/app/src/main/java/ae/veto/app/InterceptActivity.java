package ae.veto.app;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The screen the Fake-Number Interceptor shows after it held an outgoing call: why the number is suspect, and
 * three ways out: call the institution's REAL number, call anyway (this once), or don't call.
 */
public class InterceptActivity extends Activity {
  private String t(String en, String ar) { return Text.t(this, en, ar); }
  private int dp(float v) { return Ui.dp(this, v); }

  @Override protected void onCreate(Bundle b) {
    super.onCreate(b);
    final String number = getIntent().getStringExtra("number");
    JSONObject r;
    try { r = new JSONObject(getIntent().getStringExtra("result")); } catch (Exception e) { finish(); return; }
    getWindow().setBackgroundDrawable(new ColorDrawable(0));
    ScrollView sv = new ScrollView(this);
    LinearLayout root = Ui.vertical(this);
    root.setBackground(Ui.round(this, Ui.SURFACE, 26, Ui.LINE));
    root.setPadding(dp(18), dp(16), dp(18), dp(16));
    root.setGravity(Gravity.CENTER_HORIZONTAL);
    if (Text.ar(this)) root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);

    ImageView face = new ImageView(this);
    face.setImageResource(Overlay.sprite("stop"));
    root.addView(face, Ui.lp(dp(84), dp(84)));
    root.addView(Ui.text(this, t("Veto held this call", "أوقف فيتو هذه المكالمة"), 20, Ui.INK, true), Ui.lp(this, Ui.WRAP, Ui.WRAP, 0, 6, 0, 2));
    root.addView(Ui.text(this, Text.mask(number), 15, Ui.INK2, false), Ui.lp(this, Ui.WRAP, Ui.WRAP, 0, 0, 0, 10));

    LinearLayout why = Ui.vertical(this);
    why.setBackground(Ui.tinted(this, "stop", 16));
    why.setPadding(dp(14), dp(12), dp(14), dp(12));
    JSONArray rs = r.optJSONArray("reasons");
    int[] tint = Ui.tint("stop");
    if (rs != null) for (int i = 0; i < rs.length(); i++)
      why.addView(Ui.bullet(this, R.drawable.ic_triangle_alert, tint[2], Text.L(this, rs.optJSONObject(i)), 14.5f, tint[2]), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, i == 0 ? 0 : 6, 0, 0));
    root.addView(why, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 14));

    final JSONObject off = r.optJSONObject("official");
    if (off != null) {
      String name = Text.L(this, off.optJSONObject("name"));
      Button real = Ui.pill(this, t("Call " + name + ": " + off.optString("display"), "اتصل بـ" + name + ": " + off.optString("display")), R.drawable.ic_phone_call, Ui.Pill.BRAND);
      real.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { dial(off.optString("number")); } });
      root.addView(real, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 8));
    }
    Button stop = Ui.pill(this, t("Don't call", "لا تتصل"), R.drawable.ic_phone_off, off != null ? Ui.Pill.WHITE : Ui.Pill.NAVY);
    stop.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { finish(); } });
    root.addView(stop, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 8));
    Button anyway = Ui.pill(this, t("Call anyway (this once)", "اتصل على أي حال (هذه المرة)"), R.drawable.ic_phone_forwarded, Ui.Pill.WHITE);
    anyway.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
      Veto.get(InterceptActivity.this).store.allowOnce(number);
      dial(number);
    } });
    root.addView(anyway, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 10));
    root.addView(Ui.text(this, t("Banks, the police and government offices never ask for codes, PINs or transfers on the phone. If someone did, report it to Aman: 800 2626.",
        "البنوك والشرطة والجهات الحكومية لا تطلب رموزاً أو أرقاماً سرية أو تحويلات عبر الهاتف. إذا طلب أحد ذلك، أبلغ أمان: 800 2626."), 12.5f, Ui.INK2, false), Ui.lp(this, Ui.MATCH, Ui.WRAP, 2, 2, 2, 0));
    sv.addView(root);
    LinearLayout pad = Ui.vertical(this);
    pad.setPadding(dp(14), dp(14), dp(14), dp(14));
    pad.addView(sv);
    setContentView(pad);
    // a dialog window is narrow by default: use the phone's full width so the explanation reads in a few lines
    getWindow().setLayout(android.view.ViewGroup.LayoutParams.MATCH_PARENT, android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
  }

  /** Opens the dialer with the number filled in; the person presses call themselves (no CALL_PHONE permission). */
  private void dial(String n) {
    try { startActivity(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + Uri.encode(n))).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); }
    catch (ActivityNotFoundException ignored) { /* no dialer */ }
    finish();
  }
}
