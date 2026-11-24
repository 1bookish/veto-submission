package ae.veto.app;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Link Shield. Set Veto as the default link opener (or pick it once from "Open with"): every link you
 * tap in WhatsApp/SMS comes here FIRST. Veto checks it on the phone (look-alike domains, shorteners,
 * fake brands …) and, if online checks are on, asks the Veto X-ray server to open it in a sealed
 * browser and say what the page WANTS and where it sends your data. Then you decide; safe links continue
 * to your normal browser. Text shared into Veto ("Share → Veto") is checked the same way.
 */
public class LinkShieldActivity extends Activity {
  private static final Pattern URL = Pattern.compile("(?i)\\b((?:https?://|www\\.)[^\\s<>\"']+)");
  private ImageView face;
  private TextView title, verdict, wantsText, sendsText;
  private LinearLayout wants, sends, reasons, actions;
  private String url, shared;

  @Override protected void onCreate(Bundle b) {
    super.onCreate(b);
    Intent in = getIntent();
    if (Intent.ACTION_VIEW.equals(in.getAction()) && in.getData() != null) url = in.getDataString();
    else if (Intent.ACTION_SEND.equals(in.getAction())) {
      shared = in.getStringExtra(Intent.EXTRA_TEXT);
      if (shared != null) { Matcher m = URL.matcher(shared); if (m.find()) url = m.group(1); }
    }
    if (url == null && (shared == null || shared.trim().isEmpty())) { finish(); return; }
    build();
    Veto k = Veto.get(this);
    boolean linkOnly = shared == null || shared.trim().equals(url);
    JSONObject input = new JSONObject();
    try {
      input.put("text", linkOnly ? url : shared);
      input.put("channel", linkOnly ? "link" : "shared");
    } catch (Exception ignored) { /* never */ }
    k.engine.message(input, !linkOnly, new Engine.Cb() { public void done(JSONObject r) { showLocal(r); } });
    if (url != null && k.store.online() && Net.base(k.store.server()) != null) xray(k.store.server());
  }

  private int dp(float v) { return Ui.dp(this, v); }
  private String t(String en, String ar) { return Text.t(this, en, ar); }

  private void build() {
    getWindow().setBackgroundDrawable(new ColorDrawable(0));
    ScrollView sv = new ScrollView(this);
    LinearLayout root = Ui.vertical(this);
    root.setBackground(Ui.round(this, Ui.SURFACE, 26, Ui.LINE));
    root.setPadding(dp(18), dp(16), dp(18), dp(16));
    root.setGravity(Gravity.CENTER_HORIZONTAL);
    if (Text.ar(this)) root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);

    LinearLayout brand = Ui.horizontal(this);
    brand.addView(Ui.iconView(this, R.drawable.ic_shield_check, Ui.NAVY, 16));
    TextView bt = Ui.text(this, t("Veto Link Shield", "درع الروابط من فيتو"), 12.5f, Ui.INK2, true);
    LinearLayout.LayoutParams btl = Ui.lp(Ui.WRAP, Ui.WRAP);
    btl.setMarginStart(dp(6));
    brand.addView(bt, btl);
    root.addView(brand, Ui.lp(Ui.WRAP, Ui.WRAP));

    face = new ImageView(this);
    face.setImageResource(R.drawable.pet_investigating);
    face.setContentDescription("Kiki");
    root.addView(face, Ui.lp(this, dp(104), dp(98), 0, 6, 0, 0));
    title = Ui.text(this, url != null ? t("Checking this link before you open it…", "أفحص الرابط قبل أن تفتحه…")
        : t("Checking this message…", "أفحص هذه الرسالة…"), 17, Ui.INK, true);
    title.setGravity(Gravity.CENTER);
    root.addView(title, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 6, 0, 4));
    if (url != null) {
      TextView u = Ui.text(this, url.length() > 140 ? url.substring(0, 140) + "…" : url, 13, Ui.MUTED, false);
      u.setGravity(Gravity.CENTER);
      u.setTextDirection(View.TEXT_DIRECTION_LTR);
      u.setTypeface(android.graphics.Typeface.MONOSPACE);
      root.addView(u, Ui.lp(Ui.MATCH, Ui.WRAP));
    }
    // verdict: solid badge, white text
    verdict = Ui.badge(this, "", Ui.NAVY);
    verdict.setTextSize(15);
    verdict.setGravity(Gravity.CENTER);
    verdict.setPadding(dp(16), dp(7), dp(16), dp(8));
    verdict.setVisibility(View.GONE);
    root.addView(verdict, Ui.lp(this, Ui.WRAP, Ui.WRAP, 0, 12, 0, 8));

    wants = box("stop", R.drawable.ic_scan_search, t("What this page wants", "ماذا تريد هذه الصفحة"));
    wantsText = (TextView) wants.getChildAt(1);
    wantsText.setTypeface(android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.BOLD));
    root.addView(wants, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 4, 0, 4));
    sends = box("caution", R.drawable.ic_send, t("Where your data goes", "إلى أين تذهب بياناتك"));
    sendsText = (TextView) sends.getChildAt(1);
    root.addView(sends, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 4, 0, 4));

    reasons = Ui.vertical(this);
    root.addView(reasons, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 4, 0, 0));
    actions = Ui.vertical(this);
    root.addView(actions, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 10, 0, 0));
    sv.addView(root);
    setContentView(sv);
    ViewGroup.LayoutParams lp = sv.getLayoutParams();
    if (lp instanceof ViewGroup.MarginLayoutParams) ((ViewGroup.MarginLayoutParams) lp).setMargins(dp(8), dp(8), dp(8), dp(8));
    getWindow().setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    buttons(false, false);
  }

  /** Pale tinted box with a small uppercase heading and a text line (dark text on the tint). */
  private LinearLayout box(String level, int iconRes, String heading) {
    int[] tn = Ui.tint(level);
    LinearLayout b = Ui.vertical(this);
    b.setBackground(Ui.tinted(this, level, 18));
    b.setPadding(dp(14), dp(11), dp(14), dp(12));
    b.addView(Ui.kicker(this, iconRes, heading, tn[2]));
    b.addView(Ui.text(this, "", 14.5f, tn[2], false), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 5, 0, 0));
    b.setVisibility(View.GONE);
    return b;
  }

  private void setVerdict(String text, int color) {
    verdict.setText(text);
    verdict.setBackground(Ui.round(this, color, 999));
    verdict.setVisibility(text == null || text.isEmpty() ? View.GONE : View.VISIBLE);
  }

  private void reason(int iconRes, int iconColor, String s) {
    reasons.addView(Ui.bullet(this, iconRes, iconColor, s, 14.5f, Ui.INK), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 3, 0, 3));
  }

  private void showLocal(JSONObject r) {
    if (r == null || isFinishing()) return;
    String v = r.optString("verdict");
    boolean bad = "scam".equals(v) || "high".equals(v);
    String level = "scam".equals(v) ? "stop" : bad || "caution".equals(v) ? "caution" : "verified";
    face.setImageResource(Overlay.sprite(level));
    setVerdict(Text.L(this, r.optJSONObject("headline")), "scam".equals(v) ? Ui.STOP : "high".equals(v) ? Ui.HIGH : "caution".equals(v) ? Ui.CAUTION : "otp".equals(v) ? Ui.ADVISE : Ui.OK);
    title.setText(url != null ? t("Veto checked this link on your phone", "فحص فيتو الرابط على هاتفك") : t("Veto checked this message", "فحص فيتو هذه الرسالة"));
    reasons.removeAllViews();
    int col = Ui.color(level);
    JSONArray fs = r.optJSONArray("findings");
    for (int i = 0; fs != null && i < fs.length() && i < 4; i++)
      reason("stop".equals(level) ? R.drawable.ic_octagon_alert : R.drawable.ic_triangle_alert, col, Text.L(this, fs.optJSONObject(i).optJSONObject("title")));
    JSONArray links = r.optJSONArray("links");
    if (links != null && links.length() > 0 && links.optJSONObject(0).optBoolean("official"))
      reason(R.drawable.ic_circle_check, Ui.OK, t("Official website of a known organisation.", "موقع رسمي لجهة معروفة."));
    if (url != null && !Veto.get(this).store.online())
      reasons.addView(Ui.bullet(this, R.drawable.ic_info, Ui.MUTED, t("Tip: switch on online checks in Veto to X-ray links in a sealed browser.", "نصيحة: فعّل الفحص عبر الإنترنت في فيتو لفحص الروابط في متصفح معزول."), 12.5f, Ui.MUTED), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 8, 0, 0));
    buttons(bad, "scam".equals(v));
  }

  private void xray(final String server) {
    face.setImageResource(R.drawable.pet_investigating);
    new Thread(new Runnable() {
      public void run() {
        try {
          final JSONObject x = Net.xray(server, url);
          runOnUiThread(new Runnable() { public void run() { showXray(x); } });
        } catch (final Exception e) {
          runOnUiThread(new Runnable() { public void run() {
            if (!isFinishing()) reasons.addView(Ui.bullet(LinkShieldActivity.this, R.drawable.ic_info, Ui.MUTED, t("X-ray server not reachable.", "خادم الأشعة غير متاح."), 12.5f, Ui.MUTED));
          } });
        }
      }
    }).start();
  }

  private void showXray(JSONObject x) {
    if (isFinishing() || x == null || !x.optBoolean("ok")) return;
    String v = x.optString("verdict");
    boolean bad = "dangerous".equals(v) || "suspicious".equals(v);
    String level = "dangerous".equals(v) ? "stop" : bad || "caution".equals(v) ? "caution" : "official".equals(v) ? "verified" : "advising";
    face.setImageResource(Overlay.sprite(level));
    title.setText(t("X-ray: Veto opened it in a sealed browser", "الأشعة: فتحه فيتو في متصفح معزول"));
    JSONObject intent = x.optJSONObject("intent");
    if (intent != null) { wantsText.setText(Text.L(this, intent)); wants.setVisibility(View.VISIBLE); }
    JSONObject to = intent != null ? intent.optJSONObject("sendsTo") : null;
    if (to != null) { sendsText.setText(Text.L(this, to)); sends.setVisibility(View.VISIBLE); }
    if ("dangerous".equals(v)) setVerdict(t("Dangerous page, don't open it", "صفحة خطيرة، لا تفتحها"), Ui.STOP);
    else if ("suspicious".equals(v)) setVerdict(t("Suspicious page", "صفحة مريبة"), Ui.HIGH);
    else if ("official".equals(v)) setVerdict(t("Official website", "موقع رسمي"), Ui.OK);
    JSONArray s = x.optJSONArray("signals");
    reasons.removeAllViews();
    int col = Ui.color(level);
    for (int i = 0; s != null && i < s.length() && i < 4; i++)
      reason("stop".equals(level) ? R.drawable.ic_octagon_alert : R.drawable.ic_triangle_alert, col, Text.L(this, s.optJSONObject(i)));
    buttons(bad, "dangerous".equals(v));
    if ("dangerous".equals(v)) Alarm.vibrate(this);
  }

  private void buttons(boolean bad, boolean danger) {
    actions.removeAllViews();
    List<Button> bs = new ArrayList<>();
    Button no = Ui.pill(this, t("Don't open", "لا تفتحه"), R.drawable.ic_ban, danger ? Ui.Pill.DANGER : Ui.Pill.NAVY);
    no.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { finish(); } });
    bs.add(no);
    if (url != null) {
      final String goLabel = bad ? t("Open anyway", "افتحه رغم ذلك") : t("Open in browser", "افتح في المتصفح");
      final Button go = Ui.pill(this, goLabel, R.drawable.ic_external_link, Ui.Pill.WHITE);
      go.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { openInBrowser(); } });
      bs.add(go);
      if (danger) coolOff(go, goLabel, 5);
    }
    if (bad) {
      Button rep = Ui.pill(this, t("Report (SMS 2828)", "أبلغ (رسالة 2828)"), R.drawable.ic_siren, Ui.Pill.WHITE);
      rep.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
        String body = "Scam report (Veto): " + (url != null ? url : "") + (shared != null && !shared.equals(url) ? ": " + (shared.length() > 200 ? shared.substring(0, 200) : shared) : "");
        try { startActivity(new Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:2828")).putExtra("sms_body", body)); } catch (ActivityNotFoundException ignored) { /* no SMS app */ }
      } });
      bs.add(rep);
    }
    Ui.rows(this, actions, bs);
  }

  /**
   * Cool-off: on a dangerous page, "Open anyway" only works after a few seconds. Scams run on hurry
   * ("in the next 10 minutes or your account is closed"); a short forced pause breaks that rhythm
   * without taking the decision away from the user.
   */
  private void coolOff(final Button b, final String label, final int seconds) {
    b.setEnabled(false);
    b.setAlpha(0.6f);
    final android.os.Handler h = new android.os.Handler(android.os.Looper.getMainLooper());
    h.post(new Runnable() {
      int left = seconds;
      public void run() {
        if (isFinishing() || !b.isAttachedToWindow() && left < seconds) return;
        if (left <= 0) { b.setText(label); b.setEnabled(true); b.setAlpha(1f); return; }
        b.setText(label + " (" + left + ")");
        left--;
        h.postDelayed(this, 1000);
      }
    });
  }

  /** Hands the link to a real browser, explicitly, so it can't loop back into Veto. */
  private void openInBrowser() {
    Intent probe = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"));
    List<ResolveInfo> list = getPackageManager().queryIntentActivities(probe, PackageManager.MATCH_ALL);
    String pick = null;
    for (ResolveInfo ri : list) {
      String p = ri.activityInfo.packageName;
      if (p.equals(getPackageName())) continue;
      if (pick == null || p.equals("com.android.chrome")) pick = p;
    }
    if (pick == null) { Toast.makeText(this, t("No browser found.", "لا يوجد متصفح."), Toast.LENGTH_SHORT).show(); return; }
    Intent go = new Intent(Intent.ACTION_VIEW, Uri.parse(url)).setPackage(pick).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    try { startActivity(go); } catch (ActivityNotFoundException e) { Toast.makeText(this, t("No browser found.", "لا يوجد متصفح."), Toast.LENGTH_SHORT).show(); }
    finish();
  }
}
