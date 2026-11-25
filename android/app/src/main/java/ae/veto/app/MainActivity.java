package ae.veto.app;

import android.Manifest;
import android.app.Activity;
import android.app.role.RoleManager;
import org.json.JSONObject;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/** Setup: one row per permission with the reason in plain words, which chat apps Veto may read, and a few settings. */
public class MainActivity extends Activity {
  private static final int REQ_PERMS = 1, REQ_SCREEN = 2, REQ_BROWSER = 3, REQ_REDIRECT = 4;
  private EditText server, ipqs;

  @Override protected void onCreate(Bundle b) {
    super.onCreate(b);
    Veto.get(this).start();
  }

  @Override protected void onResume() {
    super.onResume();
    Veto.get(this).start();
    build();
  }

  private int dp(float v) { return Ui.dp(this, v); }
  private String t(String en, String ar) { return Text.t(this, en, ar); }

  private boolean granted(String p) { return checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED; }

  private boolean listenerOn() {
    String flat = Settings.Secure.getString(getContentResolver(), "enabled_notification_listeners");
    return flat != null && flat.contains(new ComponentName(this, ChatListener.class).flattenToString());
  }

  private boolean role(String r) {
    RoleManager rm = (RoleManager) getSystemService(ROLE_SERVICE);
    return rm != null && rm.isRoleAvailable(r) && rm.isRoleHeld(r);
  }

  private void build() {
    final Veto k = Veto.get(this);
    lightBars();
    ScrollView sv = new ScrollView(this);
    sv.setBackground(Ui.background(this));
    final LinearLayout root = Ui.vertical(this);
    root.setPadding(dp(16), dp(14), dp(16), dp(28));
    if (Text.ar(this)) root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
    sv.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
      public WindowInsets onApplyWindowInsets(View v, WindowInsets in) {
        v.setPadding(in.getSystemWindowInsetLeft(), in.getSystemWindowInsetTop(), in.getSystemWindowInsetRight(), in.getSystemWindowInsetBottom());
        return in;
      }
    });

    // ---- header: logo + navy wordmark (the pet stays hidden until something needs the user)
    LinearLayout head = Ui.horizontal(this);
    ImageView mark = new ImageView(this);
    mark.setImageResource(R.drawable.veto_mark);
    mark.setClipToOutline(true);
    mark.setBackground(Ui.round(this, Ui.NAVY, 14));
    mark.setElevation(dp(4));
    head.addView(mark, Ui.lp(dp(46), dp(46)));
    LinearLayout ht = Ui.vertical(this);
    ImageView word = new ImageView(this);
    word.setImageResource(R.drawable.veto_wordmark_dark);
    word.setAdjustViewBounds(true);
    word.setScaleType(ImageView.ScaleType.FIT_START);
    word.setContentDescription("Veto.ai");
    ht.addView(word, Ui.lp(Ui.WRAP, dp(21)));
    ht.addView(Ui.text(this, t("Scam guard for chats, calls and links", "حارس من الاحتيال في المحادثات والمكالمات والروابط"), 12.5f, Ui.MUTED, false), Ui.lp(this, Ui.WRAP, Ui.WRAP, 0, 4, 0, 0));
    LinearLayout.LayoutParams htl = new LinearLayout.LayoutParams(0, Ui.WRAP, 1f);
    htl.setMarginStart(dp(12));
    head.addView(ht, htl);
    Button lang = Ui.pill(this, Text.ar(this) ? "EN" : "ع", R.drawable.ic_languages, Ui.Pill.WHITE);
    lang.setContentDescription(Text.ar(this) ? "English" : "العربية");
    lang.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { k.store.lang(Text.ar(MainActivity.this) ? "en" : "ar"); build(); } });
    head.addView(lang, Ui.lp(Ui.WRAP, dp(42)));
    root.addView(head, Ui.lp(Ui.MATCH, Ui.WRAP));
    root.addView(Ui.text(this, t("Kiki checks new chats, calls and links on this phone. It stays hidden and only pops up when something needs you.",
        "يفحص كيكي المحادثات والمكالمات والروابط الجديدة على هذا الهاتف. يبقى مخفياً ولا يظهر إلا عندما يحتاجك أمر."), 13.5f, Ui.INK2, false), Ui.lp(this, Ui.MATCH, Ui.WRAP, 2, 12, 2, 0));

    // ---- permissions
    boolean overlay = Settings.canDrawOverlays(this), listener = listenerOn(), screening = role(RoleManager.ROLE_CALL_SCREENING),
        phone = granted(Manifest.permission.READ_PHONE_STATE) && granted(Manifest.permission.READ_CONTACTS), usage = Watchers.usageAllowed(this),
        browser = role(RoleManager.ROLE_BROWSER);
    int on = (overlay ? 1 : 0) + (listener ? 1 : 0) + (screening ? 1 : 0) + (phone ? 1 : 0) + (usage ? 1 : 0);
    root.addView(section(R.drawable.ic_shield_check, t("Guarding", "الحماية"),
        Ui.badge(this, on + " / 5 " + t("on", "مفعّلة"), on == 5 ? Ui.OK : on == 0 ? Ui.STOP : Ui.CAUTION)));
    root.addView(row(overlay, R.drawable.ic_layers, t("Show Kiki over other apps", "إظهار كيكي فوق التطبيقات"),
        t("So the warning appears on top of WhatsApp or the dialer. Kiki only appears when something needs your attention.", "ليظهر التحذير فوق واتساب أو شاشة الاتصال. لا يظهر كيكي إلا عند الحاجة."),
        new Runnable() { public void run() { startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName()))); } }));
    root.addView(row(listener, R.drawable.ic_bell, t("Read new message notifications", "قراءة إشعارات الرسائل الجديدة"),
        t("Veto reads the sender and text of NEW WhatsApp / SMS / Telegram notifications, on this phone. Trusted family chats are skipped. Nothing is uploaded.", "يقرأ فيتو المرسل ونص إشعارات واتساب والرسائل وتيليجرام الجديدة، على هذا الهاتف. محادثات العائلة الموثوقة تُتجاهل. لا يُرفع أي شيء."),
        new Runnable() { public void run() {
          Intent i = Build.VERSION.SDK_INT >= 30 ? new Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
              .putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, new ComponentName(MainActivity.this, ChatListener.class).flattenToString())
              : new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
          try { startActivity(i); } catch (RuntimeException e) { startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)); }
        } }));
    root.addView(row(screening, R.drawable.ic_phone_call, t("Check unknown callers", "فحص المتصلين المجهولين"),
        t("Makes Veto the phone's caller-ID & spam app, so it sees an unknown number before it rings. Veto never blocks or records calls.", "يجعل فيتو تطبيق هوية المتصل، فيرى الرقم المجهول قبل الرنين. لا يحظر المكالمات ولا يسجّلها."),
        new Runnable() { public void run() {
          RoleManager rm = (RoleManager) getSystemService(ROLE_SERVICE);
          if (rm != null) startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING), REQ_SCREEN);
        } }));
    root.addView(row(phone, R.drawable.ic_contact, t("Call state & contacts", "حالة المكالمة وجهات الاتصال"),
        t("To know when you are on a call, and to compare a “Hi Mum, new number” message with the Mum you saved. Contacts never leave the phone.", "لمعرفة متى تكون في مكالمة، ولمقارنة رسالة «مرحباً أمي، رقم جديد» برقم أمك المحفوظ. جهات الاتصال لا تغادر الهاتف."),
        new Runnable() { public void run() {
          List<String> p = new ArrayList<>();
          p.add(Manifest.permission.READ_PHONE_STATE);
          p.add(Manifest.permission.READ_CONTACTS);
          if (Build.VERSION.SDK_INT >= 33) p.add(Manifest.permission.POST_NOTIFICATIONS);
          requestPermissions(p.toArray(new String[0]), REQ_PERMS);
        } }));
    root.addView(row(usage, R.drawable.ic_smartphone, t("Notice your bank app during a call", "ملاحظة تطبيق البنك أثناء المكالمة"),
        t("Usage access lets Veto notice a banking or remote-control app (AnyDesk) opened DURING a call with an unknown number. It is only checked during such calls.", "يتيح لفيتو ملاحظة فتح تطبيق بنك أو تحكّم عن بُعد (AnyDesk) أثناء مكالمة مع رقم مجهول فقط."),
        new Runnable() { public void run() { startActivity(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)); } }));
    root.addView(row(role(RoleManager.ROLE_CALL_REDIRECTION), R.drawable.ic_phone_off, t("Stop calls to fake numbers (optional)", "إيقاف المكالمات إلى الأرقام المزيّفة (اختياري)"),
        t("Before you call a number from a scam message, or a contact saved as a bank that the bank does not publish, Veto holds the call and offers the bank's real number. All other calls go straight through, untouched.",
            "قبل أن تتصل برقم من رسالة احتيال، أو بجهة اتصال محفوظة باسم بنك لا يعلن هذا الرقم، يوقف فيتو المكالمة ويعرض عليك رقم البنك الحقيقي. كل المكالمات الأخرى تمر كما هي."),
        new Runnable() { public void run() {
          RoleManager rm = (RoleManager) getSystemService(ROLE_SERVICE);
          if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_CALL_REDIRECTION)) startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_REDIRECTION), REQ_REDIRECT);
        } }));
    // contacts that pretend to be an institution (scammers ask victims to save "Bank Security" under their number)
    if (phone) {
      final LinearLayout audit = Ui.vertical(this);
      root.addView(audit, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 0));
      new Thread(new Runnable() { public void run() {
        final org.json.JSONArray list = Contacts.all(MainActivity.this);
        runOnUiThread(new Runnable() { public void run() {
          k.engine.contacts(list, new Engine.Cb() { public void done(JSONObject r) { showAudit(audit, r == null ? null : r.optJSONArray("list")); } });
        } });
      } }).start();
    }
    root.addView(row(browser, R.drawable.ic_link, t("Link Shield (optional)", "درع الروابط (اختياري)"),
        t("Make Veto the default link opener: every link you tap is checked first, then opened in your normal browser.", "اجعل فيتو يفتح الروابط: يُفحص كل رابط تضغطه أولاً ثم يُفتح في متصفحك المعتاد."),
        new Runnable() { public void run() {
          RoleManager rm = (RoleManager) getSystemService(ROLE_SERVICE);
          if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_BROWSER)) startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_BROWSER), REQ_BROWSER);
          else startActivity(new Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS));
        } }));
    root.addView(row(ChatScreen.enabled(this), R.drawable.ic_scan_search, t("Highlight scams inside open chats (optional)", "تمييز الاحتيال داخل المحادثات المفتوحة (اختياري)"),
        t("When a chat is open there is no notification, so Veto outlines scam messages on the screen instead, even after you scroll. Uses Accessibility, ONLY in the apps you switch on below, read-only: Veto never taps or types. In Settings: Installed apps → Veto → On.",
            "عندما تكون المحادثة مفتوحة لا يصل إشعار، لذلك يحدّد فيتو رسائل الاحتيال على الشاشة نفسها حتى بعد التمرير. يستخدم إمكانية الوصول فقط في التطبيقات التي تفعّلها أدناه، للقراءة فقط: لا يضغط ولا يكتب. في الإعدادات: التطبيقات المثبتة ← فيتو ← تشغيل."),
        new Runnable() { public void run() { startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)); } }));

    // ---- settings
    root.addView(section(R.drawable.ic_settings, t("Settings", "الإعدادات"), null));
    LinearLayout box = Ui.card(this);
    box.addView(toggle(t("Pause Kiki", "إيقاف كيكي مؤقتاً"), k.store.paused(), new CompoundButton.OnCheckedChangeListener() {
      public void onCheckedChanged(CompoundButton b, boolean v) { k.store.paused(v); }
    }));
    box.addView(toggle(t("Online checks (link X-ray, caller reputation)", "الفحص عبر الإنترنت (أشعة الروابط، سمعة المتصل)"), k.store.online(), new CompoundButton.OnCheckedChangeListener() {
      public void onCheckedChanged(CompoundButton b, boolean v) { k.store.online(v); }
    }));
    box.addView(Ui.bullet(this, R.drawable.ic_lock, Ui.OK, t("Off until you switch it on. Sends ONLY the link or the phone number, never your messages, names or contacts.",
        "معطّل حتى تفعّله. يُرسل الرابط أو رقم الهاتف فقط، وليس رسائلك أو أسماءك أو جهات اتصالك."), 12.5f, Ui.MUTED), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 4, 0, 2));
    box.addView(toggle(t("Stronger highlight in open chats", "تمييز أقوى داخل المحادثات المفتوحة"), k.store.highlightStrong(), new CompoundButton.OnCheckedChangeListener() {
      public void onCheckedChanged(CompoundButton b, boolean v) { k.store.highlightStrong(v); }
    }));
    box.addView(toggle(t("Check SMS directly (needs SMS permission)", "فحص الرسائل النصية مباشرة (يحتاج إذن الرسائل)"), k.store.smsDirect(), new CompoundButton.OnCheckedChangeListener() {
      public void onCheckedChanged(CompoundButton b, boolean v) {
        k.store.smsDirect(v);
        if (v && !granted(Manifest.permission.RECEIVE_SMS)) requestPermissions(new String[] { Manifest.permission.RECEIVE_SMS }, REQ_PERMS);
      }
    }));
    box.addView(toggle(t("Cloud second opinion (Groq, your own key)", "رأي ثانٍ من السحابة (Groq، بمفتاحك)"), k.store.cloudSecond(), new CompoundButton.OnCheckedChangeListener() {
      public void onCheckedChanged(CompoundButton b, boolean v) { k.store.cloudSecond(v); }
    }));
    EditText groqField = field(t("Groq API key (stays on this phone)", "مفتاح Groq (يبقى على هذا الهاتف)"), k.store.groqKey(), true);
    groqField.addTextChangedListener(new TextWatcher() {
      public void beforeTextChanged(CharSequence s, int a, int b2, int c) { }
      public void onTextChanged(CharSequence s, int a, int b2, int c) { }
      public void afterTextChanged(Editable s) { k.store.groqKey(s.toString()); }
    });
    box.addView(groqField, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 6, 0, 6));
    server = field(t("Veto server, e.g. http://192.168.1.20:8787", "خادم فيتو، مثل http://192.168.1.20:8787"), k.store.server(), false);
    box.addView(server, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 10, 0, 0));
    ipqs = field(t("IPQualityScore key (optional, your own)", "مفتاح IPQualityScore (اختياري، مفتاحك)"), k.store.ipqsKey(), true);
    box.addView(ipqs, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 8, 0, 0));
    Button save = Ui.pill(this, t("Save", "حفظ"), R.drawable.ic_check, Ui.Pill.NAVY);
    save.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
      k.store.server(server.getText().toString());
      k.store.ipqsKey(ipqs.getText().toString());
      Toast.makeText(MainActivity.this, t("Saved", "تم الحفظ"), Toast.LENGTH_SHORT).show();
    } });
    box.addView(save, Ui.lp(this, Ui.WRAP, Ui.WRAP, 0, 10, 0, 0));
    root.addView(box);

    // ---- which apps Veto reads (the user's choice; nothing else is ever read)
    root.addView(section(R.drawable.ic_message_square_text, t("Apps Veto reads", "التطبيقات التي يقرؤها فيتو"), null));
    LinearLayout apps = Ui.card(this);
    apps.addView(Ui.bullet(this, R.drawable.ic_lock, Ui.OK, t("Veto reads ONLY new-message notifications from the apps switched on here, on this phone. Every other app is ignored and never read.",
        "يقرأ فيتو إشعارات الرسائل الجديدة فقط من التطبيقات المفعّلة هنا، على هذا الهاتف. أي تطبيق آخر يُتجاهل ولا يُقرأ أبداً."), 12.5f, Ui.MUTED), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 6));
    int shown = 0;
    for (final String pkg : ChatListener.APPS.keySet()) {
      Drawable appIcon;
      try { appIcon = getPackageManager().getApplicationIcon(pkg); } catch (PackageManager.NameNotFoundException e) { continue; } // not installed
      apps.addView(appRow(pkg, ChatListener.APPS.get(pkg), appIcon));
      shown++;
    }
    if (shown == 0) apps.addView(Ui.text(this, t("No supported chat app is installed yet (WhatsApp, Telegram, Messages …).", "لا يوجد تطبيق محادثة مدعوم مثبّت بعد (واتساب، تيليجرام، الرسائل …)."), 13.5f, Ui.INK2, false));
    root.addView(apps);

    // ---- privacy
    root.addView(section(R.drawable.ic_lock, t("Privacy", "الخصوصية"), null));
    LinearLayout pv = Ui.card(this);
    String[][] points = {
      { "Everything is checked on this phone. Trusted chats are never read.", "كل شيء يُفحص على هذا الهاتف. المحادثات الموثوقة لا تُقرأ." },
      { "Veto never records calls (Android doesn't allow it, and Veto doesn't need it).", "لا يسجّل فيتو المكالمات (أندرويد لا يسمح بذلك ولا يحتاجه)." },
      { "It never taps, types, replies or sends anything for you.", "لا يضغط ولا يكتب ولا يرد ولا يرسل أي شيء نيابةً عنك." },
      { "Online checks are off until you switch them on, and then send only a link or a number.", "الفحص عبر الإنترنت معطّل حتى تفعّله، وعندها يُرسل رابطاً أو رقماً فقط." } };
    for (String[] pt : points) pv.addView(Ui.bullet(this, R.drawable.ic_shield_check, Ui.OK, t(pt[0], pt[1]), 13.5f, Ui.INK), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 3, 0, 3));
    final TextView ver = Ui.text(this, "Veto 0.3 · engine " + (k.engine.ready() ? "ready" : "loading…"), 11.5f, Ui.MUTED, false);
    if (!k.engine.ready()) k.main.postDelayed(new Runnable() { public void run() {
      if (k.engine.ready()) ver.setText("Veto 0.3 · engine ready"); else if (!isFinishing()) k.main.postDelayed(this, 1000);
    } }, 1000);
    pv.addView(ver, Ui.lp(this, Ui.WRAP, Ui.WRAP, 0, 8, 0, 0));
    root.addView(pv);

    sv.addView(root);
    setContentView(sv);
  }

  /** Light status and navigation bars with dark icons, matching the sky background. */
  @SuppressWarnings("deprecation")
  private void lightBars() {
    getWindow().setStatusBarColor(Ui.SKY1);
    getWindow().setNavigationBarColor(Ui.SKY3);
    getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
  }

  /** Section heading: icon + title (+ an optional badge at the end). */
  private View section(int iconRes, String s, View end) {
    LinearLayout row = Ui.horizontal(this);
    row.setPadding(dp(4), dp(20), dp(4), dp(8));
    row.addView(Ui.iconView(this, iconRes, Ui.NAVY, 18));
    TextView t = Ui.text(this, s, 16.5f, Ui.INK, true);
    LinearLayout.LayoutParams tl = new LinearLayout.LayoutParams(0, Ui.WRAP, 1f);
    tl.setMarginStart(dp(8));
    row.addView(t, tl);
    if (end != null) row.addView(end, Ui.lp(Ui.WRAP, Ui.WRAP));
    return row;
  }

  /** A card listing saved contacts that claim to be an institution but hold a number it does not publish. */
  private void showAudit(LinearLayout into, org.json.JSONArray hits) {
    into.removeAllViews();
    if (hits == null || hits.length() == 0) return;
    LinearLayout card = Ui.vertical(this);
    card.setBackground(Ui.tinted(this, "stop", 18));
    card.setPadding(dp(14), dp(12), dp(14), dp(12));
    int[] tint = Ui.tint("stop");
    card.addView(Ui.kicker(this, R.drawable.ic_contact, t(hits.length() + " saved contact(s) pretend to be an institution", hits.length() + " جهة اتصال محفوظة تنتحل صفة جهة رسمية"), tint[2]));
    for (int i = 0; i < Math.min(5, hits.length()); i++) {
      JSONObject h = hits.optJSONObject(i);
      JSONObject off = h.optJSONObject("official");
      String line = "“" + h.optString("name") + "” · " + Text.mask(h.optString("number")) + "\n" + Text.L(this, h.optJSONObject("reason"))
          + (off != null ? t(" Use " + off.optString("display") + ".", " استخدم " + off.optString("display") + ".") : "");
      card.addView(Ui.bullet(this, R.drawable.ic_triangle_alert, tint[2], line, 13.5f, tint[2]), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 8, 0, 0));
    }
    card.addView(Ui.text(this, t("Scammers ask victims to save their number as “Bank” so a later call looks real. Delete or rename these contacts.", "يطلب المحتالون حفظ رقمهم باسم «البنك» لتبدو مكالمتهم لاحقاً حقيقية. احذف هذه الجهات أو غيّر اسمها."), 12.5f, tint[2], false), Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 8, 0, 0));
    into.addView(card, Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 4, 0, 10));
  }

  private View row(boolean ok, int iconRes, String title, String why, final Runnable fix) {
    LinearLayout c = Ui.card(this);
    LinearLayout top = Ui.horizontal(this);
    top.addView(Ui.iconTile(this, iconRes, ok ? "verified" : "advising", 38));
    LinearLayout.LayoutParams tl = new LinearLayout.LayoutParams(0, Ui.WRAP, 1f);
    tl.setMarginStart(dp(12));
    tl.setMarginEnd(dp(8));
    top.addView(Ui.text(this, title, 15, Ui.INK, true), tl);
    if (ok) {
      top.addView(Ui.badge(this, t("On", "مفعّل"), Ui.OK), Ui.lp(Ui.WRAP, Ui.WRAP));
    } else {
      Button b = Ui.pill(this, t("Allow", "سماح"), 0, Ui.Pill.NAVY);
      b.setMinHeight(dp(38));
      b.setMinimumHeight(dp(38));
      b.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { fix.run(); } });
      top.addView(b, Ui.lp(Ui.WRAP, dp(38)));
    }
    c.addView(top, Ui.lp(Ui.MATCH, Ui.WRAP));
    c.addView(Ui.text(this, why, 12.5f, Ui.MUTED, false), Ui.lp(this, Ui.MATCH, Ui.WRAP, 50, 4, 0, 0));
    c.setLayoutParams(Ui.lp(this, Ui.MATCH, Ui.WRAP, 0, 0, 0, 10));
    return c;
  }

  @SuppressWarnings("deprecation")
  private Switch toggle(String label, boolean on, CompoundButton.OnCheckedChangeListener l) {
    Switch s = new Switch(this);
    s.setText(label);
    s.setTextSize(14.5f);
    s.setTextColor(Ui.INK);
    s.setChecked(on);
    int[][] states = { { android.R.attr.state_checked }, {} };
    s.setThumbTintList(new android.content.res.ColorStateList(states, new int[] { Ui.BLUE, 0xFFFFFFFF }));
    s.setTrackTintList(new android.content.res.ColorStateList(states, new int[] { 0xFF1A6CF0, 0xFF475467 }));
    s.setOnCheckedChangeListener(l);
    s.setPadding(0, dp(8), 0, dp(8));
    return s;
  }

  private EditText field(String hint, String value, boolean secret) {
    EditText e = new EditText(this);
    e.setHint(hint);
    e.setHintTextColor(Ui.MUTED);
    e.setTextColor(Ui.INK);
    e.setText(value);
    e.setTextSize(14);
    e.setSingleLine(true);
    e.setBackground(Ui.round(this, Ui.SURFACE, 14, Ui.LINE2));
    e.setPadding(dp(14), dp(11), dp(14), dp(11));
    e.setInputType(secret ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
    e.setTypeface(android.graphics.Typeface.DEFAULT); // password fields default to monospace
    return e;
  }

  /** One chat app: its real icon, its name, and a switch (on = Veto may read its new-message notifications). */
  @SuppressWarnings("deprecation")
  private View appRow(final String pkg, String name, Drawable appIcon) {
    LinearLayout row = Ui.horizontal(this);
    row.setPadding(0, dp(6), 0, dp(6));
    ImageView ic = new ImageView(this);
    ic.setImageDrawable(appIcon);
    row.addView(ic, Ui.lp(dp(34), dp(34)));
    Switch s = new Switch(this);
    s.setText(name);
    s.setTextSize(15);
    s.setTextColor(Ui.INK);
    s.setChecked(Veto.get(this).store.reads(pkg));
    s.setContentDescription(t("Veto reads ", "يقرأ فيتو ") + name);
    int[][] states = { { android.R.attr.state_checked }, {} };
    s.setThumbTintList(new android.content.res.ColorStateList(states, new int[] { Ui.BLUE, 0xFFFFFFFF }));
    s.setTrackTintList(new android.content.res.ColorStateList(states, new int[] { 0xFF1A6CF0, 0xFF475467 }));
    s.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
      public void onCheckedChanged(CompoundButton b, boolean v) { Veto.get(MainActivity.this).store.reads(pkg, v); ChatScreen.refreshApps(); }
    });
    LinearLayout.LayoutParams sl = new LinearLayout.LayoutParams(0, Ui.WRAP, 1f);
    sl.setMarginStart(dp(12));
    row.addView(s, sl);
    return row;
  }

  @Override public void onRequestPermissionsResult(int code, String[] p, int[] r) {
    super.onRequestPermissionsResult(code, p, r);
    Veto.get(this).start();
    build();
  }

  @Override protected void onActivityResult(int code, int result, Intent data) {
    super.onActivityResult(code, result, data);
    build();
  }
}
