package ae.veto.app;

import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.ValueAnimator;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/**
 * Kiki on top of other apps ("Display over other apps"). Two windows:
 *  - the pet (the team's sprites), hidden until something needs the user; draggable; auto-hides,
 *  - the warning card, red/amber, says WHY in plain words, with Report / Warn family / I know them.
 * Read-only: Veto never taps, types or sends anything inside other apps; every action opens the
 * dialer / SMS / share sheet so the USER decides.
 */
final class Overlay {
  static final class Alert {
    String level = "stop";                 // stop | caution | advising | verified
    String title;
    String source;                         // "WhatsApp · +92 ••• 4567 · not in your contacts"
    final ArrayList<String> reasons = new ArrayList<>();
    String detail;
    String sender;                         // raw number or name, for "I know them" / reporting
    String evidence;                       // full text for the police report
    String smsReport;                      // short text for SMS 2828
    String familyText;                     // text for "warn a family member"
    boolean call;                          // about a phone call
  }

  private final Context c;
  private final WindowManager wm;
  private final Handler h = new Handler(Looper.getMainLooper());
  private LinearLayout pet;
  private TextView bubble, tag;
  private ImageView img;
  private WindowManager.LayoutParams petLp;
  private View card;
  private Alert last;
  private String mood;
  private ValueAnimator anim;
  private final Runnable hidePetTask = new Runnable() { public void run() { hidePet(); } };

  Overlay(Context c) {
    this.c = c;
    this.wm = (WindowManager) c.getSystemService(Context.WINDOW_SERVICE);
  }

  boolean allowed() { return Settings.canDrawOverlays(c); }
  String mood() { return pet == null ? null : mood; }
  private int dp(float v) { return Ui.dp(c, v); }

  private WindowManager.LayoutParams params(int w, int height, int gravity) {
    WindowManager.LayoutParams p = new WindowManager.LayoutParams(w, height, WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN, PixelFormat.TRANSLUCENT);
    p.gravity = gravity;
    return p;
  }

  static int sprite(String mood) {
    if ("listening".equals(mood)) return R.drawable.pet_listening;
    if ("investigating".equals(mood)) return R.drawable.pet_investigating;
    if ("thinking".equals(mood)) return R.drawable.pet_thinking;
    if ("advising".equals(mood)) return R.drawable.pet_advising;
    if ("caution".equals(mood)) return R.drawable.pet_caution;
    if ("stop".equals(mood)) return R.drawable.pet_stop;
    if ("verified".equals(mood)) return R.drawable.pet_verified;
    return R.drawable.pet_idle;
  }

  static String label(Context c, String mood) {
    if ("listening".equals(mood)) return Text.t(c, "Watching", "يراقب");
    if ("investigating".equals(mood)) return Text.t(c, "Checking", "يتحقّق");
    if ("thinking".equals(mood)) return Text.t(c, "Thinking", "يفكّر");
    if ("advising".equals(mood)) return Text.t(c, "Advice", "نصيحة");
    if ("caution".equals(mood)) return Text.t(c, "Caution", "انتبه");
    if ("stop".equals(mood)) return Text.t(c, "STOP!", "توقّف!");
    if ("verified".equals(mood)) return Text.t(c, "Verified", "موثّق");
    return Text.t(c, "On guard", "في الحراسة");
  }

  // ------------------------------------------------------------------ pet
  /** Show Kiki in a mood. say = bubble text (null keeps the current one); ms = auto-hide, 0 = stay. */
  void pet(String m, String say, long ms) {
    if (!allowed()) { if (say != null) Veto.notifyFallback(c, label(c, m), say); return; }
    if (pet == null) buildPet();
    if (!m.equals(mood)) {
      mood = m;
      img.setImageResource(sprite(m));
      tag.setText(label(c, m));
      tag.setBackground(Ui.round(c, Ui.color(m), 99));
      animate(m);
    }
    if (say != null && !say.isEmpty()) { bubble.setText(say); bubble.setVisibility(View.VISIBLE); }
    pet.setVisibility(card != null ? View.GONE : View.VISIBLE);
    h.removeCallbacks(hidePetTask);
    if (ms > 0) h.postDelayed(hidePetTask, ms);
  }

  void quiet() { if (bubble != null) bubble.setVisibility(View.GONE); }

  void hidePet() {
    h.removeCallbacks(hidePetTask);
    if (anim != null) { anim.cancel(); anim = null; }
    if (pet != null) { try { wm.removeView(pet); } catch (RuntimeException ignored) { /* already gone */ } }
    pet = null;
    mood = null;
  }

  private void buildPet() {
    pet = Ui.vertical(c);
    pet.setGravity(Gravity.CENTER_HORIZONTAL);
    bubble = Ui.text(c, "", 14, Ui.INK, false);
    bubble.setBackground(Ui.round(c, Color.WHITE, 18, Ui.LINE));
    bubble.setPadding(dp(14), dp(10), dp(14), dp(10));
    bubble.setMaxWidth(dp(250));
    bubble.setElevation(dp(6));
    bubble.setVisibility(View.GONE);
    if (Text.ar(c)) bubble.setTextDirection(View.TEXT_DIRECTION_RTL);
    img = new ImageView(c);
    img.setScaleType(ImageView.ScaleType.FIT_CENTER);
    img.setContentDescription("Kiki");
    tag = Ui.text(c, "", 11, Color.WHITE, true);
    tag.setPadding(dp(10), dp(2), dp(10), dp(3));
    LinearLayout.LayoutParams bl = Ui.lp(Ui.WRAP, Ui.WRAP);
    bl.bottomMargin = dp(4);
    pet.addView(bubble, bl);
    pet.addView(img, Ui.lp(dp(108), dp(102)));
    pet.addView(tag, Ui.lp(Ui.WRAP, Ui.WRAP));
    petLp = params(Ui.WRAP, Ui.WRAP, Gravity.BOTTOM | Gravity.RIGHT);
    petLp.x = dp(8);
    petLp.y = dp(96);
    img.setOnTouchListener(new View.OnTouchListener() {
      float sx, sy; int ox, oy; boolean moved;
      public boolean onTouch(View v, MotionEvent e) {
        switch (e.getActionMasked()) {
          case MotionEvent.ACTION_DOWN:
            sx = e.getRawX(); sy = e.getRawY(); ox = petLp.x; oy = petLp.y; moved = false;
            return true;
          case MotionEvent.ACTION_MOVE:
            float dx = e.getRawX() - sx, dy = e.getRawY() - sy;
            if (Math.abs(dx) + Math.abs(dy) > dp(8)) moved = true;
            if (moved && pet != null) {
              petLp.x = (int) (ox - dx);
              petLp.y = (int) (oy - dy);
              try { wm.updateViewLayout(pet, petLp); } catch (RuntimeException ignored) { /* gone */ }
            }
            return true;
          case MotionEvent.ACTION_UP:
            if (!moved) onPetTap();
            return true;
          default:
            return false;
        }
      }
    });
    bubble.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { bubble.setVisibility(View.GONE); } });
    wm.addView(pet, petLp);
  }

  private void onPetTap() {
    if (last != null && card == null && ("stop".equals(mood) || "caution".equals(mood))) { card(last); return; }
    if (bubble.getVisibility() == View.VISIBLE) bubble.setVisibility(View.GONE);
    else if (bubble.getText().length() > 0) bubble.setVisibility(View.VISIBLE);
  }

  private void animate(String m) {
    if (anim != null) { anim.cancel(); anim = null; }
    img.setRotation(0); img.setScaleX(1); img.setScaleY(1); img.setTranslationY(0);
    img.post(new Runnable() { public void run() { img.setPivotX(img.getWidth() / 2f); img.setPivotY(img.getHeight() * 0.92f); } });
    if ("stop".equals(m)) {
      anim = ObjectAnimator.ofFloat(img, "rotation", 0, -9, 9, -9, 9, -7, 7, -4, 0);
      anim.setDuration(1100);
    } else if ("caution".equals(m)) {
      anim = ObjectAnimator.ofPropertyValuesHolder(img, PropertyValuesHolder.ofFloat("scaleX", 1f, 1.07f), PropertyValuesHolder.ofFloat("scaleY", 1f, 1.07f));
      anim.setDuration(700);
      anim.setRepeatCount(ValueAnimator.INFINITE);
      anim.setRepeatMode(ValueAnimator.REVERSE);
    } else {
      anim = ObjectAnimator.ofFloat(img, "translationY", 0, -dp(5));
      anim.setDuration("listening".equals(m) ? 800 : 1600);
      anim.setRepeatCount(ValueAnimator.INFINITE);
      anim.setRepeatMode(ValueAnimator.REVERSE);
    }
    anim.start();
  }

  // ------------------------------------------------------------------ card
  void card(final Alert a) {
    last = a;
    if (!allowed()) { Veto.notifyFallback(c, a.title, a.reasons.isEmpty() ? "" : a.reasons.get(0)); return; }
    hideCard();
    final int col = Ui.color(a.level);
    LinearLayout box = Ui.vertical(c);
    box.setBackground(Ui.round(c, Color.WHITE, 22, Ui.LINE));
    box.setElevation(dp(12));
    if (Text.ar(c)) box.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);

    LinearLayout head = new LinearLayout(c);
    head.setOrientation(LinearLayout.HORIZONTAL);
    head.setGravity(Gravity.CENTER_VERTICAL);
    head.setBackground(Ui.topRound(c, col, 22));
    head.setPadding(dp(10), dp(10), dp(14), dp(10));
    ImageView face = new ImageView(c);
    face.setImageResource(sprite(a.level));
    head.addView(face, Ui.lp(dp(58), dp(56)));
    LinearLayout titles = Ui.vertical(c);
    titles.addView(Ui.text(c, a.title, 18, Color.WHITE, true));
    if (a.source != null) {
      TextView src = Ui.text(c, a.source, 12.5f, Color.WHITE, false);
      src.setPadding(0, dp(2), 0, 0);
      titles.addView(src);
    }
    LinearLayout.LayoutParams tl = new LinearLayout.LayoutParams(0, Ui.WRAP, 1f);
    tl.setMarginStart(dp(10));
    head.addView(titles, tl);
    box.addView(head, Ui.lp(Ui.MATCH, Ui.WRAP));

    LinearLayout body = Ui.vertical(c);
    body.setPadding(dp(14), dp(10), dp(14), dp(12));
    int bulletIcon = "stop".equals(a.level) ? R.drawable.ic_octagon_alert : "caution".equals(a.level) ? R.drawable.ic_triangle_alert : R.drawable.ic_info;
    for (String r : a.reasons) body.addView(Ui.bullet(c, bulletIcon, col, r, 15, Ui.INK), Ui.lp(c, Ui.MATCH, Ui.WRAP, 0, 0, 0, 6));
    if (a.detail != null && !a.detail.isEmpty()) body.addView(Ui.text(c, a.detail, 13, Ui.MUTED, false), Ui.lp(c, Ui.MATCH, Ui.WRAP, 0, 2, 0, 6));
    final LinearLayout actions = Ui.vertical(c);
    body.addView(actions, Ui.lp(c, Ui.MATCH, Ui.WRAP, 0, 6, 0, 0));
    mainButtons(actions, a, col);
    box.addView(body, Ui.lp(Ui.MATCH, Ui.WRAP));

    FrameLayout frame = new FrameLayout(c);
    frame.setPadding(dp(10), 0, dp(10), dp(12));
    frame.addView(box, new FrameLayout.LayoutParams(Ui.MATCH, Ui.WRAP));
    // Bottom of the screen: notification banners (with Reply buttons) slide in at the top and would cover
    // the red title; down here the buttons are also within thumb reach. The card carries Kiki's face, so
    // the floating pet steps aside while it is shown.
    WindowManager.LayoutParams lp = params(Ui.MATCH, Ui.WRAP, Gravity.BOTTOM);
    lp.y = dp(28);
    try { wm.addView(frame, lp); card = frame; } catch (RuntimeException e) { return; }
    if (pet != null) pet.setVisibility(View.GONE);
    box.setTranslationY(dp(320));
    box.animate().translationY(0).setDuration(280).start();
  }

  void hideCard() {
    if (card != null) { try { wm.removeView(card); } catch (RuntimeException ignored) { /* gone */ } }
    card = null;
    if (pet != null) pet.setVisibility(View.VISIBLE); // tap Kiki to bring the card back
  }

  private void dismiss() { hideCard(); hidePet(); last = null; }

  private void mainButtons(final LinearLayout actions, final Alert a, final int col) {
    actions.removeAllViews();
    List<Button> bs = new ArrayList<>();
    Button rep = Ui.pill(c, Text.t(c, "Report", "أبلغ الشرطة"), R.drawable.ic_siren, col);
    rep.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { reportButtons(actions, a, col); } });
    bs.add(rep);
    if (a.familyText != null) {
      Button fam = Ui.pill(c, Text.t(c, "Warn family", "حذّر عائلتك"), R.drawable.ic_users, Ui.Pill.WHITE);
      fam.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
        Intent s = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, a.familyText);
        open(Intent.createChooser(s, Text.t(c, "Warn a family member", "حذّر أحد أفراد عائلتك")));
      } });
      bs.add(fam);
    }
    if (a.sender != null && !a.call) {
      Button know = Ui.pill(c, Text.t(c, "I know them", "أعرف المرسل"), R.drawable.ic_user_check, Ui.Pill.WHITE);
      know.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
        Store.get(c).trust(a.sender);
        Toast.makeText(c, Text.t(c, "OK. Kiki will stay quiet for this sender unless they ask for a code or money.", "حسناً، سيبقى كيكي هادئاً مع هذا المرسل ما لم يطلب رمزاً أو مالاً."), Toast.LENGTH_LONG).show();
        dismiss();
      } });
      bs.add(know);
    }
    Button close = Ui.pill(c, Text.t(c, "Got it", "فهمت"), R.drawable.ic_check, Ui.Pill.NAVY);
    close.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { dismiss(); } });
    bs.add(close);
    Ui.rows(c, actions, bs);
  }

  private void reportButtons(final LinearLayout actions, final Alert a, final int col) {
    actions.removeAllViews();
    actions.addView(Ui.bullet(c, R.drawable.ic_info, Ui.MUTED, Text.t(c, "Nothing is sent automatically. You check it and press send.", "لا يُرسل شيء تلقائياً، أنت تراجع وتضغط إرسال."), 12.5f, Ui.MUTED), Ui.lp(c, Ui.MATCH, Ui.WRAP, 4, 0, 4, 4));
    List<Button> bs = new ArrayList<>();
    Button aman = Ui.pill(c, Text.t(c, "Aman 800 2626", "أمان 800 2626"), R.drawable.ic_phone, col);
    aman.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { open(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:8002626"))); } });
    bs.add(aman);
    Button sms = Ui.pill(c, Text.t(c, "SMS 2828", "رسالة 2828"), R.drawable.ic_message_square_text, col);
    sms.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
      open(new Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:2828")).putExtra("sms_body", a.smsReport != null ? a.smsReport : a.title));
    } });
    bs.add(sms);
    Button ecrime = Ui.pill(c, Text.t(c, "eCrime (Dubai)", "الجرائم الإلكترونية"), R.drawable.ic_globe, Ui.Pill.WHITE);
    ecrime.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { open(new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.ecrime.ae"))); } });
    bs.add(ecrime);
    Button copy = Ui.pill(c, Text.t(c, "Copy evidence", "انسخ الأدلة"), R.drawable.ic_copy, Ui.Pill.WHITE);
    copy.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
      ClipboardManager cm = (ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
      if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("Veto report", a.evidence));
      Toast.makeText(c, Text.t(c, "Evidence copied, paste it into your report.", "تم نسخ الأدلة، الصقها في بلاغك."), Toast.LENGTH_SHORT).show();
    } });
    bs.add(copy);
    if (a.sender != null && a.sender.replaceAll("\\D", "").length() >= 7) {
      Button mark = Ui.pill(c, Text.t(c, "Remember as scam", "احفظه كرقم احتيال"), R.drawable.ic_ban, Ui.Pill.WHITE);
      mark.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
        Store.get(c).report(a.sender);
        Toast.makeText(c, Text.t(c, "Saved on this phone: Kiki will warn you if this number contacts you again.", "حُفظ على هذا الهاتف: سينبّهك كيكي إذا تواصل هذا الرقم مجدداً."), Toast.LENGTH_LONG).show();
      } });
      bs.add(mark);
    }
    Button back = Ui.pill(c, Text.t(c, "Back", "رجوع"), R.drawable.ic_arrow_left, Ui.Pill.WHITE);
    back.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { mainButtons(actions, a, col); } });
    bs.add(back);
    Ui.rows(c, actions, bs);
  }

  private void open(Intent i) {
    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    try { c.startActivity(i); } catch (RuntimeException e) { Toast.makeText(c, "No app can open this.", Toast.LENGTH_SHORT).show(); }
    hideCard();
  }
}
