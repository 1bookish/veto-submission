package ae.veto.app;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.ComponentName;
import android.content.Context;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * In-chat highlighter (optional). When a chat is OPEN, Android shows no notification for new messages, so
 * Veto looks at the messages on screen instead and outlines the risky ones (red = scam, amber = caution),
 * following them while you scroll. A pill at the bottom says why.
 *
 * Limits, by design:
 *  - only the chat apps switched on under "Apps Veto reads" (enforced with AccessibilityServiceInfo.packageNames,
 *    so Android does not even deliver events from other apps),
 *  - read-only: Veto never taps, types, scrolls or changes anything (no gestures, no actions),
 *  - text is checked in memory on the phone; only a short hash of a flagged message is kept, for 200 messages.
 */
public class ChatScreen extends AccessibilityService {
  private static volatile ChatScreen running;
  /** text hash -> warning (flagged) ; text hash -> TRUE (checked, clean). In memory only. */
  private static final Map<String, Overlay.Alert> FLAGGED = lru(200);
  private static final Map<String, Boolean> CLEAN = lru(600);

  private final Handler h = new Handler(Looper.getMainLooper());
  private final Set<String> pending = new HashSet<>();
  private WindowManager wm;
  private FrameLayout layer;      // outlines, never touchable
  private LinearLayout pill;      // "Why?" button
  private Overlay.Alert pillAlert;
  private String currentPkg;
  private final int[] layerAt = new int[2];
  private final Runnable scan = new Runnable() { public void run() { scanNow(); } };

  private static <V> Map<String, V> lru(final int max) {
    return new LinkedHashMap<String, V>(64, 0.75f, true) {
      @Override protected boolean removeEldestEntry(Map.Entry<String, V> e) { return size() > max; }
    };
  }

  private static String key(String text) { return Store.key(text.replaceAll("\\s+", " ").trim()); }

  /** A message already flagged from its notification is outlined at once when its chat is opened. */
  static void remember(String text, Overlay.Alert a) {
    if (text == null || a == null) return;
    synchronized (FLAGGED) { FLAGGED.put(key(text), a); }
  }

  static boolean enabled(Context c) {
    String flat = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
    return flat != null && flat.contains(new ComponentName(c, ChatScreen.class).flattenToString());
  }

  /** Call after the user changes "Apps Veto reads". */
  static void refreshApps() { ChatScreen s = running; if (s != null) s.applyApps(); }

  private int dp(float v) { return Ui.dp(this, v); }

  @Override protected void onServiceConnected() {
    running = this;
    wm = (WindowManager) getSystemService(WINDOW_SERVICE);
    applyApps();
  }

  /** Android only delivers events from these packages. Never null (null would mean "all apps"). */
  private void applyApps() {
    AccessibilityServiceInfo info = getServiceInfo();
    if (info == null) return;
    List<String> on = new ArrayList<>();
    Store st = Store.get(this);
    for (String p : ChatListener.APPS.keySet()) if (st.reads(p)) on.add(p);
    if (on.isEmpty()) on.add(getPackageName() + ".none");
    info.packageNames = on.toArray(new String[0]);
    setServiceInfo(info);
    clear();
  }

  @Override public void onAccessibilityEvent(AccessibilityEvent e) {
    if (e == null || e.getPackageName() == null) return;
    String pkg = e.getPackageName().toString();
    if (!ChatListener.APPS.containsKey(pkg) || !Store.get(this).reads(pkg) || Store.get(this).paused()) { clear(); return; }
    h.removeCallbacks(scan);
    h.postDelayed(scan, e.getEventType() == AccessibilityEvent.TYPE_VIEW_SCROLLED ? 50 : 220);
  }

  @Override public void onInterrupt() { clear(); }

  @Override public boolean onUnbind(android.content.Intent i) {
    clear();
    running = null;
    return super.onUnbind(i);
  }

  // ------------------------------------------------------------------ reading the screen
  private static final class Item { final String text; final Rect r; Item(String t, Rect r) { text = t; this.r = r; } }

  private void collect(AccessibilityNodeInfo n, List<Item> out, int depth) {
    if (n == null || depth > 40 || out.size() > 120) return;
    if (!n.isVisibleToUser()) return;
    CharSequence t = n.isEditable() ? null : n.getText();
    if ((t == null || t.length() == 0) && n.getChildCount() == 0) t = n.getContentDescription(); // Telegram draws messages itself
    if (t != null && t.length() >= 20) {
      Rect r = new Rect();
      n.getBoundsInScreen(r);
      if (r.width() > dp(40) && r.height() > dp(14)) { out.add(new Item(t.toString(), r)); return; }
    }
    for (int i = 0; i < n.getChildCount(); i++) collect(n.getChild(i), out, depth + 1);
  }

  private void scanNow() {
    AccessibilityNodeInfo root;
    try { root = getRootInActiveWindow(); } catch (RuntimeException ex) { root = null; }
    if (root == null || root.getPackageName() == null) { clear(); return; }
    final String pkg = root.getPackageName().toString();
    if (!ChatListener.APPS.containsKey(pkg) || !Store.get(this).reads(pkg)) { clear(); return; }
    currentPkg = pkg;
    List<Item> items = new ArrayList<>();
    collect(root, items, 0);
    List<Item> hits = new ArrayList<>();
    List<Overlay.Alert> alerts = new ArrayList<>();
    for (final Item it : items) {
      final String k = key(it.text);
      Overlay.Alert a;
      synchronized (FLAGGED) { a = FLAGGED.get(k); }
      if (a != null) { hits.add(it); alerts.add(a); continue; }
      if (CLEAN.containsKey(k) || pending.contains(k)) continue;
      pending.add(k);
      JSONObject input = new JSONObject();
      try { input.put("text", it.text); input.put("channel", "chat"); } catch (Exception ignored) { /* never */ }
      final String appName = ChatListener.channel(pkg);
      final Veto v = Veto.get(this);
      v.engine.message(input, false, new Engine.Cb() {
        public void done(JSONObject r) {
          pending.remove(k);
          Overlay.Alert al = v.describe(r, appName, appName + Text.t(ChatScreen.this, " · in this chat", " · في هذه المحادثة"), null, it.text);
          if (al != null) { synchronized (FLAGGED) { FLAGGED.put(k, al); } h.removeCallbacks(scan); h.postDelayed(scan, 30); }
          else CLEAN.put(k, Boolean.TRUE);
        }
      });
    }
    draw(hits, alerts);
  }

  // ------------------------------------------------------------------ drawing
  private WindowManager.LayoutParams params(int w, int hgt, int flags, int gravity) {
    WindowManager.LayoutParams p = new WindowManager.LayoutParams(w, hgt, WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
        flags | WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN, PixelFormat.TRANSLUCENT);
    p.gravity = gravity;
    return p;
  }

  private void ensureLayer() {
    if (layer != null) return;
    layer = new FrameLayout(this);
    WindowManager.LayoutParams p = params(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.MATCH_PARENT,
        WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS, Gravity.TOP | Gravity.START);
    try { wm.addView(layer, p); } catch (RuntimeException e) { layer = null; return; }
    layer.addOnLayoutChangeListener(new View.OnLayoutChangeListener() {
      public void onLayoutChange(View v, int l, int t, int r, int b, int ol, int ot, int or, int ob) { v.getLocationOnScreen(layerAt); }
    });
  }

  private void draw(List<Item> hits, List<Overlay.Alert> alerts) {
    if (hits.isEmpty()) { clear(); return; }
    ensureLayer();
    if (layer == null) return;
    layer.getLocationOnScreen(layerAt);
    layer.removeAllViews();
    Overlay.Alert worst = alerts.get(0);
    for (int i = 0; i < hits.size(); i++) {
      Rect r = hits.get(i).r;
      Overlay.Alert a = alerts.get(i);
      if ("stop".equals(a.level)) worst = a;
      int col = Ui.color(a.level);
      View box = new View(this);
      GradientDrawable g = new GradientDrawable();
      g.setCornerRadius(dp(12));
      g.setColor(Ui.alpha(col, 0.10f));
      g.setStroke(dp(3), col);
      box.setBackground(g);
      int pad = dp(6);
      FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(r.width() + 2 * pad, r.height() + 2 * pad);
      lp.leftMargin = r.left - pad - layerAt[0];
      lp.topMargin = r.top - pad - layerAt[1];
      layer.addView(box, lp);
      TextView tag = Ui.badge(this, "stop".equals(a.level) ? Text.t(this, "Scam", "احتيال") : Text.t(this, "Caution", "انتبه"), col);
      tag.setTextSize(11);
      FrameLayout.LayoutParams tl = new FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT);
      tl.leftMargin = Math.max(0, r.left - pad - layerAt[0]);
      tl.topMargin = Math.max(0, r.top - pad - layerAt[1] - dp(20));
      layer.addView(tag, tl);
    }
    showPill(hits.size(), worst);
  }

  private void showPill(int n, Overlay.Alert a) {
    pillAlert = a;
    String label = n == 1
        ? Text.t(this, "Veto: this message looks like a scam · Why?", "فيتو: هذه الرسالة تبدو احتيالاً · لماذا؟")
        : Text.t(this, "Veto: " + n + " risky messages here · Why?", "فيتو: " + n + " رسائل خطرة هنا · لماذا؟");
    if (!"stop".equals(a.level)) label = n == 1
        ? Text.t(this, "Veto: be careful with this message · Why?", "فيتو: انتبه لهذه الرسالة · لماذا؟")
        : label;
    if (pill == null) {
      pill = Ui.horizontal(this);
      pill.setPadding(dp(16), dp(10), dp(16), dp(10));
      pill.setElevation(dp(6));
      pill.addView(Ui.iconView(this, R.drawable.ic_shield_alert, Color.WHITE, 18));
      TextView t = Ui.text(this, "", 14, Color.WHITE, true);
      LinearLayout.LayoutParams l = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
      l.setMarginStart(dp(8));
      pill.addView(t, l);
      pill.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
        if (pillAlert != null) Veto.get(ChatScreen.this).overlay.card(pillAlert);
      } });
      WindowManager.LayoutParams p = params(WindowManager.LayoutParams.WRAP_CONTENT, WindowManager.LayoutParams.WRAP_CONTENT, 0, Gravity.TOP | Gravity.CENTER_HORIZONTAL);
      p.y = dp(110);
      try { wm.addView(pill, p); } catch (RuntimeException e) { pill = null; return; }
    }
    pill.setBackground(Ui.round(this, Ui.color(a.level), 999));
    ((TextView) pill.getChildAt(1)).setText(label);
    pill.setVisibility(View.VISIBLE);
  }

  private void clear() {
    h.removeCallbacks(scan);
    if (layer != null) layer.removeAllViews();
    if (pill != null) pill.setVisibility(View.GONE);
  }
}
