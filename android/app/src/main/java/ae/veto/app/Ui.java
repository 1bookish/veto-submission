package ae.veto.app;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.List;

/**
 * Veto.ai design system for the phone, built in code (no layout XML, no AndroidX). Same light theme as
 * web/app.css: light-blue sky, white glass cards, navy pill buttons with Lucide icons, solid status
 * colours with white text, pale tints with dark text. Contrast rule: never coloured text on grey; every
 * text/background pair below is at least 4.5:1 (WCAG AA for normal text).
 */
final class Ui {
  private Ui() {}

  // ---- palette (mirrors web/app.css :root)
  static final int SKY1 = 0xFFEEF6FF, SKY2 = 0xFFDCECFF, SKY3 = 0xFFC7DEFC;
  static final int SURFACE = 0xFFFFFFFF, SURFACE2 = 0xFFF3F6FB, LINE = 0xFFE2E9F3, LINE2 = 0xFFD3DDEB;
  static final int INK = 0xFF0D1B2E, INK2 = 0xFF2F3E57, MUTED = 0xFF4A5A72;   // muted: 6.9:1 on white, 5.1:1 on SKY3
  static final int NAVY = 0xFF0F1B2E, BLUE = 0xFF1A6CF0, LINK = 0xFF1849A9;
  // solid status fills, white text on each is >= 4.8:1
  static final int STOP = 0xFFC62A1F, HIGH = 0xFFC4320A, CAUTION = 0xFFB54708, ADVISE = 0xFF1D63D8, OK = 0xFF067A4F;
  // pale tints and the dark text that goes on them (>= 7:1)
  static final int SCAM_BG = 0xFFFEF3F2, SCAM_LINE = 0xFFFECDCA, SCAM_INK = 0xFF912018;
  static final int WARN_BG = 0xFFFFFAEB, WARN_LINE = 0xFFFEDF89, WARN_INK = 0xFF7A2E0E;
  static final int INFO_BG = 0xFFEFF6FF, INFO_LINE = 0xFFC7DCFF, INFO_INK = 0xFF1849A9;
  static final int OK_BG = 0xFFECFDF3, OK_LINE = 0xFFABEFC6, OK_INK = 0xFF05603A;
  /** Brand gradient (logo blue). Every stop keeps white text >= 5:1. */
  static final int[] GRAD = { 0xFF1849A9, 0xFF1A5FF0, 0xFF0B6BCB };
  static final int WRAP = ViewGroup.LayoutParams.WRAP_CONTENT, MATCH = ViewGroup.LayoutParams.MATCH_PARENT;

  /** NAVY = main action, BRAND = the blue "check" action, DANGER = red, WHITE = secondary (white pill, navy text). */
  enum Pill { NAVY, BRAND, DANGER, WHITE }

  /** Solid colour for a level (stop | caution | advising | verified | anything else). */
  static int color(String level) {
    if ("stop".equals(level)) return STOP;
    if ("caution".equals(level)) return CAUTION;
    if ("verified".equals(level)) return OK;
    if ("advising".equals(level)) return ADVISE;
    return NAVY;
  }

  /** Pale tint {background, border, text} for a level. */
  static int[] tint(String level) {
    if ("stop".equals(level)) return new int[] { SCAM_BG, SCAM_LINE, SCAM_INK };
    if ("caution".equals(level)) return new int[] { WARN_BG, WARN_LINE, WARN_INK };
    if ("verified".equals(level)) return new int[] { OK_BG, OK_LINE, OK_INK };
    return new int[] { INFO_BG, INFO_LINE, INFO_INK };
  }

  static int alpha(int color, float a) { return (Math.round(a * 255) << 24) | (color & 0x00FFFFFF); }

  static int dp(Context c, float v) {
    return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
  }

  static GradientDrawable round(Context c, int fill, float radiusDp) {
    GradientDrawable g = new GradientDrawable();
    g.setColor(fill);
    g.setCornerRadius(dp(c, radiusDp));
    return g;
  }

  static GradientDrawable round(Context c, int fill, float radiusDp, int stroke) {
    GradientDrawable g = round(c, fill, radiusDp);
    g.setStroke(dp(c, 1), stroke);
    return g;
  }

  /** Only the top corners rounded (the coloured header of the warning card). */
  static GradientDrawable topRound(Context c, int fill, float radiusDp) {
    GradientDrawable g = new GradientDrawable();
    g.setColor(fill);
    float r = dp(c, radiusDp);
    g.setCornerRadii(new float[] { r, r, r, r, 0, 0, 0, 0 });
    return g;
  }

  static GradientDrawable gradient(Context c, int[] colors, float radiusDp) {
    GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR, colors);
    g.setCornerRadius(dp(c, radiusDp));
    return g;
  }

  /** White glass card: near-opaque white over the sky, white hairline, soft shadow via elevation. */
  static GradientDrawable glass(Context c, float radiusDp) {
    return round(c, 0xF2FFFFFF, radiusDp, 0xFFFFFFFF);
  }

  /** A card as a vertical LinearLayout with padding and elevation. */
  static LinearLayout card(Context c) {
    LinearLayout l = vertical(c);
    l.setBackground(glass(c, 22));
    l.setElevation(dp(c, 2));
    l.setPadding(dp(c, 16), dp(c, 14), dp(c, 16), dp(c, 14));
    return l;
  }

  /** Pale tinted box (X-ray panels, notes); its text colour is tint(level)[2]. */
  static GradientDrawable tinted(Context c, String level, float radiusDp) {
    int[] t = tint(level);
    return round(c, t[0], radiusDp, t[1]);
  }

  /** App background: the light-blue sky of the reference image, with a white glow top-left. */
  static Drawable background(Context c) {
    GradientDrawable base = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[] { SKY1, SKY2, SKY3 });
    GradientDrawable glow = new GradientDrawable();
    glow.setGradientType(GradientDrawable.RADIAL_GRADIENT);
    glow.setColors(new int[] { 0xCCFFFFFF, 0x00FFFFFF });
    glow.setGradientCenter(0.1f, 0.0f);
    glow.setGradientRadius(dp(c, 420));
    GradientDrawable blue = new GradientDrawable();
    blue.setGradientType(GradientDrawable.RADIAL_GRADIENT);
    blue.setColors(new int[] { 0x291A6CF0, 0x001A6CF0 });
    blue.setGradientCenter(1.0f, 0.15f);
    blue.setGradientRadius(dp(c, 340));
    return new LayerDrawable(new Drawable[] { base, glow, blue });
  }

  static Drawable icon(Context c, int res, int color, float sizeDp) {
    Drawable d = c.getDrawable(res);
    if (d == null) return null;
    d = d.mutate();
    d.setTint(color);
    int s = dp(c, sizeDp);
    d.setBounds(0, 0, s, s);
    return d;
  }

  static ImageView iconView(Context c, int res, int color, float sizeDp) {
    ImageView v = new ImageView(c);
    v.setImageResource(res);
    v.setImageTintList(ColorStateList.valueOf(color));
    v.setLayoutParams(new LinearLayout.LayoutParams(dp(c, sizeDp), dp(c, sizeDp)));
    return v;
  }

  /** Rounded square holding an icon on a pale tint (permission rows, list bullets). */
  static View iconTile(Context c, int res, String level, float sizeDp) {
    int[] t = tint(level);
    LinearLayout tile = new LinearLayout(c);
    tile.setGravity(Gravity.CENTER);
    tile.setBackground(round(c, t[0], sizeDp * 0.32f));
    tile.addView(iconView(c, res, t[2], sizeDp * 0.5f));
    tile.setLayoutParams(new LinearLayout.LayoutParams(dp(c, sizeDp), dp(c, sizeDp)));
    return tile;
  }

  static TextView text(Context c, CharSequence s, float sp, int color, boolean bold) {
    TextView t = new TextView(c);
    t.setText(s);
    t.setTextSize(sp);
    t.setTextColor(color);
    if (bold) t.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
    t.setLineSpacing(0, 1.15f);
    return t;
  }

  /** Solid status badge: level colour, white bold text. */
  static TextView badge(Context c, CharSequence s, int color) {
    TextView t = text(c, s, 12, Color.WHITE, true);
    t.setBackground(round(c, color, 999));
    t.setPadding(dp(c, 10), dp(c, 3), dp(c, 10), dp(c, 4));
    return t;
  }

  /** Pill button with an optional leading icon. */
  static Button pill(Context c, CharSequence label, int iconRes, Pill style) {
    Button b = new Button(c);
    b.setText(label);
    b.setAllCaps(false);
    b.setTextSize(14);
    b.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
    b.setStateListAnimator(null);
    b.setGravity(Gravity.CENTER);
    b.setMinHeight(dp(c, 46));
    b.setMinimumHeight(dp(c, 46));
    b.setMinWidth(0);
    b.setMinimumWidth(0);
    b.setPadding(dp(c, 16), 0, dp(c, 16), 0);
    int fg;
    switch (style) {
      case BRAND: b.setBackground(gradient(c, GRAD, 999)); fg = Color.WHITE; b.setElevation(dp(c, 2)); break;
      case DANGER: b.setBackground(round(c, STOP, 999)); fg = Color.WHITE; b.setElevation(dp(c, 2)); break;
      case WHITE: b.setBackground(round(c, Color.WHITE, 999, LINE2)); fg = INK; break;
      default: b.setBackground(round(c, NAVY, 999)); fg = Color.WHITE; b.setElevation(dp(c, 2)); break;
    }
    paint(c, b, iconRes, fg);
    return b;
  }

  /** Pill filled with a solid level colour (Report / Aman on a red or amber card), white text. */
  static Button pill(Context c, CharSequence label, int iconRes, int solid) {
    Button b = pill(c, label, iconRes, Pill.NAVY);
    b.setBackground(round(c, solid, 999));
    return b;
  }

  private static void paint(Context c, Button b, int iconRes, int fg) {
    b.setTextColor(fg);
    if (iconRes != 0) {
      b.setCompoundDrawablesRelative(icon(c, iconRes, fg, 18), null, null, null);
      b.setCompoundDrawablePadding(dp(c, 8));
    }
  }

  static LinearLayout.LayoutParams lp(int w, int h) { return new LinearLayout.LayoutParams(w, h); }

  static LinearLayout.LayoutParams lp(Context c, int w, int h, float l, float t, float r, float b) {
    LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
    p.setMargins(dp(c, l), dp(c, t), dp(c, r), dp(c, b));
    return p;
  }

  static LinearLayout vertical(Context c) {
    LinearLayout l = new LinearLayout(c);
    l.setOrientation(LinearLayout.VERTICAL);
    return l;
  }

  static LinearLayout horizontal(Context c) {
    LinearLayout l = new LinearLayout(c);
    l.setOrientation(LinearLayout.HORIZONTAL);
    l.setGravity(Gravity.CENTER_VERTICAL);
    return l;
  }

  /** Two buttons per row so everything fits any phone width. */
  static void rows(Context c, LinearLayout into, List<? extends View> views) {
    for (int i = 0; i < views.size(); i += 2) {
      LinearLayout row = new LinearLayout(c);
      row.setOrientation(LinearLayout.HORIZONTAL);
      for (int j = i; j < Math.min(i + 2, views.size()); j++) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0, WRAP, 1f);
        p.setMargins(dp(c, 4), dp(c, 4), dp(c, 4), dp(c, 4));
        row.addView(views.get(j), p);
      }
      into.addView(row, lp(MATCH, WRAP));
    }
  }

  /** A line with a small icon in front (reasons, privacy points). */
  static View bullet(Context c, int iconRes, int iconColor, CharSequence s, float sp, int textColor) {
    LinearLayout row = horizontal(c);
    row.setGravity(Gravity.TOP);
    ImageView i = iconView(c, iconRes, iconColor, 16);
    LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(dp(c, 16), dp(c, 16));
    ip.topMargin = dp(c, 3);
    ip.setMarginEnd(dp(c, 9));
    row.addView(i, ip);
    row.addView(text(c, s, sp, textColor, false), new LinearLayout.LayoutParams(0, WRAP, 1f));
    return row;
  }

  /** Small uppercase heading with an icon, used inside tinted boxes ("WHAT THIS PAGE WANTS"). */
  static View kicker(Context c, int iconRes, CharSequence s, int color) {
    LinearLayout row = horizontal(c);
    row.addView(iconView(c, iconRes, color, 14));
    TextView t = text(c, s.toString().toUpperCase(java.util.Locale.ROOT), 11, color, true);
    t.setLetterSpacing(0.06f);
    LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(WRAP, WRAP);
    p.setMarginStart(dp(c, 6));
    row.addView(t, p);
    return row;
  }
}
