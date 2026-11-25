package ae.veto.app;

/**
 * Harness for CardQueue, the queue that keeps every alert in a burst. No Android needed.
 * Run from the android folder:
 *   javac -d harness/out app/src/main/java/ae/veto/app/CardQueue.java harness/CardQueueTest.java
 *   java -cp harness/out ae.veto.app.CardQueueTest
 */
public final class CardQueueTest {
  static int failed = 0;

  static void check(boolean ok, String what) {
    System.out.println((ok ? "ok    " : "FAIL  ") + what);
    if (!ok) failed++;
  }

  static int rank(String s) { return s.startsWith("stop") ? 3 : s.startsWith("caution") ? 2 : 0; }

  static CardQueue<String> queue() {
    return new CardQueue<>(new CardQueue.Rank<String>() { public int of(String s) { return rank(s); } });
  }

  public static void main(String[] args) {
    CardQueue<String> q = queue();
    check("caution-1".equals(q.offer("caution-1", null)), "an empty screen shows the card at once");
    check(q.offer("caution-2", "caution-1") == null, "an equal card waits; the card on screen stays");
    check("stop-1".equals(q.offer("stop-1", "caution-1")), "a stop card replaces a caution card at once");
    check(q.waiting() == 2, "the replaced caution card and the waiting one are both kept");
    check("caution-1".equals(q.next()), "the next card is the oldest of the equal ones");
    check("caution-2".equals(q.next()), "then the next one");
    check(q.next() == null && q.waiting() == 0, "and then the queue is empty");

    CardQueue<String> p = queue();
    p.offer("caution-a", "caution-0");          // waits
    p.offer("stop-b", "caution-0");             // shows at once; caution-0 goes back to the front
    check(p.offer("caution-c", "stop-b") == null, "a caution card waits behind a stop card on screen");
    check("caution-0".equals(p.next()) && "caution-a".equals(p.next()) && "caution-c".equals(p.next()),
        "equal cards come out in arrival order");

    CardQueue<String> b = queue();
    String screen = null;
    for (int i = 0; i < 40; i++) {
      String item = (i % 4 == 0 ? "stop-" : "caution-") + i;
      String shown = b.offer(item, screen);
      if (shown != null) screen = shown;
    }
    int accounted = (screen == null ? 0 : 1) + b.waiting();
    check(accounted == 40, "a burst of 40 alerts loses none (on screen or waiting): " + accounted);

    int drained = 0;
    boolean stopsFirst = true;
    boolean seenCaution = false;
    String next;
    while ((next = b.next()) != null) {
      drained++;
      if (next.startsWith("caution")) seenCaution = true;
      else if (seenCaution) stopsFirst = false;
    }
    check(drained + (screen == null ? 0 : 1) == 40, "draining the queue hands out every waiting alert: " + drained);
    check(stopsFirst, "stop cards come out before caution cards");

    System.out.println(failed == 0 ? "ALL PASSED" : failed + " FAILED");
    System.exit(failed == 0 ? 0 : 1);
  }
}
