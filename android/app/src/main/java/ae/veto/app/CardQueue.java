package ae.veto.app;

import java.util.ArrayDeque;

/**
 * Cards waiting to be shown. A new card never silently replaces one on screen: the card on screen goes back into
 * the queue, and the queue hands out the most important card first, then the oldest. No alert is lost in a burst.
 * Pure Java with no Android imports, so harness/CardQueueTest.java can test it on a laptop.
 */
final class CardQueue<T> {
  interface Rank<T> { int of(T t); }

  private final ArrayDeque<T> waiting = new ArrayDeque<>();
  private final Rank<T> rank;

  CardQueue(Rank<T> rank) { this.rank = rank; }

  /** The item to show now, or null when it waits (the card on screen stays). */
  T offer(T item, T onScreen) {
    if (onScreen == null) return item;
    if (rank.of(item) > rank.of(onScreen)) {
      waiting.addFirst(onScreen);   // the card on screen goes back, ahead of the others
      return item;
    }
    waiting.addLast(item);
    return null;
  }

  /** The most important waiting item (first in line among equals), removed from the queue; null when empty. */
  T next() {
    T best = null;
    for (T t : waiting) if (best == null || rank.of(t) > rank.of(best)) best = t;
    if (best != null) waiting.remove(best);
    return best;
  }

  int waiting() { return waiting.size(); }
}
