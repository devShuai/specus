package com.theshuai.specusserver.management.service;

import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;
import java.util.*;
import java.util.function.UnaryOperator;
import java.util.function.Supplier;
import static com.theshuai.specusserver.management.service.PeerServiceDiscoveryService.CatalogKey;

/** Four catalog indexes form one commit unit per publisher session. A nonblocking per-key
 * lease survives through afterCommit publication, never a DB wait under a cache monitor.
 * Readers outside the producer see only committed values; REQUIRES_NEW gets its own overlay.
 * This is an ephemeral cache, not the durable ownership outbox, and does not replace current
 * database authorization or support nested-savepoint transaction semantics. */
final class PeerCatalogCache {
    private static final class Effect {
        final Map<PeerCatalogCache, Context> contexts = new IdentityHashMap<>();
        final Set<Context> borrowed = Collections.newSetFromMap(new IdentityHashMap<>());
        final TransactionSynchronization inherited;
        Effect() {
            if (TransactionSynchronizationManager.isActualTransactionActive() && TransactionSynchronizationManager.isSynchronizationActive()) {
                inherited = new TransactionSynchronization() {};
                TransactionSynchronizationManager.registerSynchronization(inherited);
            } else inherited = null;
        }
    }
    private static final ThreadLocal<Effect> EFFECT = new ThreadLocal<>();
    private final Object monitor = new Object(), resource = new Object();
    private final Map<CatalogKey, Cell> cells = new HashMap<>();
    private final int[] counts = new int[4];
    private final int capacity;
    PeerCatalogCache(int capacity) {
        if (capacity < 1) throw new IllegalArgumentException("invalid catalog cache capacity");
        this.capacity = capacity;
    }
    private static final class Cell {
        Object[] committed = new Object[4];
        Context owner;
    }
    private static final class Working {
        final Cell cell;
        final Object[] values;
        Working(Cell cell) { this.cell = cell; this.values = cell.committed.clone(); }
    }
    private final class Context implements TransactionSynchronization {
        final Map<CatalogKey, Working> entries = new LinkedHashMap<>();
        boolean dirty, closed;
        @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }
        @Override public void suspend() {
            if (TransactionSynchronizationManager.getResource(resource) == this) TransactionSynchronizationManager.unbindResource(resource);
        }
        @Override public void resume() { TransactionSynchronizationManager.bindResource(resource, this); }
        @Override public void afterCommit() { commit(this); }
        @Override public void afterCompletion(int status) {
            try { if (status == STATUS_COMMITTED) commit(this); }
            finally {
                if (TransactionSynchronizationManager.getResource(resource) == this) TransactionSynchronizationManager.unbindResource(resource);
                release(this);
            }
        }
    }
    static boolean inCommittedEffect() {
        Effect effect = EFFECT.get();
        if (effect == null) return false;
        return !TransactionSynchronizationManager.isActualTransactionActive() || !TransactionSynchronizationManager.isSynchronizationActive()
                || effect.inherited != null && TransactionSynchronizationManager.getSynchronizations().contains(effect.inherited);
    }
    static boolean hasScope() {
        return inCommittedEffect() || TransactionSynchronizationManager.isActualTransactionActive()
                && TransactionSynchronizationManager.isSynchronizationActive();
    }
    static <T> T mutation(Supplier<T> operation) {
        if (hasScope()) return operation.get();
        var result = new java.util.concurrent.atomic.AtomicReference<T>();
        effectScope(() -> result.set(operation.get()), false);
        return result.get();
    }
    /** Used by actual afterCommit callbacks, not by a business writer. No second connection. */
    static void committedEffect(Runnable effect) {
        effectScope(effect, true);
    }
    private static void effectScope(Runnable effect, boolean commitOnFailure) {
        if (inCommittedEffect()) { effect.run(); return; }
        Effect previous = EFFECT.get();
        Effect scope = new Effect(); EFFECT.set(scope);
        boolean completed = false;
        try { effect.run(); completed = true; }
        finally {
            try { if (completed || commitOnFailure) flushCommittedEffects(); }
            finally {
                if (previous == null) EFFECT.remove(); else EFFECT.set(previous);
                for (var entry : scope.contexts.entrySet())
                    if (!scope.borrowed.contains(entry.getValue())) entry.getKey().release(entry.getValue());
            }
        }
    }
    static void flushCommittedEffects() {
        Effect scope = EFFECT.get();
        if (scope != null && inCommittedEffect()) for (var entry : scope.contexts.entrySet()) entry.getKey().commit(entry.getValue());
    }
    private Context existing() {
        Effect scope = EFFECT.get();
        if (scope != null && inCommittedEffect()) return scope.contexts.get(this);
        return (Context) TransactionSynchronizationManager.getResource(resource);
    }
    private Context context() {
        Context current = existing();
        if (current != null) return current;
        Effect scope = EFFECT.get();
        if (scope != null && inCommittedEffect()) {
            current = (Context) TransactionSynchronizationManager.getResource(resource);
            if (current != null) { commit(current); scope.borrowed.add(current); }
            else current = new Context();
            scope.contexts.put(this, current);
            return current;
        }
        if (!TransactionSynchronizationManager.isActualTransactionActive() || !TransactionSynchronizationManager.isSynchronizationActive()) return null;
        current = new Context();
        TransactionSynchronizationManager.bindResource(resource, current);
        TransactionSynchronizationManager.registerSynchronization(current);
        return current;
    }
    private Working lock(Context owner, CatalogKey key) {
        if (owner.closed) throw new IllegalStateException("catalog transaction already completed");
        Working owned = owner.entries.get(key);
        if (owned != null) return owned;
        Cell cell = cells.get(key);
        if (cell == null) {
            if (cells.size() >= capacity) throw busy();
            cell = new Cell(); cells.put(key, cell);
        }
        if (cell.owner != null && cell.owner != owner) throw busy();
        cell.owner = owner;
        Working work = new Working(cell); owner.entries.put(key, work); return work;
    }
    void lockKey(CatalogKey key) {
        Context context = context();
        if (context == null) throw new IllegalStateException("catalog mutation requires a transaction/effect scope");
        synchronized (monitor) { lock(context, key); }
    }
    private Object value(CatalogKey key, int slot) {
        Context context = existing();
        synchronized (monitor) {
            if (context != null && !context.closed) {
                Working own = context.entries.get(key);
                if (own != null) return own.values[slot];
            }
            Cell cell = cells.get(key); return cell == null ? null : cell.committed[slot];
        }
    }
    private Object write(CatalogKey key, int slot, Object value) {
        Context context = context(); boolean immediate = context == null;
        if (immediate) context = new Context();
        try {
            synchronized (monitor) {
                Working work = lock(context, key); Object previous = work.values[slot];
                work.values[slot] = value; context.dirty = true; return previous;
            }
        } finally { if (immediate) { try { commit(context); } finally { release(context); } } }
    }
    private void commit(Context context) {
        synchronized (monitor) {
            if (context.closed || !context.dirty) return;
            for (Working work : context.entries.values()) {
                for (int slot = 0; slot < 4; slot++) {
                    if (work.cell.committed[slot] == null && work.values[slot] != null) counts[slot]++;
                    else if (work.cell.committed[slot] != null && work.values[slot] == null) counts[slot]--;
                }
                work.cell.committed = work.values.clone();
            }
            context.dirty = false;
        }
    }
    private void release(Context context) {
        synchronized (monitor) {
            if (context.closed) return;
            context.closed = true;
            context.entries.forEach((key, work) -> {
                if (work.cell.owner == context) work.cell.owner = null;
                if (Arrays.stream(work.cell.committed).allMatch(Objects::isNull)) cells.remove(key, work.cell);
            });
            context.entries.clear();
        }
    }
    int retainedKeyCount() { synchronized (monitor) { return cells.size(); } }
    private static ResponseStatusException busy() { return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "service catalog is committing; retry"); }

    <V> Map<CatalogKey, V> index(int slot, UnaryOperator<V> copy) {
        if (slot < 0 || slot >= 4) throw new IllegalArgumentException("invalid catalog slot");
        return new AbstractMap<>() {
            private V copied(Object value) { @SuppressWarnings("unchecked") V typed = (V) value; return typed == null ? null : copy.apply(typed); }
            @Override public V get(Object key) { return key instanceof CatalogKey typed ? copied(value(typed, slot)) : null; }
            @Override public V put(CatalogKey key, V value) { return copied(write(Objects.requireNonNull(key), slot, value == null ? null : copy.apply(value))); }
            @Override public V remove(Object key) { return key instanceof CatalogKey typed ? copied(write(typed, slot, null)) : null; }
            @Override public int size() {
                Context context = existing();
                synchronized (monitor) {
                    int total = counts[slot];
                    if (context != null && !context.closed) for (Working work : context.entries.values()) {
                        if (work.cell.committed[slot] == null && work.values[slot] != null) total++;
                        else if (work.cell.committed[slot] != null && work.values[slot] == null) total--;
                    }
                    return total;
                }
            }
            @Override public Set<Entry<CatalogKey, V>> entrySet() {
                List<CatalogKey> keys;
                synchronized (monitor) { keys = List.copyOf(cells.keySet()); }
                List<Entry<CatalogKey, V>> entries = new ArrayList<>();
                for (CatalogKey key : keys) { V item = get(key); if (item != null) entries.add(new SimpleImmutableEntry<>(key, item)); }
                return new AbstractSet<>() {
                    @Override public int size() { return entries.size(); }
                    @Override public Iterator<Entry<CatalogKey, V>> iterator() {
                        Iterator<Entry<CatalogKey, V>> iterator = entries.iterator();
                        return new Iterator<>() {
                            Entry<CatalogKey, V> last;
                            public boolean hasNext() { return iterator.hasNext(); }
                            public Entry<CatalogKey, V> next() { return last = iterator.next(); }
                            public void remove() { if (last == null) throw new IllegalStateException(); PeerCatalogCache.this.write(last.getKey(), slot, null); last = null; }
                        };
                    }
                };
            }
        };
    }
}
