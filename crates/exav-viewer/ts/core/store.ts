/** An observable value. Controllers are stores so that any UI can follow them. */
export interface Store<T> {
  get(): T;
  /** Called on every change. Returns the unsubscribe function. */
  subscribe(listener: (value: T) => void): () => void;
}

export interface WritableStore<T> extends Store<T> {
  set(value: T): void;
  update(change: (value: T) => T): void;
}

/** A store holding `initial`. `set` notifies only when the value changes (`Object.is`). */
export function writable<T>(initial: T): WritableStore<T> {
  let value = initial;
  const listeners = new Set<(value: T) => void>();
  const set = (next: T) => {
    if (Object.is(next, value)) return;
    value = next;
    for (const listener of [...listeners]) listener(value);
  };
  return {
    get: () => value,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    set,
    update: (change) => set(change(value)),
  };
}

/**
 * A store derived from another, recomputed when its source changes, and
 * only then: `get` returns the same value until it does, which React's
 * `useSyncExternalStore` requires of a snapshot.
 */
export function derived<A, B>(source: Store<A>, map: (value: A) => B): Store<B> {
  let last: { from: A; to: B } | null = null;
  const get = () => {
    const from = source.get();
    if (!last || !Object.is(last.from, from)) last = { from, to: map(from) };
    return last.to;
  };
  return {
    get,
    subscribe: (listener) => source.subscribe(() => listener(get())),
  };
}
