/**
 * A worker hosting one of the WebAssembly modules, called request by request.
 *
 * `wasm32-unknown-unknown` aborts on a panic: the instance traps and every
 * later call into it fails. So a worker whose module traps is terminated, the
 * requests it had are rejected with the reason, and the next request starts
 * a fresh one.
 */
export interface WorkerHost<Req, Res> {
  /**
   * With `timeoutMs`, a request not answered in time terminates the worker
   * (a damaged file can keep a decoder busy long after anyone waits for it)
   * and is rejected; so are the others it had.
   */
  call(request: Req, transfer?: Transferable[], timeoutMs?: number): Promise<Res>;
  destroy(): void;
}

type Reply<Res> = { id: number; ok: true; value: Res } | { id: number; ok: false; error: string; fatal?: boolean };

export function createWorkerHost<Req, Res>(start: () => Worker): WorkerHost<Req, Res> {
  let worker: Worker | null = null;
  let destroyed = false;
  let next = 1;
  const pending = new Map<number, { resolve: (v: Res) => void; reject: (e: Error) => void }>();

  const stop = (reason: string) => {
    worker?.terminate();
    worker = null;
    for (const p of pending.values()) p.reject(new Error(reason));
    pending.clear();
  };

  const ensure = () => {
    if (worker) return worker;
    const w = start();
    w.onmessage = (e: MessageEvent<Reply<Res>>) => {
      const reply = e.data;
      const p = pending.get(reply.id);
      if (!p) return;
      pending.delete(reply.id);
      if (reply.ok) p.resolve(reply.value);
      else {
        p.reject(new Error(reply.error));
        if (reply.fatal) stop(reply.error);
      }
    };
    w.onerror = (e) => stop(e.message || "the engine stopped");
    worker = w;
    return w;
  };

  return {
    call(request, transfer = [], timeoutMs) {
      // A controller left over from a closed session must not start a
      // worker nothing will terminate.
      if (destroyed) return Promise.reject(new Error("destroyed"));
      return new Promise<Res>((resolve, reject) => {
        const id = next++;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const settle = () => clearTimeout(timer);
        pending.set(id, {
          resolve: (v) => (settle(), resolve(v)),
          reject: (e) => (settle(), reject(e)),
        });
        if (timeoutMs !== undefined) {
          timer = setTimeout(() => {
            if (pending.has(id)) stop(`no answer within ${timeoutMs} ms`);
          }, timeoutMs);
        }
        ensure().postMessage({ id, request }, transfer);
      });
    },
    destroy: () => {
      destroyed = true;
      stop("destroyed");
    },
  };
}

/**
 * The worker side: answers each request with `handle`. A `WebAssembly.RuntimeError`
 * is a trap, after which the instance is unusable: it is reported fatal, so
 * the host replaces the worker.
 */
export function serve<Req, Res>(handle: (request: Req) => Promise<{ value: Res; transfer?: Transferable[] }>): void {
  const scope = self as unknown as {
    postMessage(message: unknown, transfer?: Transferable[]): void;
    onmessage: ((e: MessageEvent<{ id: number; request: Req }>) => void) | null;
  };
  let queue: Promise<void> = Promise.resolve();
  scope.onmessage = (e) => {
    const { id, request } = e.data;
    queue = queue.then(async () => {
      try {
        const { value, transfer } = await handle(request);
        scope.postMessage({ id, ok: true, value }, transfer ?? []);
      } catch (error) {
        const fatal = typeof WebAssembly !== "undefined" && error instanceof WebAssembly.RuntimeError;
        scope.postMessage({ id, ok: false, error: error instanceof Error ? error.message : String(error), fatal });
      }
    });
  };
}
