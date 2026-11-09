"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ArenaEvent, Health, ResultBrief, WS_BASE, api } from "./api";

/** Fetch once (and on demand) with loading/error state. */
export function useFetch<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (e: any) {
      setError(e?.message || "request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, setData };
}

/** Poll the API health endpoint. */
export function useApiHealth(intervalMs = 8000) {
  const [health, setHealth] = useState<Health | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const h = await api.health();
        if (alive) {
          setHealth(h);
          setOnline(true);
        }
      } catch {
        if (alive) setOnline(false);
      }
    };
    tick();
    const t = setInterval(tick, intervalMs);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [intervalMs]);
  return { health, online };
}

/** Subscribe to a running engagement's WebSocket stream. */
export function useEngagementStream(id: string | null) {
  const [events, setEvents] = useState<ArenaEvent[]>([]);
  const [status, setStatus] = useState<"idle" | "connecting" | "live" | "done" | "error">("idle");
  const [result, setResult] = useState<(ResultBrief & { status?: string }) | null>(null);

  useEffect(() => {
    if (!id) return;
    setEvents([]);
    setResult(null);
    setStatus("connecting");
    const ws = new WebSocket(`${WS_BASE}/ws/${id}`);
    const buffer: ArenaEvent[] = [];
    let received = 0;
    let flush: ReturnType<typeof setTimeout> | null = null;
    const push = () => {
      flush = null;
      const batch = buffer.splice(0);
      if (batch.length) setEvents((prev) => prev.concat(batch));
    };
    ws.onopen = () => setStatus("live");
    ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      if (msg.type === "event") {
        received++;
        buffer.push(msg.event);
        if (!flush) flush = setTimeout(push, 60); // batch renders
      } else if (msg.type === "done") {
        push();
        setResult({ ...msg.result, status: msg.status });
        ws.close();
        if (received === 0) {
          // History loaded from disk has no in-memory stream; fetch the log.
          api.events(id).then((evs) => setEvents(evs)).catch(() => {}).finally(() => setStatus("done"));
        } else {
          setStatus("done");
        }
      } else if (msg.type === "error") {
        setStatus("error");
      }
    };
    ws.onerror = () => setStatus("error");
    return () => {
      if (flush) clearTimeout(flush);
      ws.close();
    };
  }, [id]);

  return { events, status, result };
}

/** Tick-based replay player. */
export function useReplay(lastTick: number, opts: { msPerTick?: number } = {}) {
  const base = opts.msPerTick ?? 900;
  const [tick, setTick] = useState(lastTick);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  useEffect(() => setTick(lastTick), [lastTick]);

  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setTick((x) => {
        if (x >= lastTick) {
          setPlaying(false);
          return x;
        }
        return x + 1;
      });
    }, base / speed);
    return () => clearInterval(t);
  }, [playing, speed, lastTick, base]);

  const play = useCallback(() => {
    setTick((x) => (x >= lastTick ? -1 : x));
    setPlaying(true);
  }, [lastTick]);

  return {
    tick,
    playing,
    speed,
    setSpeed,
    play,
    pause: () => setPlaying(false),
    toggle: () => (playing ? setPlaying(false) : play()),
    seek: (t: number) => {
      setPlaying(false);
      setTick(Math.max(-1, Math.min(lastTick, t)));
    },
    step: (d: number) => {
      setPlaying(false);
      setTick((x) => Math.max(-1, Math.min(lastTick, x + d)));
    },
  };
}

/** Observe an element's width (charts size to their card). */
export function useWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return { ref, width };
}

/** localStorage-backed state; falls back to memory when storage is blocked. */
export function useLocalState<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(initial);
  useEffect(() => {
    try {
      const raw = localStorage.getItem(key);
      if (raw) setValue(JSON.parse(raw));
    } catch {}
  }, [key]);
  const set = useCallback(
    (v: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const next = typeof v === "function" ? (v as (p: T) => T)(prev) : v;
        try {
          localStorage.setItem(key, JSON.stringify(next));
        } catch {}
        return next;
      });
    },
    [key]
  );
  return [value, set] as const;
}
