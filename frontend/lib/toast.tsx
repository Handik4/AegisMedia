"use client";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { CheckCircle2, AlertTriangle, X } from "lucide-react";

type Kind = "ok" | "error" | "info";
interface Toast {
  id: number;
  kind: Kind;
  text: string;
  href?: string;
}
const Ctx = createContext<(kind: Kind, text: string, href?: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const notify = useCallback((kind: Kind, text: string, href?: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, kind, text, href }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 9000 : 5500);
  }, []);
  return (
    <Ctx.Provider value={notify}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-50 flex flex-col items-center gap-2 px-4" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`pointer-events-auto flex max-w-xl items-start gap-3 rounded-lg border px-4 py-3 text-sm shadow-xl ${
              t.kind === "error"
                ? "border-[color:var(--alarm)]/50 bg-[color:var(--alarm-dim)]"
                : "border-[color:var(--seal)]/40 bg-[color:var(--ink-3)]"
            }`}
          >
            {t.kind === "error" ? (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--alarm)]" aria-hidden />
            ) : (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--seal)]" aria-hidden />
            )}
            <span className="break-words">
              {t.text}
              {t.href && (
                <>
                  {" "}
                  <a className="underline underline-offset-2" href={t.href} target="_blank" rel="noreferrer">
                    view
                  </a>
                </>
              )}
            </span>
            <button
              aria-label="Dismiss"
              className="ml-2 text-[color:var(--muted)] hover:text-[color:var(--paper)]"
              onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export const useToast = () => useContext(Ctx);
