import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { X } from "lucide-react";
import { Toast } from "radix-ui";

interface ToastMessage {
  title: string;
  description?: string;
}

const ToastContext = createContext<{ toast: (message: ToastMessage) => void } | undefined>(undefined);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used within ToastProvider");
  return context;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<ToastMessage>();
  const [open, setOpen] = useState(false);

  const toast = useCallback((next: ToastMessage) => {
    setMessage(next);
    setOpen(true);
  }, []);

  return (
    <Toast.Provider duration={5_000}>
      <ToastContext.Provider value={{ toast }}>
        {children}
      </ToastContext.Provider>
      <Toast.Root
        open={open}
        onOpenChange={setOpen}
        onAnimationEnd={(event) => {
          if (event.currentTarget.dataset.state === "closed") setMessage(undefined);
        }}
        className="toast-slide grid w-full max-w-sm grid-cols-[1fr_auto] gap-x-4 rounded-xl border border-destructive/30 bg-card p-4 text-card-foreground shadow-lg"
      >
        <div className="grid gap-1">
          <Toast.Title className="text-sm font-semibold text-destructive">{message?.title}</Toast.Title>
          {message?.description && (
            <Toast.Description className="text-sm text-muted-foreground">
              {message.description}
            </Toast.Description>
          )}
        </div>
        <Toast.Close asChild>
          <button className="rounded-sm text-muted-foreground hover:text-foreground" aria-label="Close notification">
            <X className="size-4" />
          </button>
        </Toast.Close>
      </Toast.Root>
      <Toast.Viewport className="fixed right-4 top-4 z-50 flex w-[calc(100%-2rem)] max-w-sm flex-col gap-2 outline-none" />
    </Toast.Provider>
  );
}
