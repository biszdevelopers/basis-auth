import { BrowserRouter, Route, Routes } from "react-router-dom";
import { useCallback, useEffect, useState } from "react";
import { LoginCard, Status, StatusError } from "./components/LoginCard";
import { ToastProvider } from "./components/ui/toast";

const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

const INTERACTION_ATTEMPTS_KEY = "basis_interaction_attempts";
const MAX_INTERACTION_RELOADS = 2;

export function App() {



  const [hold, setHold] = useState(true);
  const [_status, setStatus] = useState<Status>({loading: true, page: "none", login: undefined});

  const animate = (page: string, error?: StatusError, loginContent?: any) => {
    const waitForProfile = page === "consent";
    setStatus({loading: waitForProfile, error, page: "none"});
    setTimeout(() => {
      setStatus({loading: waitForProfile, error, page, login: loginContent});
    }, 500)
  }

  const profileReady = useCallback(() => {
    setStatus((status) => status.page === "consent" ? { ...status, loading: false } : status);
  }, []);

  const reloadOrFail = (res: Response) => {
    const attempts = Number(sessionStorage.getItem(INTERACTION_ATTEMPTS_KEY) ?? 0) + 1;
    sessionStorage.setItem(INTERACTION_ATTEMPTS_KEY, String(attempts));
    if (attempts > MAX_INTERACTION_RELOADS) {
      animate("content", {
        status: res.status,
        error: "invalid_request",
        code: 2400,
        error_description: "The sign-in session is unavailable. Reload the page to try again.",
      });
      return;
    }
    window.location.replace("/oauth/authorize");
  };

  const resetToLogin = async () => {
    const res = await fetch("/oauth/interaction", { headers: { Accept: "application/json" } });
    if (!res.ok) {
      reloadOrFail(res);
      return;
    }
    sessionStorage.removeItem(INTERACTION_ATTEMPTS_KEY);
    const loginContent = await res.json();
    await delay(500);
    setStatus({ loading: false, page: "none", login: undefined });
    animate(loginContent.prompt, undefined, loginContent);
  };
  
  useEffect(() => {

    

    (async () => {


      const raw = document.cookie
        .split("; ")
        .find((c) => c.startsWith("basis_bridge_error="))
        ?.split("=")[1];

      if (raw) {

        const error = JSON.parse(atob(decodeURIComponent(raw)));
        await delay(300);
        animate( "content", error)
        console.log(error)
        // clear it so it doesn't linger
        document.cookie = "basis_bridge_error=; path=/oauth; max-age=0";

        return;
      }


      const res = await fetch("/oauth/interaction", { headers: { Accept: "application/json" } });
      if (!res.ok) {
        // No interaction cookie — restart the flow. Bounded: if cookies are
        // being dropped (or the backend is down) this would otherwise reload
        // /oauth/authorize forever, so fail onto the error screen instead.
        reloadOrFail(res);
        return;
      }
      sessionStorage.removeItem(INTERACTION_ATTEMPTS_KEY);
      const loginContent = await res.json()
      await delay(300);

      animate(loginContent.prompt, undefined, loginContent)
    })();
    
  }, []);

  return (
    <ToastProvider>
      <main className="flex min-h-screen items-center justify-center">
        <LoginCard stat={_status} onLogout={resetToLogin} onProfileReady={profileReady}></LoginCard>
      </main>
    </ToastProvider>
  );
}
