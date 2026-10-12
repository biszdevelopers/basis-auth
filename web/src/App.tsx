import { BrowserRouter, Route, Routes } from "react-router-dom";
import { useCallback, useEffect, useState } from "react";
import { LoginCard, Status, StatusError, type PublicClientInformation } from "./components/LoginCard";
import { ToastProvider } from "./components/ui/toast";

const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

const INTERACTION_ATTEMPTS_KEY = "basis_interaction_attempts";
const MAX_INTERACTION_RELOADS = 2;

function isPublicClientInformation(value: unknown): value is PublicClientInformation {
  if (!value || typeof value !== "object") return false;
  const client = value as Record<string, unknown>;
  if (typeof client.id !== "string" || typeof client.name !== "string" || !Array.isArray(client.owners)) {
    return false;
  }
  return client.owners.every((owner) => {
    if (!owner || typeof owner !== "object") return false;
    const candidate = owner as Record<string, unknown>;
    return typeof candidate.id === "string" &&
      typeof candidate.name === "string" &&
      typeof candidate.email === "string" &&
      (typeof candidate.picture === "string" || candidate.picture === null);
  });
}

export function App() {



  const [hold, setHold] = useState(true);
  const [_status, setStatus] = useState<Status>({loading: true, page: "none", login: undefined});
  const [clientInformation, setClientInformation] = useState<PublicClientInformation>();

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
    let res = await fetch("/oauth/interaction", { headers: { Accept: "application/json" } });
    if (!res.ok) {
      const authorizationUri = window.location.pathname + window.location.search;
      const authorization = await fetch(authorizationUri, { headers: { Accept: "text/html" } });
      if (authorization.ok) {
        res = await fetch("/oauth/interaction", { headers: { Accept: "application/json" } });
      }
      if (!authorization.ok || !res.ok) {
        animate("content", {
          status: res.status,
          error: "invalid_request",
          code: 2400,
          error_description: "The sign-in session is unavailable. Reload the page to try again.",
        });
        return;
      }
    }
    sessionStorage.removeItem(INTERACTION_ATTEMPTS_KEY);
    const loginContent = await res.json();
    await delay(500);
    setStatus({ loading: false, page: "none", login: undefined });
    animate(loginContent.prompt, undefined, loginContent);
  };
  
  useEffect(() => {
    const requestedClientId = new URLSearchParams(window.location.search).get("client_id");
    if (requestedClientId) {
      void fetch(`/oauth/clients/${encodeURIComponent(requestedClientId)}`, {
        headers: { Accept: "application/json" },
      })
        .then((response) => response.ok ? response.json() as Promise<unknown> : undefined)
        .then((value) => {
          if (isPublicClientInformation(value) && value.id === requestedClientId) {
            setClientInformation(value);
          }
        })
        .catch(() => undefined);
    }

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

  const visibleClient = clientInformation &&
      (!_status.login || _status.login.clientId === clientInformation.id)
    ? clientInformation
    : undefined;

  return (
    <ToastProvider>
      <main className="flex min-h-dvh w-full items-center justify-center sm:min-h-screen">
        <LoginCard stat={_status} client={visibleClient} onLogout={resetToLogin} onProfileReady={profileReady}></LoginCard>
      </main>
    </ToastProvider>
  );
}
