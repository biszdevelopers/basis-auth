// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";
import { LoginCard } from "./components/LoginCard";
import { ToastProvider } from "./components/ui/toast";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.pushState({}, "", "/");
});

it("renders the loading state", () => {
  vi.stubGlobal("fetch", vi.fn(() => new Promise(() => undefined)));
  render(<App />);
  expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
});

it("logs out from the error message with a primary text button", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true } as Response);
  const onLogout = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("fetch", fetchMock);

  render(
    <ToastProvider>
      <LoginCard
        stat={{
          loading: false,
          page: "content",
          error: {
            status: 403,
            error: "access_denied",
            code: 0,
            error_description: "This account is not allowed to sign in to this application.",
          },
        }}
        onLogout={onLogout}
        onProfileReady={() => undefined}
      />
    </ToastProvider>,
  );

  const logoutButton = screen.getByRole("button", { name: /Log out/ });
  expect(logoutButton).toHaveAttribute("data-variant", "default");
  fireEvent.click(logoutButton);

  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/oauth/logout", {
    method: "POST",
    headers: { Accept: "application/json" },
  }));
  expect(onLogout).toHaveBeenCalledOnce();
});

it("does not show logout for errors unrelated to the user account", () => {
  const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  try {
    render(
      <ToastProvider>
        <LoginCard
          stat={{
            loading: false,
            page: "content",
            error: {
              status: 400,
              error: "invalid_request",
              code: 2400,
              error_description: "The authorization request is invalid.",
            },
          }}
          onLogout={vi.fn()}
          onProfileReady={() => undefined}
        />
      </ToastProvider>,
    );

    expect(screen.queryByRole("button", { name: /Log out/ })).not.toBeInTheDocument();
    expect(screen.queryByText("The authorization request is invalid. (2400)")).not.toBeInTheDocument();
    expect(errorSpy).toHaveBeenCalledWith("The authorization request is invalid. (2400)");
  } finally {
    errorSpy.mockRestore();
  }
});

it("restarts a blocked authorization in place after logout", async () => {
  const authorizationUri = "/oauth/authorize?client_id=client&state=state";
  window.history.pushState({}, "", authorizationUri);
  const error = {
    status: 403,
    error: "access_denied",
    code: 0,
    error_description: "This account is not allowed to sign in to this application.",
  };
  document.cookie = `basis_bridge_error=${encodeURIComponent(btoa(JSON.stringify(error)))}`;
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "client", name: "Example app", owners: [] }),
    } as Response)
    .mockResolvedValueOnce({ ok: true } as Response)
    .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
    .mockResolvedValueOnce({ ok: true } as Response)
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        uid: "new-request-id",
        prompt: "login",
        clientId: "client",
        scopes: ["openid"],
        resources: [],
        csrfToken: "csrf-token",
        microsoftConfigured: true,
      }),
    } as Response);
  vi.stubGlobal("fetch", fetchMock);

  try {
    render(<App />);
    await screen.findByRole("button", { name: /Log out/ });
    expect(fetchMock).toHaveBeenNthCalledWith(1, "/oauth/clients/client", {
      headers: { Accept: "application/json" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Why am I here?" }));
    expect(await screen.findByText("Example app")).toBeInTheDocument();
    fireEvent.pointerDown(document.body);
    await waitFor(() => expect(screen.queryByText("Example app")).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Log out/ }));

    await waitFor(() => expect(fetchMock).toHaveBeenNthCalledWith(4, authorizationUri, {
      headers: { Accept: "text/html" },
    }));
    expect(fetchMock).toHaveBeenNthCalledWith(5, "/oauth/interaction", {
      headers: { Accept: "application/json" },
    });
    expect(window.location.pathname + window.location.search).toBe(authorizationUri);
    expect(await screen.findByText("Example app", {}, { timeout: 1500 })).toBeInTheDocument();
  } finally {
    document.cookie = "basis_bridge_error=; max-age=0";
    window.history.pushState({}, "", "/");
  }
});

it("shows a scrollable owner list and copies an owner email", async () => {
  const copy = vi.fn().mockResolvedValue(undefined);
  const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: copy },
  });

  try {
    render(
      <ToastProvider>
        <LoginCard
          stat={{
            loading: false,
            page: "content",
            error: {
              status: 403,
              error: "access_denied",
              code: 0,
              error_description: "This account is not allowed to sign in to this application.",
            },
          }}
          client={{
            id: "client",
            name: "Example app",
            owners: [
              {
                id: "owner-one",
                name: "Owner One",
                email: "owner@example.test",
                picture: "/api/picture/owner-one",
              },
              {
                id: "owner-two",
                name: "Owner Two",
                email: "second@example.test",
                picture: null,
              },
            ],
          }}
          onLogout={vi.fn()}
          onProfileReady={() => undefined}
        />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: /application provider/ }));
    const ownerList = await screen.findByRole("list", { name: "Application owners" });
    expect(ownerList).toHaveClass("max-h-48", "overflow-y-auto");
    expect(screen.getByText("Owner One")).toBeInTheDocument();
    expect(screen.getByText("second@example.test")).toHaveClass("text-muted-foreground");
    expect(document.querySelector('img[src="/api/picture/owner-one"]')).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy owner@example.test" }));
    await waitFor(() => expect(copy).toHaveBeenCalledWith("owner@example.test"));
  } finally {
    if (clipboardDescriptor) {
      Object.defineProperty(navigator, "clipboard", clipboardDescriptor);
    } else {
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    }
  }
});

it("keeps the Why am I here copy generic when client metadata is unavailable", async () => {
  render(
    <ToastProvider>
      <LoginCard
        stat={{
          loading: false,
          page: "content",
          error: {
            status: 403,
            error: "access_denied",
            code: 0,
            error_description: "This account is not allowed to sign in to this application.",
          },
        }}
        onLogout={vi.fn()}
        onProfileReady={() => undefined}
      />
    </ToastProvider>,
  );

  fireEvent.click(screen.getByRole("button", { name: "Why am I here?" }));
  expect(await screen.findByText(/is used as a SSO/)).toBeInTheDocument();
  expect(screen.queryByText("Example app")).not.toBeInTheDocument();
});

it("keeps loading the consent page until the profile is rendered", async () => {
  window.history.pushState({}, "", "/oauth/authorize?client_id=client");
  let resolveProfile!: (response: Response) => void;
  const profileResponse = new Promise<Response>((resolve) => {
    resolveProfile = resolve;
  });
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "client", name: "Example app", owners: [] }),
    })
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        uid: "request-id",
        prompt: "consent",
        clientId: "client",
        scopes: ["openid"],
        resources: [],
        accountId: "user-id",
        csrfToken: "csrf-token",
        microsoftConfigured: true,
      }),
    })
    .mockReturnValueOnce(profileResponse);
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/me"), { timeout: 1500 });
  expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
  expect(screen.queryByText("person@example.test")).not.toBeInTheDocument();

  await act(async () => {
    resolveProfile({
      ok: true,
      json: async () => ({
        name: "Example Person",
        email: "person@example.test",
        picture: null,
      }),
    } as Response);
  });

  expect(await screen.findByText("person@example.test")).toBeInTheDocument();
  expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
  expect(screen.getByTestId("main-content")).toHaveClass("opacity-0");
  await waitFor(
    () => expect(screen.queryByRole("status", { name: "Loading" })).not.toBeInTheDocument(),
    { timeout: 1000 },
  );
  expect(screen.getByTestId("main-content")).toHaveClass("opacity-100");
  expect(screen.getByText("Example app")).toBeInTheDocument();

  const whyButton = screen.getByRole("button", { name: "Why am I here?" });
  fireEvent.click(whyButton);
  expect(await screen.findByRole("link", { name: /Find out more about DevConnect/ })).toBeInTheDocument();
  fireEvent.pointerDown(document.body);
  await waitFor(() => {
    expect(screen.queryByRole("link", { name: /Find out more about DevConnect/ })).not.toBeInTheDocument();
  });
});

it("stops reloading and logs the error when the interaction stays unavailable", async () => {
  sessionStorage.clear();
  const replaceMock = vi.fn();
  const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const originalLocation = window.location;
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { replace: replaceMock },
  });
  vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 400 }) as Response));

  try {
    const first = render(<App />);
    await waitFor(() => expect(replaceMock).toHaveBeenCalledTimes(1));
    first.unmount();

    const second = render(<App />);
    await waitFor(() => expect(replaceMock).toHaveBeenCalledTimes(2));
    second.unmount();

    render(<App />);
    await waitFor(() => expect(errorSpy).toHaveBeenCalledWith(
      "The sign-in session is unavailable. Reload the page to try again. (2400)",
    ));
    expect(screen.queryByText(/sign-in session is unavailable/)).not.toBeInTheDocument();
    expect(replaceMock).toHaveBeenCalledTimes(2);
  } finally {
    sessionStorage.clear();
    errorSpy.mockRestore();
    Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
  }
});
