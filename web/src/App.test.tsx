// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("renders the loading state", () => {
  vi.stubGlobal("fetch", vi.fn(() => new Promise(() => undefined)));
  render(<App />);
  expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
});

it("keeps loading the consent page until the profile is rendered", async () => {
  let resolveProfile!: (response: Response) => void;
  const profileResponse = new Promise<Response>((resolve) => {
    resolveProfile = resolve;
  });
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        uid: "request-id",
        prompt: "consent",
        client: { name: "Example app" },
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
});

it("stops reloading and shows an error when the interaction stays unavailable", async () => {
  sessionStorage.clear();
  const replaceMock = vi.fn();
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
    expect(
      await screen.findByText(/sign-in session is unavailable/),
    ).toBeInTheDocument();
    expect(replaceMock).toHaveBeenCalledTimes(2);
  } finally {
    sessionStorage.clear();
    Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
  }
});
