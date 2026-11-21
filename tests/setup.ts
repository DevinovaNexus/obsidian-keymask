if (typeof window === "undefined") {
  (globalThis as unknown as { window: unknown }).window = {
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    get crypto() {
      return globalThis.crypto;
    },
    addEventListener: () => {},
    removeEventListener: () => {},
  };
}
