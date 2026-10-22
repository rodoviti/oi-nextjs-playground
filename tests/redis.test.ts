import { afterEach, beforeEach, expect, it, vi } from "vitest";

const client = vi.hoisted(() => ({
  isReady: true,
  connect: vi.fn(),
  on: vi.fn(),
  withAbortSignal: vi.fn((signal: AbortSignal) => ({ signal })),
}));
vi.mock("redis", () => ({ createClient: () => client }));

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  vi.stubEnv("REDIS_URL", "redis://localhost:6379");
  client.isReady = true;
  client.connect.mockResolvedValue(undefined);
});
afterEach(() => vi.unstubAllEnvs());

it("reuses the connection but gives each operation a fresh timeout signal", async () => {
  const { getRedis } = await import("../src/lib/redis");
  const first = await getRedis();
  const second = await getRedis();
  expect(client.connect).toHaveBeenCalledTimes(1);
  expect(client.withAbortSignal).toHaveBeenCalledTimes(2);
  expect(client.withAbortSignal.mock.calls[0][0]).toBeInstanceOf(AbortSignal);
  expect(client.withAbortSignal.mock.calls[1][0]).not.toBe(client.withAbortSignal.mock.calls[0][0]);
  expect(first).not.toBe(second);
});

it("fails explicitly when Redis has disconnected", async () => {
  const { getRedis } = await import("../src/lib/redis");
  client.isReady = false;
  await expect(getRedis()).rejects.toThrow("Redis is unavailable");
});
