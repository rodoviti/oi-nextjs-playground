import { createClient } from "redis";

let connection: ReturnType<typeof connect> | undefined;

async function connect() {
  const url = process.env.REDIS_URL;
  if (!url) throw new Error("Missing environment variable: REDIS_URL");
  const client = createClient({
    url,
    disableOfflineQueue: true,
    socket: { connectTimeout: 3000, reconnectStrategy: false },
  });
  client.on("error", (error) => console.error("[redis] Connection failed", error));
  await client.connect();
  return client;
}

export async function getRedis() {
  connection ??= connect();
  try {
    const client = await connection;
    if (!client.isReady) throw new Error("Redis is unavailable");
    return client.withAbortSignal(AbortSignal.timeout(3000));
  } catch (error) {
    connection = undefined;
    throw error;
  }
}
