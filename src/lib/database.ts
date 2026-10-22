import { Pool } from "pg";

let pool: Pool | undefined;

export function getDatabase() {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) throw new Error("Missing environment variable: DATABASE_URL");
    pool = new Pool({
      connectionString,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
      query_timeout: 5000,
    });
    pool.on("error", (error) => console.error("[database] Idle connection failed", error));
  }
  return pool;
}
