import { readdir, readFile } from "node:fs/promises";
import { getDatabase } from "../src/lib/database";

async function main() {
  const pool = getDatabase();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(617204198)");
    await client.query(`CREATE TABLE IF NOT EXISTS app_migrations (
      name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const directory = new URL("../migrations/", import.meta.url);
    for (const name of (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort()) {
      const applied = await client.query("SELECT 1 FROM app_migrations WHERE name = $1", [name]);
      if (applied.rowCount) continue;
      await client.query(await readFile(new URL(name, directory), "utf8"));
      await client.query("INSERT INTO app_migrations (name) VALUES ($1)", [name]);
      console.log(`[database] Applied ${name}`);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error("[database] Migration failed", error);
  process.exitCode = 1;
});
