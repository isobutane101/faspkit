import { createFaspApp } from "./app.js";
import { defaultStore } from "./store.js";

/**
 * `npx faspkit` — start a FASP.
 *
 * The startup banner is doing real work: it prints the admin URL and, on first
 * run, the generated admin token. Someone starting this for the first time
 * should not have to read documentation to find out how to get in.
 */

const HELP = `faspkit — run a Fediverse Auxiliary Service Provider

Usage
  npx faspkit [options]

Options
  --port <n>          Port to listen on (default 3000, or $PORT)
  --base-url <url>    Public URL other servers reach this FASP at.
                      Must match exactly — it is part of every signature.
  --name <name>       Name shown to instance admins (default "faspkit")
  --username <name>   Actor username for WebFinger (default "faspkit")
  --data <dir>        Where to store keys and state (default ./data)
  --no-admin          Do not serve the admin dashboard
  --help              Show this

Environment
  PORT, FASP_BASE_URL, FASP_NAME, FASP_USERNAME, FASP_CONTACT_EMAIL,
  FASPKIT_DATA, FASPKIT_SECRET, FASPKIT_ADMIN_TOKEN

  FASPKIT_SECRET encrypts private keys at rest and is REQUIRED when
  NODE_ENV=production. Back it up with your data directory: without it the
  stored keys cannot be read.
`;

interface ParsedArgs {
  help: boolean;
  admin: boolean;
  port?: number;
  baseUrl?: string;
  name?: string;
  username?: string;
  data?: string;
}

export function parseArgs(argv: string[]): ParsedArgs | { error: string } {
  const out: ParsedArgs = { help: false, admin: true };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`${arg} needs a value`);
      return v;
    };
    try {
      switch (arg) {
        case "--help": case "-h": out.help = true; break;
        case "--no-admin": out.admin = false; break;
        case "--port": {
          const n = Number(value());
          if (!Number.isInteger(n) || n < 1 || n > 65535) return { error: "--port must be a port number" };
          out.port = n;
          break;
        }
        case "--base-url": out.baseUrl = value(); break;
        case "--name": out.name = value(); break;
        case "--username": out.username = value(); break;
        case "--data": out.data = value(); break;
        default: return { error: `unknown option ${arg}` };
      }
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }
  return out;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const parsed = parseArgs(argv);
  if ("error" in parsed) {
    console.error(`faspkit: ${parsed.error}\n\n${HELP}`);
    return 1;
  }
  if (parsed.help) {
    console.log(HELP);
    return 0;
  }
  if (parsed.data) process.env.FASPKIT_DATA = parsed.data;

  // Whether the token already existed decides whether we print it below.
  const hadToken = !!(await defaultStore.getSetting("adminToken")) || !!process.env.FASPKIT_ADMIN_TOKEN;

  let fasp;
  try {
    fasp = await createFaspApp({
      port: parsed.port,
      baseUrl: parsed.baseUrl,
      name: parsed.name,
      username: parsed.username,
      admin: parsed.admin,
    });
  } catch (err) {
    console.error(`faspkit: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }

  const { port, close } = await fasp.listen();
  const { config } = fasp;

  console.log(`\n  ${config.name} is running`);
  console.log(`  ${"─".repeat(46)}`);
  console.log(`  Public URL   ${config.baseUrl}`);
  console.log(`  Actor        ${config.baseUrl}/actor`);
  if (parsed.admin) console.log(`  Dashboard    http://localhost:${port}/admin`);
  if (parsed.admin && !hadToken) {
    console.log(`\n  Admin token  ${config.adminToken}`);
    console.log(`  Shown once. It is stored in your data directory.`);
  } else if (parsed.admin) {
    console.log(`  Admin token  (set previously — see your data directory or FASPKIT_ADMIN_TOKEN)`);
  }
  if (!process.env.FASPKIT_SECRET) {
    console.log(`\n  Warning: FASPKIT_SECRET is not set, so private keys are stored unencrypted.`);
  }
  if (config.baseUrl.includes("localhost")) {
    console.log(`\n  Note: localhost is fine for a look around, but a fediverse server`);
    console.log(`  must be able to reach FASP_BASE_URL to register. Use a tunnel.`);
  }
  console.log(`\n  Next: open the dashboard and connect a fediverse server.\n`);

  const shutdown = async () => {
    console.log("\n  Shutting down…");
    await close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  return 0;
}
