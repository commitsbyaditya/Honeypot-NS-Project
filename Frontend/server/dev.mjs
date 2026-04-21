import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import net from "node:net";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendRoot = path.resolve(__dirname, "..");
const baseApiPort = Number(process.env.FRONTEND_API_PORT || 8787);

const nodeCmd = process.execPath;
const npmExecPath = process.env.npm_execpath;

const spawnOptions = {
  cwd: frontendRoot,
  stdio: "inherit",
  windowsHide: true,
};

function spawnNpm(args, envOverrides = {}) {
  const env = { ...process.env, ...envOverrides };

  if (npmExecPath) {
    return spawn(nodeCmd, [npmExecPath, ...args], { ...spawnOptions, env });
  }
  const fallbackOptions = {
    ...spawnOptions,
    env,
    shell: process.platform === "win32",
  };
  return spawn("npm", args, fallbackOptions);
}

async function isApiAlreadyRunning(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/health`);
    return res.ok;
  } catch {
    return false;
  }
}

async function supportsRequiredEndpoints(port) {
  try {
    const stopJobRes = await fetch(`http://127.0.0.1:${port}/api/jobs/__probe__/stop`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const stopJobText = await stopJobRes.text();
    const hasStopJob = stopJobRes.status === 404 && stopJobText.includes("Job not found");

    if (!hasStopJob) {
      return false;
    }

    const stopAllRes = await fetch(`http://127.0.0.1:${port}/api/simulation/stop-all`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });

    if (!stopAllRes.ok) {
      return false;
    }

    const payload = await stopAllRes.json();
    return payload && payload.ok === true && typeof payload.cleaned === "number";
  } catch {
    return false;
  }
}

function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(port, "127.0.0.1");
  });
}

async function findAvailablePort(startPort) {
  for (let port = startPort; port < startPort + 20; port += 1) {
    // eslint-disable-next-line no-await-in-loop
    const available = await isPortAvailable(port);
    if (available) {
      return port;
    }
  }
  return startPort;
}

const apiRunningOnBasePort = await isApiAlreadyRunning(baseApiPort);
const baseApiCompatible = apiRunningOnBasePort ? await supportsRequiredEndpoints(baseApiPort) : false;

let apiPort = baseApiPort;
if (apiRunningOnBasePort && !baseApiCompatible) {
  const fallbackPort = await findAvailablePort(baseApiPort + 1);
  apiPort = fallbackPort;
  // eslint-disable-next-line no-console
  console.log(`[dev] Existing API on ${baseApiPort} is outdated. Launching compatible API on port ${apiPort}.`);
}

const runtimeEnv = { FRONTEND_API_PORT: String(apiPort) };

let api = null;
if (apiPort === baseApiPort && baseApiCompatible) {
  // eslint-disable-next-line no-console
  console.log(`[dev] API bridge already running on port ${apiPort}; reusing existing process.`);
} else {
  api = spawnNpm(["run", "dev:api"], runtimeEnv);
}

const client = spawnNpm(["run", "dev:client"], runtimeEnv);

let shuttingDown = false;

function shutdown() {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  try {
    api?.kill();
  } catch {
    // no-op
  }
  try {
    client.kill();
  } catch {
    // no-op
  }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

api?.on("close", (code) => {
  if (!shuttingDown) {
    // eslint-disable-next-line no-console
    console.error(`[dev] API bridge exited with code ${code}. Shutting down client.`);
    shutdown();
  }
});
client.on("close", () => shutdown());
