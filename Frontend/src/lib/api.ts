export type ScreenAttackTypeRaw = "ssh" | "portscan" | "dns" | "arp" | "icmp" | "unknown";
export type SimulationAttackType = "all" | "ssh" | "portscan" | "dns" | "arp" | "icmp";

export interface AttackSessionRow {
  id: string;
  timestamp: string;
  srcIp: string;
  attackType: string;
  attackTypeRaw: ScreenAttackTypeRaw;
  duration: number;
  packetsCount: number;
  severity: "low" | "medium" | "high" | "critical";
  detected: boolean;
  predictedLabel: string;
}

export interface DataSessionsResponse {
  sessions: AttackSessionRow[];
  total: number;
}

export interface DashboardStatsResponse {
  totalAttacks: number;
  detectionRate: number;
  avgResponseTime: number;
  activeThreats: number;
  attackDistribution: Array<{ name: string; value: number }>;
  topAttackerIPs: Array<{ ip: string; count: number }>;
  recentSessions: Array<{
    id: string;
    timestamp: string;
    srcIp: string;
    attackType: string;
    severity: "low" | "medium" | "high" | "critical";
    duration: number;
  }>;
}

export interface JobStatus {
  id: string;
  type: string;
  status: "running" | "completed" | "failed";
  startedAt: string;
  endedAt: string | null;
  exitCode: number | null;
  logs: string[];
  pid: number | null;
}

export interface StopJobResponse {
  ok: boolean;
  stopped: boolean;
  cleaned: number;
  status: "running" | "completed" | "failed";
}

export interface StopAllSimulationsResponse {
  ok: boolean;
  stoppedJobs: number;
  stopped: boolean;
  cleaned: number;
}

export interface HealthResponse {
  dataExists: boolean;
  modelExists: boolean;
  isAdmin: boolean;
  apiProcessIsAdmin?: boolean;
  adminDerivedFromRuntime?: boolean;
  platform: string;
  canRequestAdmin: boolean;
  adminHint: string;
  honeypotActive: boolean;
  managerProcessDetected: boolean;
  sshPortOpen: boolean;
  dnsPortOpen: boolean;
  attackSimulationAllowed: boolean;
  honeypotHint: string;
}

export interface HoneypotStatusResponse {
  honeypotActive: boolean;
  managerProcessDetected: boolean;
  sshPortOpen: boolean;
  dnsPortOpen: boolean;
  attackSimulationAllowed: boolean;
  honeypotHint: string;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

async function requestJson<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${input}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    ...init,
  });

  if (!res.ok) {
    const text = await res.text();
    let parsedMessage = "";
    try {
      const parsed = JSON.parse(text) as { error?: string; message?: string };
      parsedMessage = parsed.error || parsed.message || "";
    } catch {
      // not JSON payload
    }
    throw new Error(parsedMessage || text || `Request failed: ${res.status}`);
  }

  return res.json() as Promise<T>;
}

export function getHealth() {
  return requestJson<HealthResponse>("/health");
}

export function getHoneypotStatus() {
  return requestJson<HoneypotStatusResponse>("/system/honeypot-status");
}

export function getDataSessions(params: {
  search?: string;
  attackType?: string;
  sortKey?: string;
  sortOrder?: "asc" | "desc";
  limit?: number;
}) {
  const q = new URLSearchParams();
  if (params.search) {
    q.set("search", params.search);
  }
  if (params.attackType) {
    q.set("attackType", params.attackType);
  }
  if (params.sortKey) {
    q.set("sortKey", params.sortKey);
  }
  if (params.sortOrder) {
    q.set("sortOrder", params.sortOrder);
  }
  if (params.limit) {
    q.set("limit", String(params.limit));
  }

  const suffix = q.toString() ? `?${q.toString()}` : "";
  return requestJson<DataSessionsResponse>(`/data/sessions${suffix}`);
}

export function getDashboardStats() {
  return requestJson<DashboardStatsResponse>("/data/stats");
}

export function startSimulation(
  mode: "quick" | "normal" | "intensive" = "quick",
  attackType: SimulationAttackType = "all",
) {
  return requestJson<{ jobId: string; status: string }>("/simulation/start", {
    method: "POST",
    body: JSON.stringify({ mode, attackType }),
  });
}

export function startTraining(dataPath?: string) {
  return requestJson<{ jobId: string; status: string }>("/training/start", {
    method: "POST",
    body: JSON.stringify({ dataPath }),
  });
}

export function getJobStatus(jobId: string) {
  return requestJson<JobStatus>(`/jobs/${jobId}`);
}

export function stopJob(jobId: string) {
  return requestJson<StopJobResponse>(`/jobs/${jobId}/stop`, {
    method: "POST",
  });
}

export function stopAllSimulations() {
  return requestJson<StopAllSimulationsResponse>("/simulation/stop-all", {
    method: "POST",
  });
}

export function startDashboard() {
  return requestJson<{ jobId: string; url: string }>("/dashboard/start", {
    method: "POST",
  });
}
