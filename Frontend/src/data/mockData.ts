export const attackTypes = [
  { id: 'ssh_brute', name: 'SSH Brute Force', icon: '🔐', color: 'destructive' },
  { id: 'port_scan', name: 'Port Scan', icon: '🔍', color: 'warning' },
  { id: 'dns_attack', name: 'DNS Attack', icon: '🌐', color: 'primary' },
  { id: 'arp_spoof', name: 'ARP Spoof', icon: '🕸️', color: 'accent' },
  { id: 'icmp_flood', name: 'ICMP Flood', icon: '🌊', color: 'destructive' },
] as const;

export type AttackType = typeof attackTypes[number];

export interface AttackSession {
  id: string;
  timestamp: string;
  srcIp: string;
  dstIp: string;
  attackType: string;
  duration: number;
  packetsCount: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detected: boolean;
}

const randomIp = () =>
  `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

export const generateSessions = (count: number): AttackSession[] =>
  Array.from({ length: count }, (_, i) => ({
    id: `SES-${String(i + 1).padStart(5, '0')}`,
    timestamp: new Date(Date.now() - Math.random() * 86400000 * 7).toISOString(),
    srcIp: randomIp(),
    dstIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
    attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)].name,
    duration: Math.floor(Math.random() * 300) + 5,
    packetsCount: Math.floor(Math.random() * 50000) + 100,
    severity: (['low', 'medium', 'high', 'critical'] as const)[Math.floor(Math.random() * 4)],
    detected: Math.random() > 0.15,
  }));

export const mockSessions = generateSessions(200);

export const terminalLogs: Record<string, string[]> = {
  'SSH Brute Force': [
    '[SSH] Connection attempt from 45.33.32.156:22',
    '[AUTH] Failed login: root / password123',
    '[AUTH] Failed login: root / admin',
    '[AUTH] Failed login: admin / 123456',
    '[AUTH] Failed login: root / toor',
    '[SSH] Brute force pattern detected — 42 attempts in 3s',
    '[ALERT] Threshold exceeded — blocking source IP',
    '[SSH] Failed login: root / qwerty',
    '[AUTH] Rate limit triggered for 45.33.32.156',
    '[SSH] Connection terminated by honeypot',
  ],
  'Port Scan': [
    '[SCAN] SYN probe detected on port 21 (FTP)',
    '[SCAN] SYN probe detected on port 22 (SSH)',
    '[SCAN] SYN probe detected on port 23 (Telnet)',
    '[SCAN] SYN probe detected on port 80 (HTTP)',
    '[SCAN] SYN probe detected on port 443 (HTTPS)',
    '[SCAN] SYN probe detected on port 3306 (MySQL)',
    '[SCAN] SYN probe detected on port 5432 (PostgreSQL)',
    '[ALERT] Sequential port scan from 185.220.101.42',
    '[SCAN] 1024 ports scanned in 2.3 seconds',
    '[BLOCK] Adding to threat intelligence feed',
  ],
  'DNS Attack': [
    '[DNS] Query flood detected: 1,200 req/s',
    '[DNS] Amplification attempt via open resolver',
    '[DNS] Suspicious TXT record query: _dmarc.evil.com',
    '[DNS] NXDOMAIN response rate: 89%',
    '[DNS] Cache poisoning attempt detected',
    '[ALERT] DNS exfiltration pattern identified',
    '[DNS] Tunnel detected in subdomain queries',
    '[DNS] Blocking recursive queries from external',
    '[DNS] Rate limiting applied to source',
    '[DNS] Captured payload for analysis',
  ],
  'ARP Spoof': [
    '[ARP] Gratuitous ARP from 00:1A:2B:3C:4D:5E',
    '[ARP] MAC address conflict detected for 192.168.1.1',
    '[ARP] Cache poisoning in progress',
    '[ARP] Gateway MAC changed: legit → spoofed',
    '[ALERT] Man-in-the-middle attack detected',
    '[ARP] DAI violation logged',
    '[ARP] Static ARP entry enforced',
    '[ARP] Isolating attacker VLAN segment',
    '[ARP] Capturing redirected traffic',
    '[NET] Restoring ARP table integrity',
  ],
  'ICMP Flood': [
    '[ICMP] Echo request flood: 50,000 pps',
    '[ICMP] Packet size: 65535 bytes (oversized)',
    '[ICMP] Source: 203.0.113.0/24 (spoofed)',
    '[ICMP] Bandwidth consumption: 850 Mbps',
    '[ALERT] ICMP flood threshold exceeded',
    '[ICMP] Applying rate limiting',
    '[ICMP] Smurf amplification detected',
    '[ICMP] Dropping oversized packets',
    '[NET] Upstream blackhole routing activated',
    '[ICMP] Attack mitigated — traffic normalized',
  ],
};

export const dashboardStats = {
  totalAttacks: 1847,
  detectionRate: 94.2,
  avgResponseTime: 1.3,
  activeThreats: 3,
  attackDistribution: [
    { name: 'SSH Brute Force', value: 542, color: '#ef4444' },
    { name: 'Port Scan', value: 389, color: '#f59e0b' },
    { name: 'DNS Attack', value: 301, color: '#22d3ee' },
    { name: 'ARP Spoof', value: 278, color: '#22c55e' },
    { name: 'ICMP Flood', value: 337, color: '#f87171' },
  ],
  topAttackerIPs: [
    { ip: '45.33.32.156', count: 234, country: 'CN' },
    { ip: '185.220.101.42', count: 189, country: 'RU' },
    { ip: '203.0.113.50', count: 156, country: 'KP' },
    { ip: '198.51.100.23', count: 142, country: 'IR' },
    { ip: '91.219.236.174', count: 98, country: 'UA' },
  ],
};
