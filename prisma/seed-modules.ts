// Large local dev/demo dataset across all six security modules, for
// multiple tenants. Deliberately NOT wired into `prisma db seed` (that
// stays scoped to the one-time Super Admin bootstrap in seed.ts) — this is
// an explicit, opt-in dev action: `npm run seed:demo`.
import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import { faker } from '@faker-js/faker';
import { Prisma, PrismaClient } from '../src/generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import {
  UserRole,
  ModuleName,
  Severity,
  VmVulnerabilitiesStatus,
  CtiIocType,
  EdrEndpointStatus,
  EdrDetectionStatus,
  SiemAlertStatus,
  SoarExecutionStatus,
  DfirIncidentStatus,
  DfirLinkSourceType,
} from '../src/generated/prisma/enums';

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});

// ---- Scale knobs — "very very big" per the request, tuned for a local dev
// Postgres to seed in seconds, not minutes. ~700 rows/tenant.
const TENANT_COUNT = 5;
const SHARED_PASSWORD = 'DemoPassw0rd!2026';
const PER_TENANT = {
  analysts: 3,
  viewers: 3,
  vmAssets: 25,
  vmVulnerabilitiesPerAsset: [2, 3] as [number, number],
  edrEndpoints: 20,
  edrDetectionsPerEndpoint: [2, 4] as [number, number],
  siemLogs: 120,
  siemAlerts: 45,
  ctiIocs: 35,
  soarPlaybooks: 6,
  soarExecutions: 25,
  dfirIncidents: 18,
  dfirLinksPerIncident: [1, 3] as [number, number],
};

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pick<T>(items: readonly T[]): T {
  return items[randomInt(0, items.length - 1)];
}

function pastDate(maxDaysAgo: number): Date {
  return faker.date.recent({ days: maxDaysAgo });
}

const ASSET_TYPES = ['server', 'workstation', 'laptop', 'router', 'firewall', 'database'];
const OS_LIST = [
  'Ubuntu 24.04',
  'Windows Server 2022',
  'Windows 11',
  'macOS Sonoma',
  'RHEL 9',
  'Debian 12',
];

// Each template pairs a record's title with the MITRE ATT&CK techniques it
// plausibly involves and a narrative description referencing the specific
// host/IP it fired against — this is what makes a seeded record read like a
// real one instead of a bare title, closing the gap the assign/escalate/
// resolve workflow was built to sit on top of.
interface EnrichmentTemplate {
  name: string;
  mitre: string[];
  describe: (hostname: string, ip: string) => string;
}

const DETECTION_TEMPLATES: EnrichmentTemplate[] = [
  {
    name: 'Suspicious PowerShell execution chain',
    mitre: ['T1059.001', 'T1027'],
    describe: (h, ip) =>
      `An obfuscated PowerShell command chain executed on ${h} (${ip}), consistent with a fileless technique used to evade static detection.`,
  },
  {
    name: 'Outbound C2 beaconing detected',
    mitre: ['T1071', 'T1105'],
    describe: (h, ip) =>
      `${h} (${ip}) was observed making periodic outbound connections to known command-and-control infrastructure, indicating active beaconing from a compromised host.`,
  },
  {
    name: 'Ransomware-like file encryption behavior',
    mitre: ['T1486'],
    describe: (h, ip) =>
      `Mass file modification and encryption activity was detected on ${h} (${ip}), matching known ransomware behavioral patterns.`,
  },
  {
    name: 'Credential dumping attempt (LSASS access)',
    mitre: ['T1003.001'],
    describe: (h, ip) =>
      `A process on ${h} (${ip}) attempted to read LSASS process memory, a common technique for harvesting cached credentials.`,
  },
  {
    name: 'Living-off-the-land binary abuse',
    mitre: ['T1218'],
    describe: (h, ip) =>
      `A signed, native Windows binary on ${h} (${ip}) was used to proxy execution of unauthorized code, evading application allowlisting.`,
  },
  {
    name: 'Unusual outbound data transfer volume',
    mitre: ['T1041'],
    describe: (h, ip) =>
      `${h} (${ip}) transferred an anomalously large volume of data outbound over a short window, consistent with staged exfiltration.`,
  },
  {
    name: 'Privilege escalation via token manipulation',
    mitre: ['T1134'],
    describe: (h, ip) =>
      `A process on ${h} (${ip}) manipulated an access token to impersonate a higher-privileged security context.`,
  },
  {
    name: 'Suspicious scheduled task creation',
    mitre: ['T1053.005'],
    describe: (h, ip) =>
      `A scheduled task was created on ${h} (${ip}) under a non-standard name, a common persistence mechanism.`,
  },
  {
    name: 'Malicious macro execution in Office document',
    mitre: ['T1204.002', 'T1566'],
    describe: (h, ip) =>
      `A user on ${h} (${ip}) opened an Office document that executed an embedded macro, spawning a child process outside normal application behavior.`,
  },
  {
    name: 'Known malware hash match',
    mitre: ['T1204'],
    describe: (h, ip) =>
      `A file matching a known-malicious hash from threat intelligence feeds was written to disk on ${h} (${ip}).`,
  },
  {
    name: 'Lateral movement via SMB',
    mitre: ['T1021.002'],
    describe: (h, ip) =>
      `Authenticated SMB connections were used to move from a previously compromised host to ${h} (${ip}).`,
  },
  {
    name: 'Disabling of security tooling detected',
    mitre: ['T1562.001'],
    describe: (h, ip) =>
      `Endpoint protection services on ${h} (${ip}) were disabled or tampered with shortly before related detections.`,
  },
];
const DETECTION_NAMES = DETECTION_TEMPLATES.map((t) => t.name);

const SIEM_SOURCES = ['firewall', 'ids', 'edr', 'vpn', 'proxy', 'dns', 'auth'];
const SIEM_EVENT_TYPES = [
  'login',
  'network',
  'file_access',
  'process_start',
  'dns_query',
  'auth_failure',
];
const SIEM_ALERT_TEMPLATES: EnrichmentTemplate[] = [
  {
    name: 'Multiple failed login attempts',
    mitre: ['T1110.001'],
    describe: (h, ip) =>
      `${randomInt(6, 40)} failed login attempts against the account "${h}" originated from ${ip} within a 10-minute window.`,
  },
  {
    name: 'Brute force attack detected',
    mitre: ['T1110'],
    describe: (h, ip) =>
      `A credential brute-force pattern was detected against "${h}" from ${ip}, cycling through a large password list at high frequency.`,
  },
  {
    name: 'Privilege escalation attempt',
    mitre: ['T1068'],
    describe: (h, ip) =>
      `The account "${h}" (last seen at ${ip}) attempted to exploit a local privilege escalation vector shortly after authenticating.`,
  },
  {
    name: 'Anomalous login location',
    mitre: ['T1078'],
    describe: (h, ip) =>
      `A successful login for "${h}" occurred from ${ip}, a geolocation inconsistent with that account's normal access pattern.`,
  },
  {
    name: 'Impossible travel login',
    mitre: ['T1078'],
    describe: (h, ip) =>
      `"${h}" authenticated from ${ip} less than an hour after a login from a geographically distant location — physically impossible travel time.`,
  },
  {
    name: 'Data exfiltration pattern detected',
    mitre: ['T1041', 'T1567'],
    describe: (h, ip) =>
      `Outbound traffic from "${h}" (${ip}) to an external endpoint matched a known data-exfiltration signature.`,
  },
  {
    name: 'Malware callback detected',
    mitre: ['T1071'],
    describe: (h, ip) =>
      `A host associated with "${h}" (${ip}) issued repeated callbacks to a domain flagged as malware infrastructure.`,
  },
  {
    name: 'Unauthorized configuration change',
    mitre: ['T1562.001'],
    describe: (h, ip) =>
      `A security-relevant configuration change was made under the account "${h}" from ${ip} outside of an approved maintenance window.`,
  },
];
const SIEM_ALERT_TITLES = SIEM_ALERT_TEMPLATES.map((t) => t.name);
const CTI_SOURCES = [
  'AlienVault OTX',
  'VirusTotal',
  'MISP',
  'Recorded Future',
  'Internal Analysis',
  'ThreatFox',
];
const PLAYBOOK_TEMPLATES: Array<{
  name: string;
  triggerCondition: Prisma.InputJsonValue;
  actions: Prisma.InputJsonValue;
}> = [
  {
    name: 'Isolate host on critical alert',
    triggerCondition: { severity: 'CRITICAL' },
    actions: { isolateHost: true },
  },
  {
    name: 'Block malicious IP on high severity',
    triggerCondition: { severity: 'HIGH' },
    actions: { blockIp: true },
  },
  {
    name: 'Disable compromised account',
    triggerCondition: { severity: 'CRITICAL' },
    actions: { disableAccount: true },
  },
  {
    name: 'Quarantine malicious file',
    triggerCondition: { severity: 'HIGH' },
    actions: { quarantineFile: true },
  },
  {
    name: 'Escalate to Tier 2 analyst',
    triggerCondition: { severity: 'MEDIUM' },
    actions: { escalate: true },
  },
  {
    name: 'Force credential reset',
    triggerCondition: { severity: 'CRITICAL' },
    actions: { resetCredentials: true },
  },
];
const DFIR_TEMPLATES: EnrichmentTemplate[] = [
  {
    name: 'Ransomware outbreak investigation',
    mitre: ['T1486', 'T1490'],
    describe: (h, ip) =>
      `File encryption activity consistent with ransomware was identified starting on ${h} (${ip}), with signs of lateral spread to adjacent hosts before containment began.`,
  },
  {
    name: 'Data exfiltration investigation',
    mitre: ['T1041', 'T1567'],
    describe: (h, ip) =>
      `A sustained, high-volume outbound transfer from ${h} (${ip}) to an external endpoint triggered this investigation into potential data theft.`,
  },
  {
    name: 'Compromised admin account',
    mitre: ['T1078', 'T1068'],
    describe: (h, ip) =>
      `An administrative account was used to authenticate from ${ip} — a location inconsistent with its owner's normal activity — then used to access ${h}.`,
  },
  {
    name: 'Supply chain compromise review',
    mitre: ['T1195'],
    describe: (h, ip) =>
      `A third-party software update installed on ${h} (${ip}) was later found to contain unauthorized code, prompting a review of the affected supply chain.`,
  },
  {
    name: 'Business email compromise',
    mitre: ['T1566', 'T1078'],
    describe: (h, ip) =>
      `A phishing-derived credential was used to access a mailbox from ${ip}, with subsequent activity observed on ${h}.`,
  },
  {
    name: 'Insider threat investigation',
    mitre: ['T1078'],
    describe: (h, ip) =>
      `Unusual data access patterns by an internal account on ${h} (${ip}) fell well outside that user's normal role and working hours.`,
  },
  {
    name: 'Web shell discovered on public server',
    mitre: ['T1505.003'],
    describe: (h, ip) =>
      `A web shell was discovered on the public-facing server ${h} (${ip}), granting remote command execution to an unknown external actor.`,
  },
  {
    name: 'Domain controller compromise',
    mitre: ['T1003', 'T1021'],
    describe: (h, ip) =>
      `Credential-dumping activity was traced back to the domain controller ${h} (${ip}), indicating a compromise at the identity-infrastructure level.`,
  },
];
const DFIR_TITLES = DFIR_TEMPLATES.map((t) => t.name);
const SEVERITIES = [
  Severity.LOW,
  Severity.MEDIUM,
  Severity.HIGH,
  Severity.CRITICAL,
] as const;

interface SeedCredential {
  tenantName: string;
  email: string;
  role: UserRole;
}

const usedEmails = new Set<string>();

function uniqueEmail(tenantSlug: string, role: string): string {
  let email: string;
  do {
    email = faker.internet
      .email({
        firstName: faker.person.firstName(),
        lastName: faker.person.lastName(),
        provider: `${tenantSlug}.demo`,
      })
      .toLowerCase();
  } while (usedEmails.has(email));
  usedEmails.add(email);
  return email;
}

function phoneNumber(): string {
  return `+216${randomInt(20000000, 59999999)}`;
}

async function seedTenant(
  index: number,
  hashedPassword: string,
): Promise<SeedCredential[]> {
  const tenantName = `${faker.company.name()} ${faker.company.buzzNoun()}`;
  const tenantSlug = faker.helpers
    .slugify(tenantName)
    .toLowerCase()
    .slice(0, 20);
  const tenant = await prisma.tenant.create({ data: { name: tenantName } });

  const credentials: SeedCredential[] = [];

  // ---- Users: 1 first Admin, 1 co-Admin, N Analysts, N Viewers.
  const userRows: Array<{
    id: string;
    email: string;
    phoneNumber: string;
    name: string;
    role: UserRole;
    hashedPassword: string;
    tenantId: string;
    mustChangePassword: boolean;
  }> = [];

  function addUser(role: UserRole) {
    const email = uniqueEmail(tenantSlug, role.toLowerCase());
    const id = randomUUID();
    userRows.push({
      id,
      email,
      phoneNumber: phoneNumber(),
      name: faker.person.fullName(),
      role,
      hashedPassword,
      tenantId: tenant.id,
      // Seed-script bootstrap, same precedent as the Super Admin seed in
      // seed.ts — not the API path the mustChangePassword hard rule targets.
      mustChangePassword: false,
    });
    credentials.push({ tenantName, email, role });
    return id;
  }

  addUser(UserRole.ADMIN);
  addUser(UserRole.ADMIN);
  for (let i = 0; i < PER_TENANT.analysts; i++) addUser(UserRole.ANALYST);
  const viewerIds: string[] = [];
  for (let i = 0; i < PER_TENANT.viewers; i++) viewerIds.push(addUser(UserRole.VIEWER));

  await prisma.user.createMany({ data: userRows });
  const analystAndAdminIds = userRows
    .filter((u) => u.role !== UserRole.VIEWER)
    .map((u) => u.id);

  // ---- TenantModule: one row per module, all active.
  await prisma.tenantModule.createMany({
    data: Object.values(ModuleName).map((moduleName) => ({
      id: randomUUID(),
      tenantId: tenant.id,
      moduleName,
      isActive: true,
      config: {},
    })),
  });

  // ---- VM
  const vmAssetIds: string[] = [];
  const usedIps = new Set<string>();
  const vmAssetRows = Array.from({ length: PER_TENANT.vmAssets }, () => {
    const id = randomUUID();
    vmAssetIds.push(id);
    let ip: string;
    do {
      ip = faker.internet.ipv4();
    } while (usedIps.has(ip));
    usedIps.add(ip);
    return {
      id,
      tenantId: tenant.id,
      name: `${faker.hacker.noun()}-${faker.string.alphanumeric(4)}`,
      ip,
      type: pick(ASSET_TYPES),
      createdAt: pastDate(90),
    };
  });
  await prisma.vmAsset.createMany({ data: vmAssetRows });

  const vmVulnerabilityRows: Array<{
    id: string;
    tenantId: string;
    assetId: string;
    severity: Severity;
    description: string;
    createdAt: Date;
    cveId: string | null;
    status: VmVulnerabilitiesStatus;
    assignedToUserId: string | null;
  }> = [];
  for (const assetId of vmAssetIds) {
    const count = randomInt(...PER_TENANT.vmVulnerabilitiesPerAsset);
    for (let i = 0; i < count; i++) {
      vmVulnerabilityRows.push({
        id: randomUUID(),
        tenantId: tenant.id,
        assetId,
        severity: pick(SEVERITIES),
        description: `${faker.hacker.verb()} vulnerability in ${faker.hacker.noun()} (${faker.hacker.adjective()})`,
        createdAt: pastDate(60),
        cveId: faker.datatype.boolean(0.6)
          ? `CVE-${randomInt(2022, 2026)}-${randomInt(1000, 99999)}`
          : null,
        status: pick(Object.values(VmVulnerabilitiesStatus)),
        assignedToUserId: faker.datatype.boolean(0.4)
          ? pick(analystAndAdminIds)
          : null,
      });
    }
  }
  await prisma.vmVulnerability.createMany({ data: vmVulnerabilityRows });

  // ---- EDR
  const edrEndpointIds: string[] = [];
  const usedHostnames = new Set<string>();
  const edrEndpointRows = Array.from({ length: PER_TENANT.edrEndpoints }, () => {
    const id = randomUUID();
    edrEndpointIds.push(id);
    let hostname: string;
    do {
      hostname = `${faker.hacker.noun()}-${faker.string.alphanumeric(5)}`.toLowerCase();
    } while (usedHostnames.has(hostname));
    usedHostnames.add(hostname);
    return {
      id,
      tenantId: tenant.id,
      hostname,
      ip: faker.internet.ipv4(),
      os: pick(OS_LIST),
      status: pick(Object.values(EdrEndpointStatus)),
      lastSeen: pastDate(7),
    };
  });
  await prisma.edrEndpoint.createMany({ data: edrEndpointRows });

  const edrEndpointById = new Map<string, (typeof edrEndpointRows)[number]>(
    edrEndpointRows.map((e) => [e.id, e]),
  );
  const edrDetectionRows: Array<{
    id: string;
    tenantId: string;
    endpointId: string;
    detectionName: string;
    description: string;
    mitreTechniques: string[];
    severity: Severity;
    status: EdrDetectionStatus;
    assignedToUserId: string | null;
    createdAt: Date;
  }> = [];
  for (const endpointId of edrEndpointIds) {
    const count = randomInt(...PER_TENANT.edrDetectionsPerEndpoint);
    const endpoint = edrEndpointById.get(endpointId);
    for (let i = 0; i < count; i++) {
      const template = pick(DETECTION_TEMPLATES);
      const isAssigned = faker.datatype.boolean(0.5);
      edrDetectionRows.push({
        id: randomUUID(),
        tenantId: tenant.id,
        endpointId,
        detectionName: template.name,
        description: template.describe(
          endpoint?.hostname ?? 'unknown-host',
          endpoint?.ip ?? faker.internet.ipv4(),
        ),
        mitreTechniques: template.mitre,
        severity: pick(SEVERITIES),
        status: isAssigned
          ? pick([
              EdrDetectionStatus.ASSIGNED,
              EdrDetectionStatus.ESCALATED,
              EdrDetectionStatus.RESOLVED,
            ])
          : EdrDetectionStatus.OPEN,
        assignedToUserId: isAssigned ? pick(analystAndAdminIds) : null,
        createdAt: pastDate(30),
      });
    }
  }
  await prisma.edrDetection.createMany({ data: edrDetectionRows });

  // ---- SIEM
  const siemLogRows = Array.from({ length: PER_TENANT.siemLogs }, () => ({
    id: randomUUID(),
    tenantId: tenant.id,
    source: pick(SIEM_SOURCES),
    eventType: pick(SIEM_EVENT_TYPES),
    severity: pick(SEVERITIES),
    timestamp: pastDate(30),
  }));
  await prisma.siemLog.createMany({ data: siemLogRows });

  const siemAlertIds: string[] = [];
  const siemAlertRows = Array.from({ length: PER_TENANT.siemAlerts }, () => {
    const id = randomUUID();
    siemAlertIds.push(id);
    const template = pick(SIEM_ALERT_TEMPLATES);
    const isAssigned = faker.datatype.boolean(0.5);
    const account = faker.internet.username().toLowerCase();
    return {
      id,
      tenantId: tenant.id,
      title: template.name,
      description: template.describe(account, faker.internet.ipv4()),
      mitreTechniques: template.mitre,
      severity: pick(SEVERITIES),
      status: isAssigned
        ? pick([
            SiemAlertStatus.ASSIGNED,
            SiemAlertStatus.ESCALATED,
            SiemAlertStatus.RESOLVED,
          ])
        : SiemAlertStatus.OPEN,
      assignedToUserId: isAssigned ? pick(analystAndAdminIds) : null,
      createdAt: pastDate(30),
    };
  });
  await prisma.siemAlert.createMany({ data: siemAlertRows });

  // ---- CTI
  function ctiValueFor(type: CtiIocType): string {
    switch (type) {
      case CtiIocType.IP:
        return faker.internet.ipv4();
      case CtiIocType.DOMAIN:
        return faker.internet.domainName();
      case CtiIocType.URL:
        return faker.internet.url();
      case CtiIocType.HASH:
        return faker.string.hexadecimal({ length: 64, casing: 'lower', prefix: '' });
      case CtiIocType.EMAIL:
        return faker.internet.email().toLowerCase();
    }
  }
  const usedIocKeys = new Set<string>();
  const ctiIocRows: Array<{
    id: string;
    tenantId: string;
    type: CtiIocType;
    value: string;
    confidence: number;
    source: string;
    createdAt: Date;
  }> = [];
  while (ctiIocRows.length < PER_TENANT.ctiIocs) {
    const type = pick(Object.values(CtiIocType));
    const value = ctiValueFor(type);
    const key = `${type}:${value}`;
    if (usedIocKeys.has(key)) continue;
    usedIocKeys.add(key);
    ctiIocRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      type,
      value,
      confidence: randomInt(30, 100),
      source: pick(CTI_SOURCES),
      createdAt: pastDate(45),
    });
  }
  await prisma.ctiIoc.createMany({ data: ctiIocRows });

  // ---- SOAR
  const soarPlaybookIds: string[] = [];
  const soarPlaybookRows = faker.helpers
    .arrayElements(PLAYBOOK_TEMPLATES, PER_TENANT.soarPlaybooks)
    .map((template) => {
      const id = randomUUID();
      soarPlaybookIds.push(id);
      return {
        id,
        tenantId: tenant.id,
        name: template.name,
        triggerCondition: template.triggerCondition,
        actions: template.actions,
        createdAt: pastDate(120),
      };
    });
  await prisma.soarPlaybook.createMany({ data: soarPlaybookRows });

  const soarExecutionRows = Array.from({ length: PER_TENANT.soarExecutions }, () => {
    const playbook = soarPlaybookRows[randomInt(0, soarPlaybookRows.length - 1)];
    const alertId = pick(siemAlertIds);
    return {
      id: randomUUID(),
      tenantId: tenant.id,
      playbookId: playbook.id,
      alertId,
      status: faker.helpers.weightedArrayElement([
        { value: SoarExecutionStatus.SUCCESS, weight: 7 },
        { value: SoarExecutionStatus.FAILED, weight: 1 },
        { value: SoarExecutionStatus.RUNNING, weight: 1 },
        { value: SoarExecutionStatus.PENDING, weight: 1 },
      ]),
      logs: `Playbook "${playbook.name}" executed (simulated).`,
      createdAt: pastDate(30),
    };
  });
  await prisma.soarExecution.createMany({ data: soarExecutionRows });

  // ---- DFIR
  const dfirIncidentIds: string[] = [];
  const dfirIncidentRows = Array.from({ length: PER_TENANT.dfirIncidents }, () => {
    const id = randomUUID();
    dfirIncidentIds.push(id);
    const template = pick(DFIR_TEMPLATES);
    const endpoint = pick(edrEndpointRows);
    const isAssigned = faker.datatype.boolean(0.5);
    return {
      id,
      tenantId: tenant.id,
      title: template.name,
      description: template.describe(endpoint.hostname, endpoint.ip),
      mitreTechniques: template.mitre,
      severity: pick(SEVERITIES),
      status: isAssigned
        ? pick([
            DfirIncidentStatus.INVESTIGATING,
            DfirIncidentStatus.ESCALATED,
            DfirIncidentStatus.CONTAINED,
            DfirIncidentStatus.RESOLVED,
          ])
        : DfirIncidentStatus.OPEN,
      assignedToUserId: isAssigned ? pick(analystAndAdminIds) : null,
      createdAt: pastDate(60),
    };
  });
  await prisma.dfirIncident.createMany({ data: dfirIncidentRows });

  const linkPools = [
    { sourceType: DfirLinkSourceType.SIEM_ALERT, ids: siemAlertIds },
    { sourceType: DfirLinkSourceType.EDR_DETECTION, ids: edrDetectionRows.map((r) => r.id) },
    { sourceType: DfirLinkSourceType.CTI_IOC, ids: ctiIocRows.map((r) => r.id) },
    { sourceType: DfirLinkSourceType.SOAR_EXECUTION, ids: soarExecutionRows.map((r) => r.id) },
    { sourceType: DfirLinkSourceType.VM_VULNERABILITY, ids: vmVulnerabilityRows.map((r) => r.id) },
  ].filter((pool) => pool.ids.length > 0);

  const dfirLinkRows: Array<{
    id: string;
    tenantId: string;
    incidentId: string;
    sourceType: DfirLinkSourceType;
    sourceId: string;
  }> = [];
  for (const incidentId of dfirIncidentIds) {
    const count = randomInt(...PER_TENANT.dfirLinksPerIncident);
    for (let i = 0; i < count; i++) {
      const pool = pick(linkPools);
      dfirLinkRows.push({
        id: randomUUID(),
        tenantId: tenant.id,
        incidentId,
        sourceType: pool.sourceType,
        sourceId: pick(pool.ids),
      });
    }
  }
  await prisma.dfirLink.createMany({ data: dfirLinkRows });

  // ---- Asset feed — mirrors what AssetService's real listeners would have
  // written, for demo purposes only (the one deliberate exception to "only
  // AssetService writes this table").
  const feedRows: Array<{
    id: string;
    tenantId: string;
    source: ModuleName;
    type: string;
    severity: Severity;
    timestamp: Date;
    summary: string;
    sourceId: string;
  }> = [];
  for (const d of edrDetectionRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.EDR,
      type: 'detection',
      severity: d.severity,
      timestamp: d.createdAt,
      summary: `${d.detectionName} on ${edrEndpointById.get(d.endpointId)?.hostname ?? 'unknown-host'}`,
      sourceId: d.id,
    });
  }
  for (const a of siemAlertRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.SIEM,
      type: 'alert',
      severity: a.severity,
      timestamp: a.createdAt,
      summary: a.title,
      sourceId: a.id,
    });
  }
  const playbookById = new Map<string, (typeof soarPlaybookRows)[number]>(
    soarPlaybookRows.map((p) => [p.id, p]),
  );
  for (const e of soarExecutionRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.SOAR,
      type: 'execution',
      severity: pick(SEVERITIES),
      timestamp: e.createdAt,
      summary: `Playbook "${playbookById.get(e.playbookId)?.name ?? 'unknown'}" executed`,
      sourceId: e.id,
    });
  }
  for (const i of dfirIncidentRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.DFIR,
      type: 'incident',
      severity: i.severity,
      timestamp: i.createdAt,
      summary: i.title,
      sourceId: i.id,
    });
  }
  for (const ioc of ctiIocRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.CTI,
      type: 'ioc',
      severity: Severity.LOW,
      timestamp: ioc.createdAt,
      summary: `${ioc.type} IOC: ${ioc.value}`,
      sourceId: ioc.id,
    });
  }
  for (const v of vmVulnerabilityRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.VM,
      type: 'vulnerability',
      severity: v.severity,
      timestamp: v.createdAt,
      summary: v.description,
      sourceId: v.id,
    });
  }
  await prisma.assetFeedEntry.createMany({ data: feedRows });

  console.log(
    `  Tenant "${tenantName}": ${userRows.length} users, ${vmAssetRows.length} VM assets/` +
      `${vmVulnerabilityRows.length} vulns, ${edrEndpointRows.length} endpoints/` +
      `${edrDetectionRows.length} detections, ${siemLogRows.length} logs/` +
      `${siemAlertRows.length} alerts, ${ctiIocRows.length} IOCs, ` +
      `${soarPlaybookRows.length} playbooks/${soarExecutionRows.length} executions, ` +
      `${dfirIncidentRows.length} incidents/${dfirLinkRows.length} links, ` +
      `${feedRows.length} feed entries`,
  );

  return credentials;
}

async function main() {
  console.log(`Seeding ${TENANT_COUNT} demo tenants with large module datasets...\n`);
  const hashedPassword = await argon2.hash(SHARED_PASSWORD);

  const allCredentials: SeedCredential[] = [];
  for (let i = 0; i < TENANT_COUNT; i++) {
    const creds = await seedTenant(i, hashedPassword);
    allCredentials.push(...creds);
  }

  console.log('\n=== Demo credentials (all accounts share one password) ===');
  console.log(`Password for every seeded account: ${SHARED_PASSWORD}\n`);

  let currentTenant = '';
  for (const cred of allCredentials) {
    if (cred.tenantName !== currentTenant) {
      currentTenant = cred.tenantName;
      console.log(`\n${currentTenant}`);
    }
    console.log(`  [${cred.role.padEnd(7)}] ${cred.email}`);
  }
  console.log(`\nTotal accounts seeded: ${allCredentials.length}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
