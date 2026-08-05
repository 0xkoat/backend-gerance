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
const DETECTION_NAMES = [
  'Suspicious PowerShell execution chain',
  'Outbound C2 beaconing detected',
  'Ransomware-like file encryption behavior',
  'Credential dumping attempt (LSASS access)',
  'Living-off-the-land binary abuse',
  'Unusual outbound data transfer volume',
  'Privilege escalation via token manipulation',
  'Suspicious scheduled task creation',
  'Malicious macro execution in Office document',
  'Known malware hash match',
  'Lateral movement via SMB',
  'Disabling of security tooling detected',
];
const SIEM_SOURCES = ['firewall', 'ids', 'edr', 'vpn', 'proxy', 'dns', 'auth'];
const SIEM_EVENT_TYPES = [
  'login',
  'network',
  'file_access',
  'process_start',
  'dns_query',
  'auth_failure',
];
const SIEM_ALERT_TITLES = [
  'Multiple failed login attempts',
  'Brute force attack detected',
  'Privilege escalation attempt',
  'Anomalous login location',
  'Impossible travel login',
  'Data exfiltration pattern detected',
  'Malware callback detected',
  'Unauthorized configuration change',
];
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
const DFIR_TITLES = [
  'Ransomware outbreak investigation',
  'Data exfiltration investigation',
  'Compromised admin account',
  'Supply chain compromise review',
  'Business email compromise',
  'Insider threat investigation',
  'Web shell discovered on public server',
  'Domain controller compromise',
];
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

  const edrDetectionRows: Array<{
    id: string;
    tenantId: string;
    endpointId: string;
    detectionName: string;
    severity: Severity;
    createdAt: Date;
  }> = [];
  for (const endpointId of edrEndpointIds) {
    const count = randomInt(...PER_TENANT.edrDetectionsPerEndpoint);
    for (let i = 0; i < count; i++) {
      edrDetectionRows.push({
        id: randomUUID(),
        tenantId: tenant.id,
        endpointId,
        detectionName: pick(DETECTION_NAMES),
        severity: pick(SEVERITIES),
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
    return {
      id,
      tenantId: tenant.id,
      title: pick(SIEM_ALERT_TITLES),
      severity: pick(SEVERITIES),
      status: pick(Object.values(SiemAlertStatus)),
      assignedToUserId: faker.datatype.boolean(0.5)
        ? pick(analystAndAdminIds)
        : null,
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
    return {
      id,
      tenantId: tenant.id,
      title: pick(DFIR_TITLES),
      severity: pick(SEVERITIES),
      status: pick(Object.values(DfirIncidentStatus)),
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
  const endpointById = new Map<string, (typeof edrEndpointRows)[number]>(
    edrEndpointRows.map((e) => [e.id, e]),
  );
  for (const d of edrDetectionRows) {
    feedRows.push({
      id: randomUUID(),
      tenantId: tenant.id,
      source: ModuleName.EDR,
      type: 'detection',
      severity: d.severity,
      timestamp: d.createdAt,
      summary: `${d.detectionName} on ${endpointById.get(d.endpointId)?.hostname ?? 'unknown-host'}`,
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
