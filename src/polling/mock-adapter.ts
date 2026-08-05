import { Injectable } from '@nestjs/common';
import { ModuleDataSourceAdapter } from '../common/security-module/data-source-adapter.interface';
import {
  ModuleName,
  RawRecord,
  Severity,
} from '../common/security-module/types';

// Stands in for every real per-vendor adapter until real module API
// documentation exists (root CLAUDE.md's "open input required" note) — one
// canned record per module, so PollingService's cron path is real and
// testable without any actual vendor access. Ignores config/since entirely
// (they're only meaningful once a real vendor is behind this).
@Injectable()
export class MockAdapter implements ModuleDataSourceAdapter {
  fetchSince(moduleName: ModuleName): Promise<RawRecord[]> {
    return Promise.resolve([this.buildRecord(moduleName)]);
  }

  private buildRecord(moduleName: ModuleName): RawRecord {
    const timestamp = new Date();

    switch (moduleName) {
      case ModuleName.VM:
        return {
          timestamp,
          type: 'vulnerability',
          severity: Severity.MEDIUM,
          data: {
            assetIP: '10.0.0.50',
            assetName: 'polled-asset',
            assetType: 'server',
            description: 'Mock polled vulnerability',
            cveId: 'CVE-2026-0001',
          },
        };
      case ModuleName.EDR:
        return {
          timestamp,
          type: 'detection',
          severity: Severity.HIGH,
          data: {
            hostname: 'polled-host',
            ip: '10.0.0.51',
            os: 'Ubuntu 24.04',
            detectionName: 'Mock polled detection',
          },
        };
      case ModuleName.SIEM:
        return {
          timestamp,
          type: 'event',
          severity: Severity.LOW,
          data: { title: 'Mock polled SIEM event' },
        };
      case ModuleName.CTI:
        return {
          timestamp,
          type: 'ioc',
          severity: Severity.LOW,
          data: {
            type: 'IP',
            value: '203.0.113.1',
            confidence: 70,
            source: 'MockFeed',
          },
        };
      case ModuleName.SOAR:
        return {
          timestamp,
          type: 'event',
          severity: Severity.LOW,
          data: {},
        };
      case ModuleName.DFIR:
        return {
          timestamp,
          type: 'event',
          severity: Severity.LOW,
          data: { title: 'Mock polled incident' },
        };
    }
  }
}
