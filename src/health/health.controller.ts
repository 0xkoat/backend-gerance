import { Controller, Get } from '@nestjs/common';
import {
  HealthCheckService,
  HealthCheck,
  PrismaHealthIndicator,
  MemoryHealthIndicator,
} from '@nestjs/terminus';
import { Public } from '../auth/decorators/public.decorator';
import { PrismaService } from '../prisma/prisma.service';

const HEAP_THRESHOLD_BYTES = 300 * 1024 * 1024;
const RSS_THRESHOLD_BYTES = 300 * 1024 * 1024;

@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly prismaIndicator: PrismaHealthIndicator,
    private readonly memoryIndicator: MemoryHealthIndicator,
    private readonly prisma: PrismaService,
  ) {}

  // Public (no JWT) so an external uptime monitor can hit it. One aggregate
  // endpoint with a per-component breakdown rather than one route per
  // module, since every module currently shares the same single failure mode
  // (Postgres down), so a per-module route would just triplicate this
  // check. Add a new named indicator here once a module gains its own
  // independent external dependency (e.g. SIEM's Elastic cluster).
  @Public()
  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () => this.prismaIndicator.pingCheck('database', this.prisma),
      () => this.memoryIndicator.checkHeap('memory_heap', HEAP_THRESHOLD_BYTES),
      () => this.memoryIndicator.checkRSS('memory_rss', RSS_THRESHOLD_BYTES),
    ]);
  }
}
