import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
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

// Polled by Docker's healthcheck and uptime monitors: never rate limited.
@SkipThrottle()
@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly prismaIndicator: PrismaHealthIndicator,
    private readonly memoryIndicator: MemoryHealthIndicator,
    private readonly prisma: PrismaService,
  ) {}

  // Public (no JWT) so an external uptime monitor can hit it. One aggregate
  // endpoint with a per-component breakdown: the platform's only runtime
  // dependency is Postgres. The external security modules are deliberately
  // not probed here — their reachability is the Integration Admin's
  // "Test connection" (module-access), and a module being down shouldn't
  // mark the platform itself unhealthy.
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
