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

  @Public()
  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () => this.prismaIndicator.pingCheck('database', this.prisma),
      () =>
        this.memoryIndicator.checkHeap('memory_heap', HEAP_THRESHOLD_BYTES),
      () => this.memoryIndicator.checkRSS('memory_rss', RSS_THRESHOLD_BYTES),
    ]);
  }
}