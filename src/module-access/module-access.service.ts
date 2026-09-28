import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import {
  AnalystLevel,
  ModuleName,
  Prisma,
  UserRole,
} from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { ConnectionProbe, type ProbeResult } from './connection-probe';
import { meetsMinLevel } from './module-levels';
import { buildModuleUrl } from './module-url';
import { UpdateModuleEndpointDto } from './dto/updateModuleEndpoint.dto';

export interface AvailableModule {
  moduleName: ModuleName;
  minAnalystLevel: AnalystLevel;
  // false while the Integration Admin hasn't set host/port yet.
  configured: boolean;
  canLaunch: boolean;
}

const RECENT_LAUNCHES_LIMIT = 50;

@Injectable()
export class ModuleAccessService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly connectionProbe: ConnectionProbe,
  ) {}

  // ---- Platform-wide endpoints (Integration Admin) ----

  listEndpoints() {
    return this.prisma.moduleEndpoint.findMany({
      orderBy: { moduleName: 'asc' },
    });
  }

  async updateEndpoint(
    moduleName: ModuleName,
    dto: UpdateModuleEndpointDto,
    updatedById: string,
  ) {
    try {
      return await this.prisma.moduleEndpoint.update({
        where: { moduleName },
        data: { ...dto, updatedById },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        throw new NotFoundException(`No endpoint row for ${moduleName}`);
      }
      throw error;
    }
  }

  async testConnection(moduleName: ModuleName): Promise<ProbeResult> {
    const endpoint = await this.prisma.moduleEndpoint.findUnique({
      where: { moduleName },
    });
    if (!endpoint) {
      throw new NotFoundException(`No endpoint row for ${moduleName}`);
    }
    if (!endpoint.host || !endpoint.port) {
      throw new BadRequestException(
        `${moduleName} has no host/port configured yet`,
      );
    }
    return this.connectionProbe.probe(endpoint.host, endpoint.port);
  }

  // ---- Tenant side (Admin, Analyst) ----

  // Modules active for the caller's tenant. An Admin sees every one (they also
  // manage the level rules); an Analyst sees only the ones their level allows,
  // so the list never advertises modules they can't open.
  async listForUser(
    tenantId: string,
    role: UserRole,
    analystLevel: AnalystLevel | null,
  ): Promise<AvailableModule[]> {
    const [subscriptions, endpoints] = await Promise.all([
      this.prisma.tenantModule.findMany({
        where: { tenantId, isActive: true },
        orderBy: { moduleName: 'asc' },
      }),
      this.prisma.moduleEndpoint.findMany(),
    ]);
    const configuredModules = new Set(
      endpoints.filter((e) => buildModuleUrl(e)).map((e) => e.moduleName),
    );

    return subscriptions
      .filter(
        (s) =>
          role === UserRole.ADMIN ||
          (analystLevel !== null &&
            meetsMinLevel(analystLevel, s.minAnalystLevel)),
      )
      .map((s) => {
        const configured = configuredModules.has(s.moduleName);
        return {
          moduleName: s.moduleName,
          minAnalystLevel: s.minAnalystLevel,
          configured,
          canLaunch: configured,
        };
      });
  }

  async setMinLevel(
    tenantId: string,
    moduleName: ModuleName,
    minAnalystLevel: AnalystLevel,
  ) {
    try {
      return await this.prisma.tenantModule.update({
        where: { tenantId_moduleName: { tenantId, moduleName } },
        data: { minAnalystLevel },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        throw new NotFoundException(
          `${moduleName} is not activated for your tenant`,
        );
      }
      throw error;
    }
  }

  // Role and level are re-read from the database rather than trusted from the
  // access token, so a demotion takes effect on the very next launch instead of
  // up to 15 minutes later.
  async launch(
    userId: string,
    tenantId: string,
    moduleName: ModuleName,
  ): Promise<{ url: string }> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.tenantId !== tenantId) {
      throw new ForbiddenException('Account not found in this tenant');
    }

    const subscription = await this.prisma.tenantModule.findUnique({
      where: { tenantId_moduleName: { tenantId, moduleName } },
    });
    if (!subscription || !subscription.isActive) {
      throw new NotFoundException(
        `${moduleName} is not available for your tenant`,
      );
    }

    const allowed =
      user.role === UserRole.ADMIN ||
      (user.role === UserRole.ANALYST &&
        user.analystLevel !== null &&
        meetsMinLevel(user.analystLevel, subscription.minAnalystLevel));
    if (!allowed) {
      throw new ForbiddenException(
        `${moduleName} requires analyst level ${subscription.minAnalystLevel} or higher`,
      );
    }

    const endpoint = await this.prisma.moduleEndpoint.findUnique({
      where: { moduleName },
    });
    const url = endpoint ? buildModuleUrl(endpoint) : null;
    if (!url) {
      throw new ConflictException(
        `${moduleName} has no endpoint configured yet — contact your Integration Admin`,
      );
    }

    await this.prisma.moduleLaunch.create({
      data: {
        userId: user.id,
        userEmail: user.email,
        role: user.role,
        tenantId,
        moduleName,
        targetUrl: url,
      },
    });

    return { url };
  }

  recentLaunches(tenantId: string) {
    return this.prisma.moduleLaunch.findMany({
      where: { tenantId },
      orderBy: { launchedAt: 'desc' },
      take: RECENT_LAUNCHES_LIMIT,
    });
  }
}
