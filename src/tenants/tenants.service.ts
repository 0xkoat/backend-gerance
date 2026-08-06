import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ModuleName, Prisma, UserRole } from '../generated/prisma/client';
import type { TenantModule } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTenantDto } from './dto/createTenant.dto';
import * as argon2 from 'argon2';

@Injectable()
export class TenantsService {
  private readonly logger = new Logger(TenantsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async createTenantWithAdmin(createTenantDto: CreateTenantDto) {
    const { tenantName, name, email, password, phoneNumber } = createTenantDto;
    const hashedPassword = await argon2.hash(password);

    try {
      return await this.prisma.$transaction(async (tx) => {
        const tenant = await tx.tenant.create({
          data: { name: tenantName },
        });

        const admin = await tx.user.create({
          data: {
            name,
            email,
            phoneNumber,
            hashedPassword,
            role: UserRole.ADMIN,
            tenantId: tenant.id,
            mustChangePassword: true,
          },
        });

        const { hashedPassword: _hashedPassword, ...safeAdmin } = admin;
        return { tenant, admin: safeAdmin };
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        this.logger.warn(
          `Tenant creation rejected — duplicate admin email: ${email}`,
        );
        throw new ConflictException('A user with this email already exists');
      }
      throw error;
    }
  }

  async findAll() {
    return this.prisma.tenant.findMany();
  }

  async findById(id: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { id },
      include: {
        users: {
          where: { role: UserRole.ADMIN },
          orderBy: { createdAt: 'asc' },
        },
      },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    const { users, ...safeTenant } = tenant;
    return {
      ...safeTenant,
      admins: users.map(({ hashedPassword, ...safeAdmin }) => safeAdmin),
    };
  }

  async renameTenant(id: string, name: string) {
    await this.ensureTenantExists(id);

    return this.prisma.tenant.update({ where: { id }, data: { name } });
  }

  // No CRUD for TenantModule existed anywhere before this — the only writer
  // was the demo seed script, so a tenant created through the real
  // provisioning path (createTenantWithAdmin, above) never got any rows,
  // meaning PollingService's `where: { isActive: true }` query silently
  // matched nothing for every real tenant. This is the actual activation
  // path the architecture doc's "activate the modules relevant to them"
  // language describes — deliberately not auto-provisioned at tenant
  // creation, since which modules apply is a per-tenant decision, not a
  // default every tenant gets.
  async listModules(tenantId: string): Promise<TenantModule[]> {
    await this.ensureTenantExists(tenantId);

    return this.prisma.tenantModule.findMany({ where: { tenantId } });
  }

  async activateModule(
    tenantId: string,
    moduleName: ModuleName,
    config?: object,
  ): Promise<TenantModule> {
    await this.ensureTenantExists(tenantId);

    try {
      return await this.prisma.tenantModule.create({
        data: { tenantId, moduleName, config },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException(
          `${moduleName} is already configured for this tenant — use PATCH to update it`,
        );
      }
      throw error;
    }
  }

  async updateModule(
    tenantId: string,
    moduleName: ModuleName,
    dto: { isActive?: boolean; config?: object },
  ): Promise<TenantModule> {
    await this.ensureTenantExists(tenantId);

    try {
      return await this.prisma.tenantModule.update({
        where: { tenantId_moduleName: { tenantId, moduleName } },
        data: dto,
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        throw new NotFoundException(
          `${moduleName} is not configured for this tenant`,
        );
      }
      throw error;
    }
  }

  async deactivateModule(
    tenantId: string,
    moduleName: ModuleName,
  ): Promise<void> {
    await this.ensureTenantExists(tenantId);

    try {
      await this.prisma.tenantModule.delete({
        where: { tenantId_moduleName: { tenantId, moduleName } },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        throw new NotFoundException(
          `${moduleName} is not configured for this tenant`,
        );
      }
      throw error;
    }
  }

  private async ensureTenantExists(id: string): Promise<void> {
    const tenant = await this.prisma.tenant.findUnique({ where: { id } });
    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }
  }

  async deleteTenantWithUsers(id: string) {
    await this.findById(id);

    // Every security-module table's tenantId FK is RESTRICT (Prisma's
    // default), so each one has to be cleared before the Tenant row itself
    // can go — order matters here: children before the parents they
    // reference (e.g. DfirLink before DfirIncident, SoarExecution before
    // both SoarPlaybook and SiemAlert), and SiemAlert before User since an
    // alert can optionally reference its assignedToUser. RefreshToken and
    // PasswordHistory are scoped by userId, not tenantId, but also RESTRICT
    // on User — filtered via the `user` relation so they can stay in this
    // same array-based transaction instead of needing a separate
    // fetch-user-ids-first step.
    const results = await this.prisma.$transaction([
      this.prisma.assetFeedEntry.deleteMany({ where: { tenantId: id } }),
      this.prisma.dfirLink.deleteMany({ where: { tenantId: id } }),
      this.prisma.dfirIncident.deleteMany({ where: { tenantId: id } }),
      this.prisma.soarExecution.deleteMany({ where: { tenantId: id } }),
      this.prisma.soarPlaybook.deleteMany({ where: { tenantId: id } }),
      this.prisma.siemAlert.deleteMany({ where: { tenantId: id } }),
      this.prisma.siemLog.deleteMany({ where: { tenantId: id } }),
      this.prisma.edrDetection.deleteMany({ where: { tenantId: id } }),
      this.prisma.edrEndpoint.deleteMany({ where: { tenantId: id } }),
      this.prisma.ctiIoc.deleteMany({ where: { tenantId: id } }),
      this.prisma.vmVulnerability.deleteMany({ where: { tenantId: id } }),
      this.prisma.vmAsset.deleteMany({ where: { tenantId: id } }),
      this.prisma.tenantModule.deleteMany({ where: { tenantId: id } }),
      this.prisma.refreshToken.deleteMany({
        where: { user: { tenantId: id } },
      }),
      this.prisma.passwordHistory.deleteMany({
        where: { user: { tenantId: id } },
      }),
      this.prisma.user.deleteMany({ where: { tenantId: id } }),
      this.prisma.tenant.delete({ where: { id } }),
    ]);

    // Last element is the tenant.delete() result, per the array above.
    const deletedTenant = results[16];
    return deletedTenant;
  }
}
