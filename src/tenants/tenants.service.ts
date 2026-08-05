import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma, UserRole } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTenantDto } from './dto/createTenant.dto';
import * as argon2 from 'argon2';

@Injectable()
export class TenantsService {
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

  async deleteTenantWithUsers(id: string) {
    await this.findById(id);

    // Every security-module table's tenantId FK is RESTRICT (Prisma's
    // default), so each one has to be cleared before the Tenant row itself
    // can go — order matters here: children before the parents they
    // reference (e.g. DfirLink before DfirIncident, SoarExecution before
    // both SoarPlaybook and SiemAlert), and SiemAlert before User since an
    // alert can optionally reference its assignedToUser.
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
      this.prisma.user.deleteMany({ where: { tenantId: id } }),
      this.prisma.tenant.delete({ where: { id } }),
    ]);

    // Last element is the tenant.delete() result, per the array above.
    const deletedTenant = results[14];
    return deletedTenant;
  }
}
