import { ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, UserRole } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service'; 
import { CreateUserDto } from './dto/createUser.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import * as argon2 from 'argon2';



@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) {}

    async findByEmail(email: string) {
        return this.prisma.user.findUnique({
            where: { email },
        });
    }

    async findByIdForTenant(id: string, tenantId: string) {
        const user = await this.prisma.user.findUnique({
            where: { id },
        });

        if (!user || user.tenantId !== tenantId) {
            throw new NotFoundException('User not found');
        }

        return user;
    }

    async findAllForTenant(tenantId: string) {
        return this.prisma.user.findMany({
            where: { tenantId },
        });
    }

    async createUser(createUserDto: CreateUserDto, role: UserRole, tenantId: string | null) {
        if (role === UserRole.SUPER_ADMIN) {
            throw new ForbiddenException('Super Admin cannot be created through the API');
        }

        const { password, ...rest } = createUserDto;
        const hashedPassword = await argon2.hash(password);

        try {
            return await this.prisma.user.create({
                data: {
                    ...rest,
                    hashedPassword,
                    role,
                    tenantId,
                },
            });
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                throw new ConflictException('A user with this email already exists');
            }
            throw error;
        }
    }

    async updateUserForTenant(id: string, tenantId: string, updateUserDto: UpdateUserDto) {
        await this.findByIdForTenant(id, tenantId);

        try {
            return await this.prisma.user.update({
                where: { id },
                data: updateUserDto,
            });
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                throw new ConflictException('A user with this email already exists');
            }
            throw error;
        }
    }

    async removeUserForTenant(id: string, tenantId: string) {
        await this.findByIdForTenant(id, tenantId);

        return this.prisma.user.delete({
            where: { id },
        });
    }

    async changeRoleForTenant(id: string, tenantId: string, role: UserRole) {
        const user = await this.findByIdForTenant(id, tenantId);

        if (user.role === UserRole.ADMIN && role !== UserRole.ADMIN) {
            const adminCount = await this.prisma.user.count({
                where: { tenantId, role: UserRole.ADMIN },
            });

            if (adminCount <= 1) {
                throw new ConflictException('Cannot demote the last remaining Admin in this tenant');
            }
        }

        return this.prisma.user.update({
            where: { id },
            data: { role },
        });
    }

}