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

    async findById(id: string) {
        const user = await this.prisma.user.findUnique({
            where: { id },
        });

        if (!user) {
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

    async updateUser(id: string, updateUserDto: UpdateUserDto) {
        try {
            return await this.prisma.user.update({
                where: { id },
                data: updateUserDto,
            });
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                if (error.code === 'P2025') {
                    throw new NotFoundException('User not found');
                }
                if (error.code === 'P2002') {
                    throw new ConflictException('A user with this email already exists');
                }
            }
            throw error;
        }
    }

    async removeUser(id: string) {
        try {
            return await this.prisma.user.delete({
                where: { id },
            });
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
                throw new NotFoundException('User not found');
            }
            throw error;
        }
    }

}