import {
  Controller,
  Get,
  ForbiddenException,
  Post,
  Body,
  Param,
  Patch,
  Delete,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from './users.service';
import { User, UserRole } from '../generated/prisma/client';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { Roles } from '../auth/decorators/roles.decorator';
import { CreateSubordinateUserDto } from './dto/createSubordinateUser.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { ChangeUserRoleDto } from './dto/changeUserRole.dto';
import { ChangePasswordDto } from './dto/changePassword.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { SkipPasswordCheck } from '../auth/decorators/skip-password-check.decorator';

type SafeUser = Omit<User, 'hashedPassword'>;

@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  @Get('me')
  async getMe(@CurrentUser() user: AuthenticatedUser): Promise<SafeUser> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }

    const foundUser = await this.usersService.findByIdForTenant(
      user.userId,
      user.tenantId,
    );
    const { hashedPassword, ...safeUser } = foundUser;

    return safeUser;
  }

  @SkipPasswordCheck()
  @Patch('me/password')
  async changeMyPassword(
    @CurrentUser() user: AuthenticatedUser,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<{
    message: string;
    access_token: string;
    mustChangePassword: boolean;
  }> {
    const updatedUser = await this.usersService.changePassword(
      user.userId,
      changePasswordDto.currentPassword,
      changePasswordDto.newPassword,
    );

    const access_token = this.jwtService.sign({
      sub: updatedUser.id,
      role: updatedUser.role,
      tenantId: updatedUser.tenantId,
      mustChangePassword: updatedUser.mustChangePassword,
    });

    return {
      message: 'Password changed successfully',
      access_token,
      mustChangePassword: updatedUser.mustChangePassword,
    };
  }

  @Roles(UserRole.ADMIN)
  @Post()
  async createUser(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createSubordinateUserDto: CreateSubordinateUserDto,
  ): Promise<SafeUser> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }

    const createdUser = await this.usersService.createUser(
      createSubordinateUserDto,
      createSubordinateUserDto.role,
      user.tenantId,
    );

    const { hashedPassword, ...safeUser } = createdUser;
    return safeUser;
  }

  @Roles(UserRole.ADMIN)
  @Get()
  async getAllUsers(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<SafeUser[]> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }

    const users = await this.usersService.findAllForTenant(user.tenantId);
    return users.map(({ hashedPassword, ...safeUser }) => safeUser);
  }

  @Roles(UserRole.ADMIN)
  @Get(':id')
  async getUserById(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ): Promise<SafeUser> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }

    const foundUser = await this.usersService.findByIdForTenant(
      id,
      user.tenantId,
    );
    const { hashedPassword, ...safeUser } = foundUser;

    return safeUser;
  }

  @Roles(UserRole.ADMIN)
  @Patch(':id')
  async updateUserById(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<SafeUser> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }

    const updatedUser = await this.usersService.updateUserForTenant(
      id,
      user.tenantId,
      updateUserDto,
    );
    const { hashedPassword, ...safeUser } = updatedUser;

    return safeUser;
  }

  @Roles(UserRole.ADMIN)
  @Patch(':id/role')
  async updateUserRoleById(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() changeUserRoleDto: ChangeUserRoleDto,
  ): Promise<SafeUser> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    if (id === user.userId) {
      throw new ForbiddenException('You cannot change your own role');
    }

    const updatedUser = await this.usersService.changeRoleForTenant(
      id,
      user.tenantId,
      changeUserRoleDto.role,
    );
    const { hashedPassword, ...safeUser } = updatedUser;

    return safeUser;
  }

  @Roles(UserRole.ADMIN)
  @Post(':id/reset-password')
  async resetUserPassword(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }

    await this.usersService.resetPasswordForTenant(
      id,
      user.tenantId,
      resetPasswordDto.newPassword,
    );

    return { message: 'Password reset successfully' };
  }

  @Roles(UserRole.ADMIN)
  @Delete(':id')
  async deleteUserById(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ): Promise<{ message: string; id: string }> {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    if (id === user.userId) {
      throw new ForbiddenException('You cannot delete your own account');
    }

    const deletedUser = await this.usersService.removeUserForTenant(
      id,
      user.tenantId,
    );

    return { message: 'User deleted successfully', id: deletedUser.id };
  }
}
