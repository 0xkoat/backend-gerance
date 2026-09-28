import { Body, Controller, Delete, Get, Param, Post } from '@nestjs/common';
import { UsersService } from './users.service';
import { User, UserRole } from '../generated/prisma/client';
import { Roles } from '../auth/decorators/roles.decorator';
import { CreateUserDto } from './dto/createUser.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';

type SafeUser = Omit<User, 'hashedPassword'>;

// Integration Admins are platform-wide (tenantId null): they manage module
// endpoints and receive Module tickets. Only a Super Admin provisions them,
// the same way a Super Admin provisions each tenant's first Admin — role and
// tenantId are fixed by this endpoint, never taken from the body.
@Controller('integration-admins')
@Roles(UserRole.SUPER_ADMIN)
export class IntegrationAdminsController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async create(@Body() createUserDto: CreateUserDto): Promise<SafeUser> {
    const created = await this.usersService.createUser(
      createUserDto,
      UserRole.INTEGRATION_ADMIN,
      null,
    );
    const { hashedPassword: _hashedPassword, ...safeUser } = created;
    return safeUser;
  }

  @Get()
  findAll(): Promise<SafeUser[]> {
    return this.usersService.findAllIntegrationAdmins();
  }

  @Post(':id/reset-password')
  async resetPassword(
    @Param('id') id: string,
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    await this.usersService.resetIntegrationAdminPassword(
      id,
      resetPasswordDto.newPassword,
    );
    return { message: 'Password reset successfully' };
  }

  @Delete(':id')
  async remove(
    @Param('id') id: string,
  ): Promise<{ message: string; id: string }> {
    await this.usersService.removeIntegrationAdmin(id);
    return { message: 'Integration Admin deleted successfully', id };
  }
}
