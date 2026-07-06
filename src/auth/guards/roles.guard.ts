import { Injectable, ExecutionContext, UnauthorizedException, CanActivate } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { UserRole } from 'src/generated/prisma/enums';

@Injectable()
export class RolesGuard implements CanActivate { 
    constructor(private reflector: Reflector) { }
    
    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredRoles) {
            return true;
        }
        const { user } = context.switchToHttp().getRequest();
        if (!user || !user.role) {
            throw new UnauthorizedException('User role not found');
        }
        return requiredRoles.includes(user.role);
    }
}