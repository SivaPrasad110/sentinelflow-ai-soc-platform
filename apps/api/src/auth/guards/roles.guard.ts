import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { AuthenticatedUser } from '../decorators/current-user.decorator';

const ROLE_HIERARCHY: Record<Role, number> = {
  [Role.VIEWER]: 1,
  [Role.ANALYST]: 2,
  [Role.ADMIN]: 3,
};

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<{ user?: AuthenticatedUser }>();

    if (!user || !user.role) {
      throw new ForbiddenException('Access denied: no organization role assigned to user context.');
    }

    const userLevel = ROLE_HIERARCHY[user.role] ?? 0;
    const minRequiredLevel = Math.min(...requiredRoles.map((r) => ROLE_HIERARCHY[r] ?? 99));

    const hasPermission = userLevel >= minRequiredLevel || requiredRoles.includes(user.role);

    if (!hasPermission) {
      throw new ForbiddenException(
        `Insufficient permissions: role "${user.role}" does not satisfy required role(s): [${requiredRoles.join(', ')}].`,
      );
    }

    return true;
  }
}
