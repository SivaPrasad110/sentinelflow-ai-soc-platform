import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from './roles.guard';
import { Role } from '@prisma/client';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  const createMockContext = (role?: Role): ExecutionContext => {
    return {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => ({
          user: role
            ? {
                id: 'USR-001',
                email: 'test@sentinelflow.local',
                organizationId: 'org-1',
                role,
              }
            : undefined,
        }),
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  it('should allow access if no roles are required on endpoint', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
    const ctx = createMockContext(Role.VIEWER);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should permit ANALYST on endpoints requiring [ANALYST, ADMIN]', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ANALYST, Role.ADMIN]);
    const ctx = createMockContext(Role.ANALYST);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should permit ADMIN on endpoints requiring [ANALYST, ADMIN]', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ANALYST, Role.ADMIN]);
    const ctx = createMockContext(Role.ADMIN);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should block VIEWER on endpoints requiring [ANALYST, ADMIN] with ForbiddenException', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ANALYST, Role.ADMIN]);
    const ctx = createMockContext(Role.VIEWER);
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('should block ANALYST on sensitive endpoints requiring [ADMIN] with ForbiddenException', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ADMIN]);
    const ctx = createMockContext(Role.ANALYST);
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('should permit ADMIN on endpoints requiring [ADMIN]', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ADMIN]);
    const ctx = createMockContext(Role.ADMIN);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should permit VIEWER on read endpoints requiring [VIEWER]', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.VIEWER, Role.ANALYST, Role.ADMIN]);
    const ctx = createMockContext(Role.VIEWER);
    expect(guard.canActivate(ctx)).toBe(true);
  });
});
