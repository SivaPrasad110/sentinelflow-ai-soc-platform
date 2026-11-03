import { Test, TestingModule } from '@nestjs/testing';
import { EventsGateway } from './events.gateway';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';

describe('EventsGateway (Phase 5 WebSocket Event Streaming)', () => {
  let gateway: EventsGateway;
  let mockServer: any;

  beforeEach(async () => {
    mockServer = {
      to: jest.fn().mockReturnThis(),
      emit: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EventsGateway,
        {
          provide: JwtService,
          useValue: {
            verifyAsync: jest.fn().mockResolvedValue({
              sub: 'usr-1',
              email: 'sarah.chen@sentinelflow.local',
              organizationId: 'org-sentinel-corp',
              role: 'ANALYST',
            }),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('test-secret'),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            organizationMembership: {
              findFirst: jest.fn().mockResolvedValue({ id: 'mem-1', role: 'ANALYST' }),
            },
          },
        },
      ],
    }).compile();

    gateway = module.get<EventsGateway>(EventsGateway);
    gateway.server = mockServer;
  });

  it('should be defined', () => {
    expect(gateway).toBeDefined();
  });

  it('should broadcast event strictly to the designated organization room', () => {
    const orgId = 'org-sentinel-corp';
    const payload = { id: 'ALT-1', title: 'Suspicious Execution' };

    gateway.broadcastToOrg(orgId, 'alert:created', payload);

    expect(mockServer.to).toHaveBeenCalledWith(`org:${orgId}`);
    expect(mockServer.emit).toHaveBeenCalledWith('alert:created', payload);
  });

  it('should allow clients to switch organization rooms', async () => {
    const mockClient: any = {
      activeOrgId: 'old-org',
      orgMemberships: ['org-new-corp'],
      leave: jest.fn(),
      join: jest.fn(),
      emit: jest.fn(),
    };

    const res = await gateway.handleOrgSwitch(mockClient, { organizationId: 'org-new-corp' });

    expect(mockClient.leave).toHaveBeenCalledWith('org:old-org');
    expect(mockClient.join).toHaveBeenCalledWith('org:org-new-corp');
    expect(res).toEqual({ success: true, organizationId: 'org-new-corp' });
  });

  describe('WebSocket CORS Security Configuration', () => {
    it('should verify gateway metadata includes credentials: true and secure namespace /events', () => {
      // Reflect metadata defined by @WebSocketGateway
      const metadata = Reflect.getMetadata('websockets:gateway_options', EventsGateway);
      expect(metadata).toBeDefined();
      expect(metadata.namespace).toBe('/events');
      expect(metadata.cors).toBeDefined();
      expect(metadata.cors.credentials).toBe(true);
      expect(typeof metadata.cors.origin).toBe('function');
    });

    it('should validate allowed and rejected origins via the gateway CORS callback', (done) => {
      const metadata = Reflect.getMetadata('websockets:gateway_options', EventsGateway);
      const corsCallback = metadata.cors.origin;

      // 1. Production Vercel frontend should be permitted
      corsCallback(
        'https://sentinelflow-ai-soc-platform-beryl.vercel.app',
        (err: Error | null, allow?: boolean) => {
          expect(err).toBeNull();
          expect(allow).toBe(true);

          // 2. Production Render backend should be permitted
          corsCallback(
            'https://sentinelflow-api-ohio.onrender.com',
            (err2: Error | null, allow2?: boolean) => {
              expect(err2).toBeNull();
              expect(allow2).toBe(true);

              // 3. Requests without Origin header should be permitted
              corsCallback(undefined, (err3: Error | null, allow3?: boolean) => {
                expect(err3).toBeNull();
                expect(allow3).toBe(true);

                // 4. Unauthorized origins should be rejected with Error
                corsCallback('https://evil-unauthorized-site.com', (err4: Error | null) => {
                  expect(err4).toBeInstanceOf(Error);
                  expect(err4?.message).toContain('WebSocket CORS: origin "https://evil-unauthorized-site.com" not allowed');
                  done();
                });
              });
            },
          );
        },
      );
    });
  });
});
