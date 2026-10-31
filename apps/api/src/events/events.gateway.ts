import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  userEmail?: string;
  activeOrgId?: string;
  orgMemberships?: string[];
}

@WebSocketGateway({
  cors: {
    origin: '*',
    credentials: true,
  },
  namespace: '/events',
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  private readonly logger = new Logger(EventsGateway.name);

  @WebSocketServer()
  server!: Server;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async handleConnection(client: AuthenticatedSocket) {
    try {
      const token =
        client.handshake.auth?.token ||
        client.handshake.headers?.authorization?.replace('Bearer ', '');

      if (!token) {
        this.logger.debug(`Socket disconnected: missing auth token [${client.id}]`);
        client.disconnect();
        return;
      }

      const secret = this.configService.get<string>('JWT_ACCESS_SECRET') || 'sentinelflow-access-jwt-secret-2026';
      const payload = this.jwtService.verify(token, { secret });

      // Fetch user and memberships from database
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        include: { memberships: true },
      });

      if (!user) {
        client.disconnect();
        return;
      }

      client.userId = user.id;
      client.userEmail = user.email;
      client.orgMemberships = user.memberships.map((m) => m.organizationId);

      // Determine requested org or fallback to user's first membership
      const requestedOrg = client.handshake.auth?.organizationId || payload.orgId;
      const validOrg = client.orgMemberships.includes(requestedOrg)
        ? requestedOrg
        : client.orgMemberships[0];

      if (validOrg) {
        client.activeOrgId = validOrg;
        client.join(`org:${validOrg}`);
        this.logger.log(`Socket client connected [${client.id}] user=${user.email} joined org=${validOrg}`);
      } else {
        this.logger.warn(`User ${user.email} has no active organization memberships`);
        client.disconnect();
      }
    } catch (err: any) {
      this.logger.debug(`Socket authentication failed [${client.id}]: ${err.message}`);
      client.disconnect();
    }
  }

  handleDisconnect(client: AuthenticatedSocket) {
    this.logger.debug(`Socket client disconnected [${client.id}]`);
  }

  @SubscribeMessage('org:switch')
  async handleOrgSwitch(
    @ConnectedSocket() client: AuthenticatedSocket,
    @MessageBody() data: { organizationId: string },
  ) {
    if (!client.orgMemberships || !data?.organizationId) return;

    if (client.orgMemberships.includes(data.organizationId)) {
      if (client.activeOrgId) {
        client.leave(`org:${client.activeOrgId}`);
      }
      client.activeOrgId = data.organizationId;
      client.join(`org:${data.organizationId}`);
      this.logger.log(`Socket client [${client.id}] switched to org room: ${data.organizationId}`);
      return { success: true, organizationId: data.organizationId };
    } else {
      this.logger.warn(`Unauthorized org switch attempt by user ${client.userEmail} to org ${data.organizationId}`);
      return { success: false, error: 'Unauthorized organization' };
    }
  }

  /**
   * Broadcast tenant-scoped event strictly to clients in that organization's room
   */
  broadcastToOrg(organizationId: string, event: string, payload: any) {
    if (!this.server) {
      this.logger.warn(`Cannot broadcast ${event}: WebSocket server not initialized`);
      return;
    }
    this.server.to(`org:${organizationId}`).emit(event, payload);
  }
}
