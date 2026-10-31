import { Module, Global } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { EventsGateway } from './events.gateway';
import { PrismaModule } from '../prisma/prisma.module';

@Global()
@Module({
  imports: [JwtModule.register({}), ConfigModule, PrismaModule],
  providers: [EventsGateway],
  exports: [EventsGateway],
})
export class EventsModule {}
