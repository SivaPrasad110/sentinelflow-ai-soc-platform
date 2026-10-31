import { Module, forwardRef } from '@nestjs/common';
import { IocService } from './ioc.service';
import { IocController } from './ioc.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { EventsModule } from '../events/events.module';

@Module({
  imports: [
    PrismaModule,
    forwardRef(() => AuditModule),
    forwardRef(() => EventsModule),
  ],
  controllers: [IocController],
  providers: [IocService],
  exports: [IocService],
})
export class IocModule {}
