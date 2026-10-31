import { Module, forwardRef } from '@nestjs/common';
import { ThreatIntelService } from './threat-intel.service';
import { ThreatIntelController } from './threat-intel.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { IocModule } from '../ioc/ioc.module';
import { AuditModule } from '../audit/audit.module';
import { EventsModule } from '../events/events.module';

@Module({
  imports: [
    PrismaModule,
    IocModule,
    forwardRef(() => AuditModule),
    forwardRef(() => EventsModule),
  ],
  controllers: [ThreatIntelController],
  providers: [ThreatIntelService],
  exports: [ThreatIntelService],
})
export class ThreatIntelModule {}
