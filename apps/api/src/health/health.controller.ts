import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { HealthService } from './health.service';
import { SystemHealthResponse } from '@sentinelflow/shared';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Check API and integrated services status' })
  @ApiResponse({
    status: 200,
    description: 'Returns health status of SentinelFlow platform',
  })
  async getHealth(): Promise<SystemHealthResponse> {
    return this.healthService.checkHealth();
  }
}
