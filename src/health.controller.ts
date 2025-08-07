import { Controller, Get } from '@nestjs/common'
import { HealthCheck, HealthCheckService } from '@nestjs/terminus'

import { PrismaService } from 'src/shared/services/prisma.service'
import { IsPublic } from 'src/shared/decorators/auth.decorator'

@Controller('/health')
export class HealthController {
  constructor(
    private readonly healthCheckService: HealthCheckService,
    private readonly prismaService: PrismaService
  ) {}

  @Get()
  @HealthCheck()
  @IsPublic()
  public async getHealth() {
    return this.healthCheckService.check([() => this.prismaService.isHealthy()])
  }
}
