import { HealthCheck, HealthCheckService } from '@nestjs/terminus'
import { Controller, Get } from '@nestjs/common'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { PrismaService } from 'src/shared/services/prisma.service'

@Controller('health')
export class HealthController {
  constructor(
    private readonly healthCheckService: HealthCheckService,
    private readonly prismaService: PrismaService,
  ) {}

  @Get()
  @IsPublic()
  public async getHealthSimple() {
    return { status: 'ok', timestamp: new Date().toISOString() }
  }

  @Get('check')
  @HealthCheck()
  @IsPublic()
  public async getHealth() {
    return this.healthCheckService.check([() => this.prismaService.isHealthy()])
  }
}
