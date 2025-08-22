import { HealthCheck, HealthCheckService } from '@nestjs/terminus'
import { Controller, Get } from '@nestjs/common'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { PrismaService } from 'src/shared/services/prisma.service'
import { RedisHealthService } from './health.service'

@Controller('health')
export class HealthController {
  constructor(
    private readonly healthCheckService: HealthCheckService,
    private readonly prismaService: PrismaService,
    private readonly redisHealthService: RedisHealthService
  ) {}

  @Get()
  @IsPublic()
  public async getHealthSimple() {
    return { status: 'ok', timestamp: new Date().toISOString() }
  }

  @Get('check-prisma')
  @HealthCheck()
  @IsPublic()
  public async getHealth() {
    return this.healthCheckService.check([() => this.prismaService.isHealthy()])
  }

  @Get('redis')
  async getRedisHealth() {
    const redisInfo = await this.redisHealthService.getRedisInfo()
    return {
      ...redisInfo,
      timestamp: new Date().toISOString()
    }
  }

  @Get('redis/status')
  getRedisStatus() {
    return {
      healthy: this.redisHealthService.isRedisHealthy(),
      status: this.redisHealthService.getRedisStatus(),
      timestamp: new Date().toISOString()
    }
  }
}
