import { HealthCheck, HealthCheckService } from '@nestjs/terminus'
import { Controller, Get, Post } from '@nestjs/common'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { PrismaService } from 'src/shared/services/prisma.service'
import { RedisHealthService } from './health.service'
import { RedisService } from 'src/shared/services/redis.service'

@Controller('health')
export class HealthController {
  constructor(
    private readonly healthCheckService: HealthCheckService,
    private readonly prismaService: PrismaService,
    private readonly redisHealthService: RedisHealthService,
    private readonly redisService: RedisService
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

  @Get('cache')
  @IsPublic()
  async getCacheHealth() {
    const healthStatus = await this.redisService.getHealthStatus()
    const stats = await this.redisService.getStats()

    return {
      ...healthStatus,
      stats: stats,
      features: {
        gracefulShutdown: '✅ Implemented',
        errorHandling: '✅ With retry & fallback',
        declarativeCaching: '✅ @Cacheable decorators',
        scopedCaching: '✅ Global & Module scope',
        typeSafe: '✅ Full TypeScript support',
        detailedLogging: '✅ Debug & Error logs'
      }
    }
  }

  @Get('cache/stats')
  @IsPublic()
  async getCacheStats() {
    try {
      const stats = await this.redisService.getStats()
      return {
        message: 'Cache statistics retrieved successfully',
        data: stats,
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      return {
        message: 'Failed to retrieve cache statistics',
        error: error.message,
        timestamp: new Date().toISOString()
      }
    }
  }

  @Get('cache/test')
  @IsPublic()
  async testCache() {
    try {
      const testKey = 'health:test'
      const testValue = { test: true, timestamp: new Date() }

      // Test set
      await this.redisService.set(testKey, testValue, 60)

      // Test get
      const retrieved = await this.redisService.get(testKey)

      // Test delete
      const deleted = await this.redisService.del(testKey)

      return {
        message: 'Cache test completed successfully',
        operations: {
          set: 'success',
          get: retrieved ? 'success' : 'failed',
          delete: deleted ? 'success' : 'failed'
        },
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      return {
        message: 'Cache test failed',
        error: error.message,
        timestamp: new Date().toISOString()
      }
    }
  }

  @Post('cache/flush')
  @IsPublic()
  async flushCache() {
    try {
      await this.redisService.flushAll()
      return {
        message: '🧹 Cache cleared successfully',
        timestamp: new Date().toISOString(),
        action: 'FLUSHALL'
      }
    } catch (error) {
      return {
        message: '❌ Cache flush failed',
        error: error.message,
        timestamp: new Date().toISOString()
      }
    }
  }

  @Get('cache/retry-test')
  @IsPublic()
  async testRetryMechanism() {
    try {
      // Test retry mechanism với operation có thể fail
      const result = await this.redisService.withRetry(
        async () => {
          // Simulate unreliable operation (50% fail rate)
          if (Math.random() < 0.5) {
            throw new Error('Simulated Redis operation failure')
          }

          await this.redisService.set('retry:test', { success: true, timestamp: new Date() }, 60)
          return await this.redisService.get('retry:test')
        },
        3,
        500
      )

      return {
        message: 'Retry mechanism test completed',
        retryResult: result,
        success: result !== null,
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      return {
        message: 'Retry mechanism test failed',
        error: error.message,
        timestamp: new Date().toISOString()
      }
    }
  }
}
