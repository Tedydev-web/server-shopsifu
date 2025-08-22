import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Cron, CronExpression } from '@nestjs/schedule'

@Injectable()
export class RedisHealthService {
  private readonly logger = new Logger(RedisHealthService.name)
  private readonly redis = this.configService.get('redis.redis')
  private isHealthy = false

  constructor(private readonly configService: ConfigService) {
    this.setupEventListeners()
    this.performHealthCheck()
  }

  private setupEventListeners() {
    if (!this.redis) return

    this.redis.on('connect', () => {
      this.logger.log('✅ Redis connected')
      this.isHealthy = true
    })

    this.redis.on('ready', () => {
      this.logger.log('✅ Redis ready')
      this.isHealthy = true
    })

    this.redis.on('error', (error) => {
      this.logger.error(`❌ Redis error: ${error.message}`)
      this.isHealthy = false
    })

    this.redis.on('close', () => {
      this.logger.warn('⚠️ Redis connection closed')
      this.isHealthy = false
    })

    this.redis.on('reconnecting', (delay) => {
      this.logger.log(`🔄 Redis reconnecting in ${delay}ms`)
    })

    this.redis.on('end', () => {
      this.logger.warn('🔌 Redis connection ended')
      this.isHealthy = false
    })
  }

  @Cron(CronExpression.EVERY_30_SECONDS)
  async performHealthCheck() {
    if (!this.redis) return

    try {
      // Ping Redis để kiểm tra connection
      const result = await this.redis.ping()
      if (result === 'PONG') {
        this.isHealthy = true
        this.logger.debug('Redis health check: OK')
      } else {
        this.isHealthy = false
        this.logger.warn('Redis health check: Unexpected response')
      }
    } catch (error) {
      this.isHealthy = false
      this.logger.error(`Redis health check failed: ${error.message}`)

      // Thử reconnect nếu connection bị mất
      if (this.redis.status === 'end') {
        this.logger.log('Attempting to reconnect to Redis...')
        try {
          await this.redis.connect()
        } catch (reconnectError) {
          this.logger.error(`Redis reconnection failed: ${reconnectError.message}`)
        }
      }
    }
  }

  isRedisHealthy(): boolean {
    return this.isHealthy
  }

  getRedisStatus(): string {
    if (!this.redis) return 'NOT_INITIALIZED'
    return this.redis.status
  }

  async getRedisInfo(): Promise<any> {
    if (!this.redis || !this.isHealthy) {
      return { status: 'unhealthy', message: 'Redis not available' }
    }

    try {
      const info = await this.redis.info()
      return {
        status: 'healthy',
        connection: this.redis.status,
        info: info.substring(0, 500) + '...' // Truncate long info
      }
    } catch (error) {
      return {
        status: 'error',
        message: error.message
      }
    }
  }
}
