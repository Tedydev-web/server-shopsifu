import { registerAs } from '@nestjs/config'
import Client from 'ioredis'
import Redlock from 'redlock'

export default registerAs('redis', (): Record<string, any> => {
  const config = {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    password: process.env.REDIS_PASSWORD,
    tls: process.env.REDIS_ENABLE_TLS === 'true' ? {} : null,
    url: process.env.REDIS_URL,
    connectionName: process.env.REDIS_CONNECTION_NAME,
    requireAuth: process.env.REDIS_REQUIRE_AUTH === 'true'
  }

  const isPasswordProvided: boolean = typeof config.password === 'string' && config.password.trim().length > 0

  // Redis options chung cho cả hai trường hợp
  const commonRedisOptions = {
    // Connection settings
    lazyConnect: false, // Kết nối ngay lập tức để kiểm tra
    connectionName: config.connectionName || 'shopsifu-main',

    // Timeout settings
    connectTimeout: 15000,
    commandTimeout: 10000,

    // Retry settings
    maxRetriesPerRequest: 5,

    // Auto reconnect
    autoResubscribe: true,
    autoResendUnfulfilledCommands: true,

    // Health check
    healthCheckInterval: 30000,

    // Connection pool
    keepAlive: 30000,
    family: 4,

    // Error handling
    enableReadyCheck: true,
    enableOfflineQueue: true,
    maxLoadingTimeout: 10000
  }

  // Khởi tạo Redis client với connection pooling tối ưu và error handling
  const redis = config.url
    ? new Client(config.url, commonRedisOptions)
    : new Client({
        host: config.host,
        port: Number(config.port),
        ...(isPasswordProvided ? { password: config.password } : {}),
        tls: config.tls || undefined,
        ...commonRedisOptions
      })

  // Event handlers để xử lý connection errors
  redis.on('error', (error) => {
    console.error('❌ Redis connection error:', error.message)
  })

  redis.on('connect', () => {
    console.log('✅ Redis connected successfully')
  })

  redis.on('ready', () => {
    console.log('✅ Redis ready for commands')
  })

  redis.on('close', () => {
    console.log('⚠️ Redis connection closed')
  })

  redis.on('reconnecting', (delay) => {
    console.log(`🔄 Redis reconnecting in ${delay}ms`)
  })

  redis.on('end', () => {
    console.log('🔌 Redis connection ended')
  })

  // Khởi tạo Redlock với retry logic tốt hơn
  const redlock = new Redlock([redis], {
    retryCount: 5, // Tăng retry count
    retryDelay: 200, // time in ms
    retryJitter: 100, // Thêm jitter để tránh thundering herd
    automaticExtensionThreshold: 500 // Tự động extend lock
  })

  return {
    ...config,
    url: config.url,
    redis,
    redlock
  }
})
