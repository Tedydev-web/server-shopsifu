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

  const commonRedisOptions = {
    lazyConnect: true,
    connectionName: config.connectionName || 'shopsifu-main',
    connectTimeout: 30000,
    commandTimeout: 20000,
    keepAlive: 60000,
    retryDelayOnFailover: 100,
    retryDelayOnClusterDown: 300,
    retryDelayOnTryAgain: 100,
    autoResubscribe: true,
    autoResendUnfulfilledCommands: true,
    reconnectOnError: (err) => {
      const targetError = 'READONLY'
      if (err.message.includes(targetError)) {
        return true
      }
      return false
    },

    family: 4,
    enableReadyCheck: true,
    enableOfflineQueue: true,
    maxLoadingTimeout: 20000,

    maxRetriesPerRequest: 3,
    showFriendlyErrorStack: process.env.NODE_ENV === 'development'
  }

  const redis = config.url
    ? new Client(config.url, commonRedisOptions)
    : new Client({
        host: config.host,
        port: Number(config.port),
        ...(isPasswordProvided ? { password: config.password } : {}),
        tls: config.tls || undefined,
        ...commonRedisOptions
      })

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

  const redlock = new Redlock([redis], {
    retryCount: 10,
    retryDelay: 200,
    retryJitter: 100,
    automaticExtensionThreshold: 500
  })

  return {
    ...config,
    url: config.url,
    redis,
    redlock
  }
})
