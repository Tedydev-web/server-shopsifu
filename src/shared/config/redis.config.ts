import { registerAs } from '@nestjs/config'
import Client from 'ioredis'
import Redlock from 'redlock'

export default registerAs('redis', (): Record<string, any> => {
  const config = {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || '6379',
    password: process.env.REDIS_PASSWORD,
    tls: process.env.REDIS_ENABLE_TLS === 'true' ? {} : null,
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    connectionName: process.env.REDIS_CONNECTION_NAME,
    requireAuth: process.env.REDIS_REQUIRE_AUTH === 'true',
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'shopsifu:',
    defaultTtl: Number(process.env.REDIS_DEFAULT_TTL) || 300,
    enableLogging: process.env.REDIS_ENABLE_LOGGING !== 'false'
  }

  const commonRedisOptions = {
    lazyConnect: false,
    connectionName: config.connectionName || 'shopsifu-main',

    connectTimeout: 20000,
    commandTimeout: 15000,
    keepAlive: 60000,

    retryDelayOnFailover: 500,
    retryDelayOnClusterDown: 1000,
    retryDelayOnTryAgain: 300,
    maxRetriesPerRequest: null,

    autoResubscribe: true,
    autoResendUnfulfilledCommands: false,

    reconnectOnError: (err) => {
      const errorMsg = err.message.toLowerCase()

      if (
        errorMsg.includes('socket') ||
        errorMsg.includes('connection') ||
        errorMsg.includes('econnreset') ||
        errorMsg.includes('epipe') ||
        errorMsg.includes('readonly') ||
        errorMsg.includes('noscript') ||
        err.code === 'NR_CLOSED'
      ) {
        console.log(`🔄 Redis auto-reconnect: ${err.message}`)
        return true
      }
      return false
    },

    family: 4,
    enableReadyCheck: true,
    enableOfflineQueue: true,
    maxLoadingTimeout: 20000,

    showFriendlyErrorStack: true,

    dropBufferSupport: false,
    enableAutoPipelining: true
  }

  const redis = config.url
    ? new Client(config.url, commonRedisOptions)
    : new Client({
        host: config.host,
        port: Number(config.port),
        password: config.password,
        tls: config.tls || undefined,
        ...(config.requireAuth ? { password: config.password } : {}),
        ...commonRedisOptions
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
