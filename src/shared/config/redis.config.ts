import { registerAs } from '@nestjs/config'
import Client from 'ioredis'
import Redlock from 'redlock'

export default registerAs('redis', (): Record<string, any> => {
  const config = {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    password: process.env.REDIS_PASSWORD,
    tls: process.env.REDIS_ENABLE_TLS === 'true' ? {} : null
  }

  // Khởi tạo Redis client với connection pooling tối ưu
  const redis = new Client({
    host: config.host,
    port: Number(config.port),
    password: config.password,
    tls: config.tls || undefined,
    // Tối ưu connection pooling
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: true,
    // Connection pool settings
    connectionName: 'shopsifu-app',
    // Tối ưu cho production
    keepAlive: 30000,
    family: 4,
    // Timeout settings
    connectTimeout: 10000,
    commandTimeout: 5000
  })

  // Khởi tạo Redlock
  const redlock = new Redlock([redis], {
    retryCount: 3,
    retryDelay: 200 // time in ms
  })

  return {
    ...config,
    redis,
    redlock
  }
})
