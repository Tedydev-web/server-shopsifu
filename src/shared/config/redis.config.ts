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

  // Khởi tạo Redis client
  const redis = new Client({
    host: config.host,
    port: Number(config.port),
    password: config.password,
    tls: config.tls || undefined
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
