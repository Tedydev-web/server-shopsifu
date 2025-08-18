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

  const isPasswordProvided: boolean =
    config.requireAuth && typeof config.password === 'string' && config.password.trim().length > 0

  // Nếu không có password, loại bỏ thông tin xác thực trong URL (nếu có)
  let sanitizedUrl: string | undefined = config.url
  if (!isPasswordProvided && typeof config.url === 'string' && config.url.length > 0) {
    try {
      const parsed = new URL(config.url)
      if (parsed.username || parsed.password) {
        parsed.username = ''
        parsed.password = ''
        sanitizedUrl = parsed.toString()
      }
    } catch {
      // Bỏ qua nếu URL không hợp lệ; giữ nguyên
    }
  }

  // Khởi tạo Redis client với connection pooling tối ưu
  const redis = sanitizedUrl
    ? new Client(sanitizedUrl, {
        // Tối ưu connection pooling
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: true,
        // Connection pool settings
        connectionName: config.connectionName,
        // Tối ưu cho production
        keepAlive: 30000,
        family: 4,
        // Timeout settings
        connectTimeout: 10000,
        commandTimeout: 5000
      })
    : new Client({
        host: config.host,
        port: Number(config.port),
        ...(isPasswordProvided ? { password: config.password } : {}),
        tls: config.tls || undefined,
        // Tối ưu connection pooling
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: true,
        // Connection pool settings
        connectionName: config.connectionName,
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
    url: sanitizedUrl ?? config.url,
    redis,
    redlock
  }
})
