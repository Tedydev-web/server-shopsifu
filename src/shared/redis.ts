import Client from 'ioredis'
import Redlock from 'redlock'

/**
 * Khởi tạo kết nối Redis sử dụng URL từ biến môi trường.
 * Nếu không có REDIS_URL, sẽ sử dụng giá trị mặc định 'redis://localhost:6379'.
 */
const redisUrl: string = process.env.REDIS_URL ?? 'redis://localhost:6379'
export const redis: Client = new Client(redisUrl)

/**
 * Khởi tạo Redlock để quản lý distributed lock với Redis.
 */
export const redlock: Redlock = new Redlock([redis], {
  retryCount: 3,
  retryDelay: 200 // thời gian chờ giữa các lần retry (ms)
})
