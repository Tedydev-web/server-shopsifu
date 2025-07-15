import Client from 'ioredis'
import Redlock from 'redlock'

export const redis = new Client(process.env.REDIS_URL)
export const redlock = new Redlock([redis], {
  retryCount: 3,
  retryDelay: 200 // time in ms
})
