import Client from 'ioredis'
import Redlock from 'redlock'
import envConfig from 'src/shared/config'

export const redis = new Client(envConfig.REDIS_URL)
export const redlock = new Redlock([redis], {
  retryCount: 3,
  retryDelay: 200, // time in ms
})
