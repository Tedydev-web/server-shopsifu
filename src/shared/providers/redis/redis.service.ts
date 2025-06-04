import { Injectable, Inject, Logger, OnModuleDestroy, OnModuleInit, HttpStatus } from '@nestjs/common'
import Redis, { RedisKey, RedisValue } from 'ioredis'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { REDIS_CLIENT } from 'src/shared/constants/injection.tokens'
import { CryptoService } from '../../services/crypto.service'

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)

  constructor(
    @Inject(REDIS_CLIENT) private readonly redisClient: Redis,
    private readonly cryptoService?: CryptoService
  ) {}

  async onModuleInit() {
    try {
      await this.redisClient.ping()
      this.logger.log('Redis connection established successfully')
    } catch (error) {
      this.logger.error(`Failed to connect to Redis: ${error.message}`, error.stack)
    }
  }

  onModuleDestroy() {
    this.redisClient.disconnect()
  }

  get client(): Redis {
    return this.redisClient
  }

  // --- Core Redis Methods ---

  /**
   * SET - Thiết lập giá trị với key
   * @returns "OK" nếu thành công
   */
  async set(
    key: RedisKey,
    value: RedisValue,
    mode?: string,
    duration?: number,
    condition?: string
  ): Promise<'OK' | null> {
    try {
      const args: any[] = []
      if (mode) {
        args.push(mode)
        if (duration !== undefined) {
          args.push(duration)
        }
      }
      if (condition) {
        args.push(condition)
      }

      return await this.redisClient.set(key, value, ...args)
    } catch (error) {
      this.logger.error(`Redis SET error: ${error.message}`)
      throw error
    }
  }

  /**
   * GET - Lấy giá trị từ key
   */
  async get(key: RedisKey): Promise<string | null> {
    try {
      return await this.redisClient.get(key)
    } catch (error) {
      this.logger.error(`Redis GET error: ${error.message}`)
      throw error
    }
  }

  /**
   * DEL - Xóa key
   * @returns Số lượng key đã xóa
   */
  async del(keys: RedisKey | RedisKey[]): Promise<number> {
    try {
      const keysToDelete = Array.isArray(keys) ? keys : [keys]
      if (keysToDelete.length === 0) return 0
      return await this.redisClient.del(keysToDelete)
    } catch (error) {
      this.logger.error(`Redis DEL error: ${error.message}`)
      throw error
    }
  }

  /**
   * EXISTS - Kiểm tra key có tồn tại không
   * @returns Số lượng key tồn tại
   */
  async exists(keys: RedisKey | RedisKey[]): Promise<number> {
    try {
      const keysToCheck = Array.isArray(keys) ? keys : [keys]
      if (keysToCheck.length === 0) return 0
      return await this.redisClient.exists(keysToCheck)
    } catch (error) {
      this.logger.error(`Redis EXISTS error: ${error.message}`)
      throw error
    }
  }

  /**
   * EXPIRE - Thiết lập thời gian hết hạn cho key
   * @returns 1 nếu thành công, 0 nếu key không tồn tại
   */
  async expire(key: RedisKey, seconds: number): Promise<number> {
    try {
      if (typeof seconds !== 'number' || isNaN(seconds) || !isFinite(seconds) || Math.floor(seconds) !== seconds) {
        throw new ApiException(HttpStatus.BAD_REQUEST, 'BadRequest', 'Error.Global.BadRequest')
      }
      return await this.redisClient.expire(key, seconds)
    } catch (error) {
      this.logger.error(`Redis EXPIRE error: ${error.message}`)
      throw error
    }
  }

  /**
   * TTL - Lấy thời gian còn lại của key
   * @returns Thời gian còn lại (giây)
   */
  async ttl(key: RedisKey): Promise<number> {
    try {
      return await this.redisClient.ttl(key)
    } catch (error) {
      this.logger.error(`Redis TTL error: ${error.message}`)
      throw error
    }
  }

  /**
   * INCR - Tăng giá trị của key lên 1
   */
  async incr(key: RedisKey): Promise<number> {
    return await this.redisClient.incr(key)
  }

  /**
   * DECR - Giảm giá trị của key đi 1
   */
  async decr(key: RedisKey): Promise<number> {
    return await this.redisClient.decr(key)
  }

  // --- Hash Commands ---

  /**
   * HSET - Thiết lập giá trị cho field trong hash
   * @returns Số field được tạo mới
   */
  async hset(key: RedisKey, field: string | Record<string, RedisValue>, value?: RedisValue): Promise<number> {
    try {
      if (typeof field === 'string' && value !== undefined) {
        return await this.redisClient.hset(key, field, value)
      }
      if (typeof field === 'object') {
        return await this.redisClient.hset(key, field)
      }
      throw new Error('Invalid arguments for hset')
    } catch (error) {
      this.logger.error(`Redis HSET error: ${error.message}`)
      throw error
    }
  }

  /**
   * HGET - Lấy giá trị của field trong hash
   */
  async hget(key: RedisKey, field: string): Promise<string | null> {
    try {
      return await this.redisClient.hget(key, field)
    } catch (error) {
      this.logger.error(`Redis HGET error: ${error.message}`)
      throw error
    }
  }

  /**
   * HMGET - Lấy nhiều field từ hash
   */
  async hmget(key: RedisKey, fields: string[]): Promise<(string | null)[]> {
    if (fields.length === 0) return []
    return await this.redisClient.hmget(key, ...fields)
  }

  /**
   * HGETALL - Lấy tất cả field và giá trị trong hash
   */
  async hgetall(key: RedisKey): Promise<Record<string, string>> {
    try {
      return await this.redisClient.hgetall(key)
    } catch (error) {
      this.logger.error(`Redis HGETALL error: ${error.message}`)
      throw error
    }
  }

  /**
   * HDEL - Xóa field trong hash
   */
  async hdel(key: RedisKey, fields: string | string[]): Promise<number> {
    const fieldsToDelete = Array.isArray(fields) ? fields : [fields]
    if (fieldsToDelete.length === 0) return 0
    return await this.redisClient.hdel(key, ...fieldsToDelete)
  }

  /**
   * HINCRBY - Tăng giá trị của field trong hash
   */
  async hincrby(key: RedisKey, field: string, increment: number): Promise<number> {
    return await this.redisClient.hincrby(key, field, increment)
  }

  // --- Set Commands ---

  /**
   * SADD - Thêm phần tử vào set
   */
  async sadd(key: RedisKey, members: RedisValue | RedisValue[]): Promise<number> {
    const membersToAdd = Array.isArray(members) ? members : [members]
    if (membersToAdd.length === 0) return 0
    return await this.redisClient.sadd(key, ...membersToAdd)
  }

  /**
   * SREM - Xóa phần tử khỏi set
   */
  async srem(key: RedisKey, members: RedisValue | RedisValue[]): Promise<number> {
    const membersToRemove = Array.isArray(members) ? members : [members]
    if (membersToRemove.length === 0) return 0
    return await this.redisClient.srem(key, ...membersToRemove)
  }

  /**
   * SMEMBERS - Lấy tất cả phần tử trong set
   */
  async smembers(key: RedisKey): Promise<string[]> {
    return await this.redisClient.smembers(key)
  }

  /**
   * SISMEMBER - Kiểm tra phần tử có trong set không
   */
  async sismember(key: RedisKey, member: RedisValue): Promise<number> {
    return await this.redisClient.sismember(key, member)
  }

  /**
   * SCARD - Đếm số phần tử trong set
   */
  async scard(key: RedisKey): Promise<number> {
    return await this.redisClient.scard(key)
  }

  // --- List Commands ---

  /**
   * LPUSH - Thêm phần tử vào đầu list
   */
  async lpush(key: RedisKey, elements: RedisValue | RedisValue[]): Promise<number> {
    const elementsToPush = Array.isArray(elements) ? elements : [elements]
    if (elementsToPush.length === 0) return 0
    return await this.redisClient.lpush(key, ...elementsToPush)
  }

  /**
   * RPUSH - Thêm phần tử vào cuối list
   */
  async rpush(key: RedisKey, elements: RedisValue | RedisValue[]): Promise<number> {
    const elementsToPush = Array.isArray(elements) ? elements : [elements]
    if (elementsToPush.length === 0) return 0
    return await this.redisClient.rpush(key, ...elementsToPush)
  }

  /**
   * LPOP - Lấy và xóa phần tử đầu list
   */
  async lpop(key: RedisKey, count?: number): Promise<string | null | string[]> {
    if (count !== undefined) {
      return await this.redisClient.lpop(key, count)
    }
    return await this.redisClient.lpop(key)
  }

  /**
   * RPOP - Lấy và xóa phần tử cuối list
   */
  async rpop(key: RedisKey, count?: number): Promise<string | null | string[]> {
    if (count !== undefined) {
      return await this.redisClient.rpop(key, count)
    }
    return await this.redisClient.rpop(key)
  }

  /**
   * LLEN - Đếm số phần tử trong list
   */
  async llen(key: RedisKey): Promise<number> {
    return await this.redisClient.llen(key)
  }

  /**
   * LRANGE - Lấy phần tử trong list theo vị trí
   */
  async lrange(key: RedisKey, start: number, stop: number): Promise<string[]> {
    return await this.redisClient.lrange(key, start, stop)
  }

  // --- JSON Helpers ---

  /**
   * Lấy và parse JSON từ key
   */
  async getJson<T>(key: RedisKey): Promise<T | null> {
    const jsonString = await this.get(key)
    if (!jsonString) return null
    try {
      return JSON.parse(jsonString) as T
    } catch {
      return null
    }
  }

  /**
   * Lưu đối tượng dưới dạng JSON vào key
   */
  async setJson(key: RedisKey, value: any, ttlSeconds?: number): Promise<'OK' | null> {
    let jsonString: string
    try {
      jsonString = JSON.stringify(value)
    } catch {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
    if (ttlSeconds !== undefined) {
      return this.set(key, jsonString, 'EX', ttlSeconds)
    } else {
      return this.set(key, jsonString)
    }
  }

  // --- Search & Keys ---

  /**
   * KEYS - Tìm kiếm key theo pattern
   * @returns Mảng các key khớp với pattern
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      return await this.redisClient.keys(pattern)
    } catch (error) {
      this.logger.error(`Redis KEYS error: ${error.message}`)
      throw error
    }
  }

  /**
   * SCAN - Quét key theo pattern (an toàn hơn KEYS)
   * @returns [cursor, keys]
   */
  async scan(cursor: number | string, ...args: any[]): Promise<[string, string[]]> {
    try {
      return await this.redisClient.scan(cursor, ...args)
    } catch (error) {
      this.logger.error(`Redis SCAN error: ${error.message}`)
      throw error
    }
  }

  /**
   * Find all keys matching a pattern.
   * Warning: Use with caution on production with large datasets as SCAN can still block.
   */
  async findKeys(pattern: string): Promise<string[]> {
    const foundKeys: string[] = []
    let cursor = '0'
    do {
      const [nextCursor, keys] = await this.scan(cursor, 'MATCH', pattern, 'COUNT', 100)
      keys.forEach((key) => foundKeys.push(key))
      cursor = nextCursor
    } while (cursor !== '0')
    return foundKeys
  }

  /**
   * Delete all keys matching a pattern.
   * Warning: Use with extreme caution on production.
   */
  async deleteKeysByPattern(pattern: string): Promise<number> {
    const keysToDelete = await this.findKeys(pattern)
    if (keysToDelete.length > 0) {
      return await this.del(keysToDelete)
    }
    return 0
  }

  /**
   * Executes a pipeline of commands.
   */
  async pipeline(
    fn: (pipeline: ReturnType<Redis['pipeline']>) => ReturnType<Redis['pipeline']>
  ): Promise<[Error | null, any][] | null> {
    const pipeline = this.redisClient.pipeline()
    return await fn(pipeline).exec()
  }

  /**
   * PUBLISH - Phát hành tin nhắn đến một kênh
   * @param channel Tên kênh
   * @param message Tin nhắn
   * @returns Số lượng clients đã nhận tin nhắn
   */
  async publish(channel: string, message: string): Promise<number> {
    try {
      return await this.redisClient.publish(channel, message)
    } catch (error) {
      this.logger.error(`Redis PUBLISH error: ${error.message}`)
      throw error
    }
  }

  // --- Mã hóa dữ liệu ---

  /**
   * Lưu trữ dữ liệu với mã hóa
   * @param key Key để lưu trữ dữ liệu
   * @param value Giá trị cần mã hóa và lưu trữ
   * @param ttlSeconds Thời gian hết hạn (giây)
   * @returns "OK" nếu thành công
   */
  async setEncrypted(key: RedisKey, value: string | object, ttlSeconds?: number): Promise<'OK' | null> {
    if (!this.cryptoService) {
      this.logger.warn('CryptoService không khả dụng. Dữ liệu sẽ được lưu không được mã hóa.')
      return this.setJson(key, value, ttlSeconds)
    }

    try {
      const encrypted = this.cryptoService.encrypt(value)
      if (ttlSeconds !== undefined) {
        return this.set(key, encrypted, 'EX', ttlSeconds)
      } else {
        return this.set(key, encrypted)
      }
    } catch (error) {
      this.logger.error(`Redis setEncrypted error: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Lấy và giải mã dữ liệu
   * @param key Key của dữ liệu đã mã hóa
   * @param asObject Trả về dưới dạng object
   * @returns Dữ liệu đã giải mã
   */
  async getDecrypted<T = any>(key: RedisKey, asObject: boolean = true): Promise<string | T | null> {
    if (!this.cryptoService) {
      this.logger.warn('CryptoService không khả dụng. Dữ liệu sẽ được đọc mà không giải mã.')
      return this.getJson<T>(key)
    }

    try {
      const encrypted = await this.get(key)
      if (!encrypted) return null

      return this.cryptoService.decrypt<T>(encrypted, asObject)
    } catch (error) {
      this.logger.error(`Redis getDecrypted error: ${error.message}`, error.stack)
      return null
    }
  }

  /**
   * Lưu trữ hash với các field được mã hóa
   * @param key Key của hash
   * @param fields Object chứa các field cần mã hóa và lưu trữ
   * @param sensitiveFields Danh sách các field nhạy cảm cần mã hóa (mặc định tất cả)
   * @returns Số field được tạo mới
   */
  async hsetEncrypted(
    key: RedisKey,
    fields: Record<string, string | number | boolean | object>,
    sensitiveFields?: string[]
  ): Promise<number> {
    const hashedFields: Record<string, string> = {}

    // Nếu CryptoService không khả dụng, lưu dữ liệu dưới dạng JSON
    if (!this.cryptoService) {
      for (const [field, value] of Object.entries(fields)) {
        hashedFields[field] = typeof value === 'object' ? JSON.stringify(value) : String(value)
      }
      return this.hset(key, hashedFields)
    }

    // Mã hóa các field nhạy cảm
    for (const [field, value] of Object.entries(fields)) {
      const shouldEncrypt = !sensitiveFields || sensitiveFields.includes(field)
      if (shouldEncrypt) {
        const valueToEncrypt = typeof value === 'string' ? value : JSON.stringify(value)
        hashedFields[field] = this.cryptoService.encrypt(valueToEncrypt)
      } else {
        hashedFields[field] = typeof value === 'object' ? JSON.stringify(value) : String(value)
      }
    }

    return this.hset(key, hashedFields)
  }

  /**
   * Lấy và giải mã field từ hash
   * @param key Key của hash
   * @param field Field cần lấy và giải mã
   * @param isSensitive Field có phải là dữ liệu nhạy cảm không
   * @param asObject Trả về dưới dạng object
   * @returns Dữ liệu đã giải mã
   */
  async hgetDecrypted<T = any>(
    key: RedisKey,
    field: string,
    isSensitive: boolean = true,
    asObject: boolean = true
  ): Promise<string | T | null> {
    const value = await this.hget(key, field)
    if (!value) return null

    // Nếu không phải field nhạy cảm hoặc CryptoService không khả dụng
    if (!isSensitive || !this.cryptoService) {
      if (asObject) {
        try {
          return JSON.parse(value) as T
        } catch {
          return value as unknown as T
        }
      }
      return value
    }

    // Giải mã dữ liệu
    return this.cryptoService.decrypt<T>(value, asObject)
  }

  /**
   * Lấy và giải mã tất cả field trong hash
   * @param key Key của hash
   * @param sensitiveFields Danh sách các field nhạy cảm cần giải mã
   * @returns Object chứa tất cả các field đã giải mã
   */
  async hgetallDecrypted<T = Record<string, any>>(
    key: RedisKey,
    sensitiveFields?: string[]
  ): Promise<T | Record<string, string> | null> {
    const data = await this.hgetall(key)
    if (!data || Object.keys(data).length === 0) return null

    // Nếu CryptoService không khả dụng, trả về dữ liệu gốc
    if (!this.cryptoService) {
      return data
    }

    const result: Record<string, any> = {}

    for (const [field, value] of Object.entries(data)) {
      const isSensitive = !sensitiveFields || sensitiveFields.includes(field)
      if (isSensitive) {
        try {
          result[field] = this.cryptoService.decrypt(value, true)
        } catch {
          result[field] = value
        }
      } else {
        try {
          result[field] = JSON.parse(value)
        } catch {
          result[field] = value
        }
      }
    }

    return result as T
  }

  /**
   * Thực hiện nhiều thao tác Redis trong một pipeline duy nhất
   * @param operations Mảng các thao tác để thực hiện
   * @returns Kết quả của mỗi thao tác
   */
  async batchProcess(
    operations: Array<{
      command: string
      args: any[]
    }>
  ): Promise<any[]> {
    if (operations.length === 0) return []

    const pipeline = this.redisClient.pipeline()

    for (const op of operations) {
      if (typeof pipeline[op.command] === 'function') {
        pipeline[op.command](...op.args)
      } else {
        this.logger.warn(`Command không hợp lệ: ${op.command}`)
      }
    }

    const results = (await pipeline.exec()) || []

    // Trả về kết quả của mỗi hoạt động, bỏ qua lỗi
    return results.map(([err, result]) => {
      if (err) {
        this.logger.error(`Pipeline error: ${err.message}`)
        return null
      }
      return result
    })
  }

  /**
   * Lấy nhiều key trong một lần gọi
   * @param keys Danh sách các key cần lấy
   * @returns Mảng giá trị tương ứng với các key
   */
  async mget(keys: RedisKey[]): Promise<(string | null)[]> {
    if (keys.length === 0) return []
    return this.redisClient.mget(keys)
  }

  /**
   * Thiết lập nhiều key-value trong một lần gọi
   * @param keyValuePairs Mảng các cặp [key, value]
   * @returns "OK" nếu thành công
   */
  async mset(keyValuePairs: Array<[RedisKey, RedisValue]>): Promise<'OK'> {
    if (keyValuePairs.length === 0) return 'OK'

    // Chuyển đổi mảng cặp thành mảng phẳng [key1, val1, key2, val2, ...]
    const args: (RedisKey | RedisValue)[] = []
    keyValuePairs.forEach(([key, value]) => {
      args.push(key, value)
    })

    return this.redisClient.mset(args)
  }

  /**
   * LTRIM - Cắt bớt danh sách để chỉ giữ các phần tử từ start đến stop
   * @returns "OK" nếu thành công
   */
  async ltrim(key: RedisKey, start: number, stop: number): Promise<'OK'> {
    try {
      return await this.redisClient.ltrim(key, start, stop)
    } catch (error) {
      this.logger.error(`Redis LTRIM error: ${error.message}`)
      throw error
    }
  }

  /**
   * Thực thi một lệnh Redis tùy chỉnh
   * @param command Tên lệnh Redis
   * @param args Các tham số của lệnh
   * @returns Kết quả của lệnh
   */
  async exec(command: string, args: any[] = []): Promise<any> {
    try {
      return await this.redisClient.call(command, ...args)
    } catch (error) {
      this.logger.error(`Redis ${command} error: ${error.message}`)
      throw error
    }
  }
}
