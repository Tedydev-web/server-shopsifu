import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as crypto from 'crypto'

@Injectable()
export class CryptoService {
  private readonly logger = new Logger(CryptoService.name)
  private readonly encryptionKey: Buffer
  private readonly algorithm = 'aes-256-gcm'
  private readonly ivLength = 16
  private readonly saltLength = 16
  private readonly tagLength = 16
  private readonly keyLength = 32 // 256 bits
  private readonly iterations = 10000

  constructor(private readonly configService: ConfigService) {
    const key = this.configService.get<string>('ENCRYPTION_KEY')

    if (!key) {
      this.logger.warn(
        'ENCRYPTION_KEY is not configured. Sensitive data will be stored unencrypted. ' +
          'For production environments, please ensure ENCRYPTION_KEY is set.'
      )
      this.encryptionKey = Buffer.from('default-key-please-change-in-production!', 'utf-8')
    } else {
      this.encryptionKey = Buffer.from(key, 'hex')
    }
  }

  /**
   * Mã hóa dữ liệu
   * @param data Dữ liệu cần mã hóa
   * @returns Chuỗi đã mã hóa dưới dạng base64
   */
  encrypt(data: string | object): string {
    try {
      if (!data) return ''

      // Chuyển đổi object thành string nếu cần
      const textToEncrypt = typeof data === 'object' ? JSON.stringify(data) : data

      // Tạo salt ngẫu nhiên
      const salt = crypto.randomBytes(this.saltLength)

      // Tạo key dựa trên salt
      const key = crypto.pbkdf2Sync(this.encryptionKey, salt, this.iterations, this.keyLength, 'sha256')

      // Tạo IV (Initialization Vector) ngẫu nhiên
      const iv = crypto.randomBytes(this.ivLength)

      // Tạo cipher
      const cipher = crypto.createCipheriv(this.algorithm, key, iv)

      // Mã hóa dữ liệu
      let encrypted = cipher.update(textToEncrypt, 'utf8', 'hex')
      encrypted += cipher.final('hex')

      // Lấy tag xác thực
      const authTag = cipher.getAuthTag()

      // Kết hợp tất cả thành buffer
      const result = Buffer.concat([salt, iv, authTag, Buffer.from(encrypted, 'hex')])

      // Trả về chuỗi base64
      return result.toString('base64')
    } catch (error) {
      this.logger.error(`Error during data encryption: ${error.message}`, error.stack)
      return ''
    }
  }

  /**
   * Giải mã dữ liệu
   * @param encryptedData Dữ liệu đã mã hóa dưới dạng base64
   * @param asObject Có chuyển đổi kết quả thành object không
   * @returns Dữ liệu đã được giải mã
   */
  decrypt<T = any>(encryptedData: string, asObject: boolean = false): string | T {
    try {
      if (!encryptedData) return asObject ? ({} as T) : ''

      // Chuyển đổi chuỗi base64 thành buffer
      const buffer = Buffer.from(encryptedData, 'base64')

      // Tách các thành phần từ buffer
      const salt = buffer.subarray(0, this.saltLength)
      const iv = buffer.subarray(this.saltLength, this.saltLength + this.ivLength)
      const authTag = buffer.subarray(this.saltLength + this.ivLength, this.saltLength + this.ivLength + this.tagLength)
      const encrypted = buffer.subarray(this.saltLength + this.ivLength + this.tagLength)

      // Tạo key từ salt
      const key = crypto.pbkdf2Sync(this.encryptionKey, salt, this.iterations, this.keyLength, 'sha256')

      // Tạo decipher
      const decipher = crypto.createDecipheriv(this.algorithm, key, iv)
      decipher.setAuthTag(authTag)

      // Giải mã dữ liệu
      let decrypted = decipher.update(encrypted.toString('hex'), 'hex', 'utf8')
      decrypted += decipher.final('utf8')

      // Trả về kết quả
      if (asObject) {
        try {
          return JSON.parse(decrypted) as T
        } catch (e) {
          return decrypted as unknown as T
        }
      }

      return decrypted
    } catch (error) {
      this.logger.error(`Error during data decryption: ${error.message}`, error.stack)
      return asObject ? ({} as T) : ''
    }
  }

  /**
   * Tạo hash cho dữ liệu
   * @param data Dữ liệu cần hash
   * @returns Chuỗi hash
   */
  createHash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex')
  }
}
