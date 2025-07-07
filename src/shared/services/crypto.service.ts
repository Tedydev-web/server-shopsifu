import { Injectable, Logger } from '@nestjs/common'
import * as crypto from 'crypto'
import envConfig from 'src/shared/config'

@Injectable()
export class CryptoService {
  private readonly logger = new Logger(CryptoService.name)
  private readonly encryptionKey: Buffer
  private readonly algorithm = 'aes-256-gcm'
  private readonly ivLength = 16
  private readonly tagLength = 16

  constructor() {
    const key = envConfig.COOKIE_SECRET
    if (!key || key.length < 32) {
      throw new Error('A 32-byte (256-bit) encryption key is required. Please check your configuration.')
    }
    this.encryptionKey = Buffer.from(key.slice(0, 32)) // Ensure key is 32 bytes
  }

  encrypt(plainText: string): string {
    const iv = crypto.randomBytes(this.ivLength)
    const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv)
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return Buffer.concat([iv, tag, encrypted]).toString('hex')
  }

  decrypt(cipherText: string): string | null {
    try {
      const data = Buffer.from(cipherText, 'hex')
      const iv = data.slice(0, this.ivLength)
      const tag = data.slice(this.ivLength, this.ivLength + this.tagLength)
      const encrypted = data.slice(this.ivLength + this.tagLength)
      const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv)
      decipher.setAuthTag(tag)
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()])
      return decrypted.toString('utf8')
    } catch (error) {
      // Log the error for debugging, but don't expose details to the caller
      this.logger.error('Decryption failed:', error)
      return null
    }
  }

  generateOTP(): string {
    return String(crypto.randomInt(100000, 1000000))
  }
}
