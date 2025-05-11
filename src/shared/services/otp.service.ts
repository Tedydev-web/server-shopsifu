import { Injectable } from '@nestjs/common'
import { randomInt } from 'crypto'
import { HashingService } from './hashing.service'

@Injectable()
export class OtpService {
  constructor(private readonly hashingService: HashingService) {}

  /**
   * Tạo mã OTP ngẫu nhiên 6 chữ số
   */
  generateOTP(): string {
    return String(randomInt(100000, 1000000))
  }

  /**
   * Băm mã OTP để lưu an toàn trong database
   */
  async hashOTP(otp: string, salt: string): Promise<string> {
    // Thêm salt vào OTP trước khi băm để tăng tính bảo mật
    return this.hashingService.hash(`${otp}${salt}`)
  }

  /**
   * So sánh mã OTP được nhập với mã OTP đã được băm trong database
   */
  async verifyOTP(otp: string, hashedOTP: string, salt: string): Promise<boolean> {
    return this.hashingService.compare(`${otp}${salt}`, hashedOTP)
  }
}
