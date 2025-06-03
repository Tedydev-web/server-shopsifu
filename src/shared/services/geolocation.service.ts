import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import axios from 'axios'

interface GeoLocationResult {
  country: string
  city: string
  regionName?: string
  countryCode?: string
  lat?: number
  lon?: number
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name)
  private readonly ipCache = new Map<string, { location: string; timestamp: number }>()
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 giờ
  private readonly DEFAULT_LOCATION = 'Việt Nam'
  private isDevMode = false

  constructor(private readonly configService: ConfigService) {
    this.isDevMode = this.configService.get('NODE_ENV') !== 'production'
  }

  /**
   * Lấy thông tin vị trí từ địa chỉ IP, có cache và xử lý lỗi
   */
  async getLocationFromIP(ip: string): Promise<string> {
    // Kiểm tra IP local
    if (this.isLocalIP(ip)) {
      return this.DEFAULT_LOCATION
    }

    // Kiểm tra cache
    const cachedResult = this.ipCache.get(ip)
    if (cachedResult && Date.now() - cachedResult.timestamp < this.CACHE_DURATION) {
      this.logger.debug(`[getLocationFromIP] Trả về kết quả từ cache cho IP ${ip}: ${cachedResult.location}`)
      return cachedResult.location
    }

    try {
      // Môi trường phát triển - trả về giá trị mô phỏng để tránh gọi API quá nhiều
      if (this.isDevMode) {
        const devLocation = this.getDevModeLocation(ip)
        this.ipCache.set(ip, { location: devLocation, timestamp: Date.now() })
        return devLocation
      }

      // Gọi API IP geolocation thực tế
      const response = await this.callIPGeolocationAPI(ip)

      // Cache kết quả
      this.ipCache.set(ip, { location: response, timestamp: Date.now() })
      return response
    } catch (error) {
      this.logger.error(`Lỗi khi lấy thông tin vị trí từ IP ${ip}: ${error.message}`)

      // Trả về giá trị phù hợp dựa trên IP
      const fallbackLocation = this.getFallbackLocation(ip)
      this.ipCache.set(ip, { location: fallbackLocation, timestamp: Date.now() })
      return fallbackLocation
    }
  }

  /**
   * Kiểm tra xem IP có phải là IP local không
   */
  private isLocalIP(ip: string): boolean {
    return (
      ip === '127.0.0.1' ||
      ip === 'localhost' ||
      ip === '::1' ||
      ip.startsWith('192.168.') ||
      ip.startsWith('10.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.20.') ||
      ip.startsWith('172.21.') ||
      ip.startsWith('172.22.') ||
      ip.startsWith('172.23.') ||
      ip.startsWith('172.24.') ||
      ip.startsWith('172.25.') ||
      ip.startsWith('172.26.') ||
      ip.startsWith('172.27.') ||
      ip.startsWith('172.28.') ||
      ip.startsWith('172.29.') ||
      ip.startsWith('172.30.') ||
      ip.startsWith('172.31.')
    )
  }

  /**
   * Tạo giá trị mô phỏng cho môi trường phát triển dựa trên IP
   */
  private getDevModeLocation(ip: string): string {
    // Tạo vị trí mô phỏng đa dạng dựa trên phần cuối của IP
    const ipParts = ip.split('.')
    const lastPart = parseInt(ipParts[ipParts.length - 1], 10)

    // Tạo danh sách các thành phố mô phỏng
    const cities = [
      'Hà Nội, Việt Nam',
      'Hồ Chí Minh, Việt Nam',
      'Đà Nẵng, Việt Nam',
      'Huế, Việt Nam',
      'Nha Trang, Việt Nam',
      'Hải Phòng, Việt Nam',
      'Cần Thơ, Việt Nam',
      'Đà Lạt, Việt Nam'
    ]

    return cities[lastPart % cities.length]
  }

  /**
   * Gọi API IP Geolocation thực tế
   */
  private async callIPGeolocationAPI(ip: string): Promise<string> {
    // Thiết lập timeout để tránh chờ đợi quá lâu
    const timeoutMs = 2000

    try {
      // Sử dụng ip-api.com - API miễn phí với giới hạn 45 requests/phút
      const response = await axios.get(`http://ip-api.com/json/${ip}?fields=country,city,regionName,countryCode`, {
        timeout: timeoutMs
      })

      if (response.data && response.data.status !== 'fail') {
        const location: GeoLocationResult = response.data

        if (location.city && location.country) {
          return `${location.city}, ${location.country}`
        } else if (location.country) {
          return location.country
        }
      }

      // Fallback nếu API không trả về kết quả như mong đợi
      throw new Error('Không thể xác định vị trí từ dữ liệu API')
    } catch (error) {
      // Thử API khác nếu API đầu tiên thất bại
      try {
        const response = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: timeoutMs })

        if (response.data && response.data.city && response.data.country_name) {
          return `${response.data.city}, ${response.data.country_name}`
        } else if (response.data && response.data.country_name) {
          return response.data.country_name
        }
      } catch (innerError) {
        this.logger.error(`Lỗi khi gọi API dự phòng: ${innerError.message}`)
      }

      throw error // Ném lỗi để xử lý ở mức cao hơn
    }
  }

  /**
   * Trả về vị trí fallback dựa trên IP khi các API thất bại
   */
  private getFallbackLocation(ip: string): string {
    // Tạo vị trí dựa trên octet đầu tiên của IP
    try {
      const firstOctet = parseInt(ip.split('.')[0], 10)

      if (isNaN(firstOctet)) {
        return 'Việt Nam' // Fallback cho IPv6 hoặc định dạng khác
      }

      if (firstOctet < 100) return 'Hà Nội, Việt Nam'
      else if (firstOctet < 150) return 'Hồ Chí Minh, Việt Nam'
      else if (firstOctet < 200) return 'Singapore'
      else return 'Châu Á'
    } catch (error) {
      return 'Việt Nam' // Fallback cuối cùng
    }
  }
}
