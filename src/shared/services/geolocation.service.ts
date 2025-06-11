// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

// ================================================================
// External Libraries
// ================================================================
import axios from 'axios'

// ================================================================
// Interfaces & Types
// ================================================================
export interface GeoLocationResult {
  country?: string
  city?: string
  lat?: number
  lon?: number
  timezone?: string
  display: string
}

/**
 * Service quản lý việc xác định vị trí địa lý từ IP address
 * Hỗ trợ cache, fallback và development mode
 */
@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name)
  private readonly ipCache = new Map<string, { location: GeoLocationResult; timestamp: number }>()
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 giờ
  private readonly DEFAULT_LOCATION: GeoLocationResult = {
    display: 'Vietnam',
    timezone: 'Asia/Ho_Chi_Minh'
  }
  private isDevMode = false

  constructor(private readonly configService: ConfigService) {
    this.isDevMode = this.configService.get('NODE_ENV') !== 'production'
  }

  // ================================================================
  // Public Methods - Geolocation API
  // ================================================================

  /**
   * Lấy thông tin vị trí từ IP address với cache và xử lý lỗi
   * Hỗ trợ các trường hợp: Local IP, Development mode, External API
   * @param ip - IP address cần tra cứu
   * @returns Thông tin vị trí địa lý
   */
  async getLocationFromIP(ip: string): Promise<GeoLocationResult> {
    // Kiểm tra IP local/private - trả về location mặc định
    if (!ip || this.isLocalIP(ip)) {
      return this.DEFAULT_LOCATION
    }

    // Kiểm tra cache - tránh gọi API không cần thiết
    const cachedResult = this.ipCache.get(ip)
    if (cachedResult && Date.now() - cachedResult.timestamp < this.CACHE_DURATION) {
      this.logger.debug(`[getLocationFromIP] Trả về kết quả từ cache cho IP ${ip}: ${cachedResult.location.display}`)
      return cachedResult.location
    }

    try {
      // Development environment - trả về mock data để tránh gọi API quá nhiều
      if (this.isDevMode) {
        const devLocation = this.getDevModeLocation(ip)
        this.ipCache.set(ip, { location: devLocation, timestamp: Date.now() })
        return devLocation
      }

      // Gọi API thực tế để lấy thông tin geolocation
      const response = await this.callIPGeolocationAPI(ip)

      // Lưu kết quả vào cache
      this.ipCache.set(ip, { location: response, timestamp: Date.now() })
      return response
    } catch (error) {
      this.logger.error(`Lỗi khi lấy thông tin location từ IP ${ip}: ${error.message}`)

      // Trả về fallback location phù hợp dựa trên IP
      const fallbackLocation = this.getFallbackLocation(ip)
      this.ipCache.set(ip, { location: fallbackLocation, timestamp: Date.now() })
      return fallbackLocation
    }
  }

  // ================================================================
  // Private Methods - Utility & Helper Functions
  // ================================================================

  /**
   * Kiểm tra xem IP có phải là local/private IP không
   * @param ip - IP address cần kiểm tra
   * @returns true nếu là local IP
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
   * Tạo mock location cho development environment dựa trên IP
   * Giúp tránh gọi API thực tế trong quá trình phát triển
   * @param ip - IP address làm seed cho mock data
   * @returns Mock location data
   */
  private getDevModeLocation(ip: string): GeoLocationResult {
    // Tạo mock location đa dạng dựa trên phần cuối của IP
    const ipParts = ip.split('.')
    const lastPart = parseInt(ipParts[ipParts.length - 1], 10)

    // Danh sách các thành phố mock để test
    const locations: GeoLocationResult[] = [
      {
        city: 'Hanoi',
        country: 'Vietnam',
        lat: 21.0285,
        lon: 105.8542,
        timezone: 'Asia/Ho_Chi_Minh',
        display: 'Hanoi, Vietnam'
      },
      {
        city: 'Ho Chi Minh',
        country: 'Vietnam',
        lat: 10.8231,
        lon: 106.6297,
        timezone: 'Asia/Ho_Chi_Minh',
        display: 'Ho Chi Minh, Vietnam'
      },
      {
        city: 'Da Nang',
        country: 'Vietnam',
        lat: 16.0544,
        lon: 108.2022,
        timezone: 'Asia/Ho_Chi_Minh',
        display: 'Da Nang, Vietnam'
      },
      {
        city: 'Singapore',
        country: 'Singapore',
        lat: 1.3521,
        lon: 103.8198,
        timezone: 'Asia/Singapore',
        display: 'Singapore'
      },
      { 
        city: 'Tokyo', 
        country: 'Japan', 
        lat: 35.6762, 
        lon: 139.6503, 
        timezone: 'Asia/Tokyo', 
        display: 'Tokyo, Japan' 
      },
      {
        city: 'Sydney',
        country: 'Australia',
        lat: -33.8688,
        lon: 151.2093,
        timezone: 'Australia/Sydney',
        display: 'Sydney, Australia'
      }
    ]

    // Sử dụng phần cuối IP để chọn location (tạo tính đa dạng)
    return locations[lastPart % locations.length]
  }

  // ================================================================
  // Private Methods - External API Integration
  // ================================================================

  /**
   * Gọi API thực tế để lấy thông tin geolocation từ IP
   * Sử dụng ip-api.com (miễn phí, giới hạn 45 requests/phút)
   * @param ip - IP address cần tra cứu
   * @returns Thông tin location từ API
   */
  private async callIPGeolocationAPI(ip: string): Promise<GeoLocationResult> {
    // Timeout để tránh chờ quá lâu
    const timeoutMs = 2000

    try {
      // Sử dụng ip-api.com - API miễn phí với giới hạn 45 requests/phút
      const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon,timezone`, {
        timeout: timeoutMs
      })

      if (response.data && response.data.status !== 'fail') {
        const { country, city, lat, lon, timezone } = response.data
        const display = city && country ? `${city}, ${country}` : country || 'Unknown Location'
        return { country, city, lat, lon, timezone, display }
      }

      // Fallback nếu API không trả về kết quả mong đợi
      throw new Error('Không thể xác định location từ dữ liệu API')
    } catch (error) {
      // Thử API backup nếu API chính bị lỗi
      try {
        const response = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: timeoutMs })

        if (response.data && !response.data.error) {
          const { country_name, city, latitude, longitude, timezone } = response.data
          const display = city && country_name ? `${city}, ${country_name}` : country_name || 'Unknown Location'
          return { country: country_name, city, lat: latitude, lon: longitude, timezone, display }
        }
      } catch (innerError) {
        this.logger.error(`Lỗi khi gọi backup API: ${innerError.message}`)
      }

      throw error // Re-throw lỗi để xử lý ở tầng cao hơn
    }
  }

  // ================================================================
  // Private Methods - Fallback & Default Logic
  // ================================================================

  /**
   * Trả về fallback location dựa trên IP khi các API bị lỗi
   * Sử dụng logic đơn giản dựa trên octet đầu của IP
   * @param ip - IP address để tạo fallback
   * @returns Fallback location data
   */
  private getFallbackLocation(ip: string): GeoLocationResult {
    // Tạo location dựa trên octet đầu tiên của IP
    try {
      const firstOctet = parseInt(ip.split('.')[0], 10)

      if (isNaN(firstOctet)) {
        return { display: 'Vietnam', timezone: 'Asia/Ho_Chi_Minh' } // Fallback cho IPv6 hoặc format khác
      }

      // Phân chia theo dải IP để tạo fallback phù hợp
      if (firstOctet < 100)
        return { city: 'Hanoi', country: 'Vietnam', display: 'Hanoi, Vietnam', timezone: 'Asia/Ho_Chi_Minh' }
      else if (firstOctet < 150)
        return {
          city: 'Ho Chi Minh',
          country: 'Vietnam',
          display: 'Ho Chi Minh, Vietnam',
          timezone: 'Asia/Ho_Chi_Minh'
        }
      else if (firstOctet < 200) 
        return { country: 'Singapore', display: 'Singapore', timezone: 'Asia/Singapore' }
      else 
        return { country: 'Asia', display: 'Asia', timezone: 'Asia/Bangkok' }
    } catch (error) {
      return { display: 'Vietnam', timezone: 'Asia/Ho_Chi_Minh' } // Fallback cuối cùng
    }
  }
}
