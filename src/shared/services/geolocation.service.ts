import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import axios from 'axios'

export interface GeoLocationResult {
  country?: string
  city?: string
  lat?: number
  lon?: number
  timezone?: string
  display: string
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name)
  private readonly ipCache = new Map<string, { location: GeoLocationResult; timestamp: number }>()
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 giờ
  private readonly DEFAULT_LOCATION: GeoLocationResult = {
    display: 'Việt Nam',
    timezone: 'Asia/Ho_Chi_Minh'
  }
  private isDevMode = false

  constructor(private readonly configService: ConfigService) {
    this.isDevMode = this.configService.get('NODE_ENV') !== 'production'
  }

  /**
   * Lấy thông tin vị trí từ địa chỉ IP, có cache và xử lý lỗi
   */
  async getLocationFromIP(ip: string): Promise<GeoLocationResult> {
    // Kiểm tra IP local
    if (!ip || this.isLocalIP(ip)) {
      return this.DEFAULT_LOCATION
    }

    // Kiểm tra cache
    const cachedResult = this.ipCache.get(ip)
    if (cachedResult && Date.now() - cachedResult.timestamp < this.CACHE_DURATION) {
      this.logger.debug(`[getLocationFromIP] Trả về kết quả từ cache cho IP ${ip}: ${cachedResult.location.display}`)
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
  private getDevModeLocation(ip: string): GeoLocationResult {
    // Tạo vị trí mô phỏng đa dạng dựa trên phần cuối của IP
    const ipParts = ip.split('.')
    const lastPart = parseInt(ipParts[ipParts.length - 1], 10)

    // Tạo danh sách các thành phố mô phỏng
    const locations: GeoLocationResult[] = [
      {
        city: 'Hà Nội',
        country: 'Việt Nam',
        lat: 21.0285,
        lon: 105.8542,
        timezone: 'Asia/Ho_Chi_Minh',
        display: 'Hà Nội, Việt Nam'
      },
      {
        city: 'Hồ Chí Minh',
        country: 'Việt Nam',
        lat: 10.8231,
        lon: 106.6297,
        timezone: 'Asia/Ho_Chi_Minh',
        display: 'Hồ Chí Minh, Việt Nam'
      },
      {
        city: 'Đà Nẵng',
        country: 'Việt Nam',
        lat: 16.0544,
        lon: 108.2022,
        timezone: 'Asia/Ho_Chi_Minh',
        display: 'Đà Nẵng, Việt Nam'
      },
      {
        city: 'Singapore',
        country: 'Singapore',
        lat: 1.3521,
        lon: 103.8198,
        timezone: 'Asia/Singapore',
        display: 'Singapore'
      },
      { city: 'Tokyo', country: 'Japan', lat: 35.6762, lon: 139.6503, timezone: 'Asia/Tokyo', display: 'Tokyo, Japan' },
      {
        city: 'Sydney',
        country: 'Australia',
        lat: -33.8688,
        lon: 151.2093,
        timezone: 'Australia/Sydney',
        display: 'Sydney, Australia'
      }
    ]

    return locations[lastPart % locations.length]
  }

  /**
   * Gọi API IP Geolocation thực tế
   */
  private async callIPGeolocationAPI(ip: string): Promise<GeoLocationResult> {
    // Thiết lập timeout để tránh chờ đợi quá lâu
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

      // Fallback nếu API không trả về kết quả như mong đợi
      throw new Error('Không thể xác định vị trí từ dữ liệu API')
    } catch (error) {
      // Thử API khác nếu API đầu tiên thất bại
      try {
        const response = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: timeoutMs })

        if (response.data && !response.data.error) {
          const { country_name, city, latitude, longitude, timezone } = response.data
          const display = city && country_name ? `${city}, ${country_name}` : country_name || 'Unknown Location'
          return { country: country_name, city, lat: latitude, lon: longitude, timezone, display }
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
  private getFallbackLocation(ip: string): GeoLocationResult {
    // Tạo vị trí dựa trên octet đầu tiên của IP
    try {
      const firstOctet = parseInt(ip.split('.')[0], 10)

      if (isNaN(firstOctet)) {
        return { display: 'Việt Nam', timezone: 'Asia/Ho_Chi_Minh' } // Fallback cho IPv6 hoặc định dạng khác
      }

      if (firstOctet < 100)
        return { city: 'Hà Nội', country: 'Việt Nam', display: 'Hà Nội, Việt Nam', timezone: 'Asia/Ho_Chi_Minh' }
      else if (firstOctet < 150)
        return {
          city: 'Hồ Chí Minh',
          country: 'Việt Nam',
          display: 'Hồ Chí Minh, Việt Nam',
          timezone: 'Asia/Ho_Chi_Minh'
        }
      else if (firstOctet < 200) return { country: 'Singapore', display: 'Singapore', timezone: 'Asia/Singapore' }
      else return { country: 'Châu Á', display: 'Châu Á', timezone: 'Asia/Bangkok' }
    } catch (error) {
      return { display: 'Việt Nam', timezone: 'Asia/Ho_Chi_Minh' } // Fallback cuối cùng
    }
  }
}
