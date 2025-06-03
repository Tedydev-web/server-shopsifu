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

  constructor(private readonly configService: ConfigService) {}

  /**
   * Lấy thông tin vị trí từ địa chỉ IP sử dụng dịch vụ miễn phí
   * Trong môi trường production, nên sử dụng dịch vụ Geolocation có trả phí cho độ chính xác cao
   */
  async getLocationFromIP(ip: string): Promise<string> {
    // Nếu là địa chỉ IP nội bộ hoặc localhost, trả về giá trị mặc định
    if (ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return 'Hà Nội, Việt Nam'
    }

    try {
      // Sử dụng ip-api.com - dịch vụ geolocation miễn phí
      // Lưu ý: giới hạn 45 requests/phút trong môi trường miễn phí
      const response = await axios.get(`http://ip-api.com/json/${ip}?fields=country,city,regionName,countryCode`)

      if (response.data && response.data.status !== 'fail') {
        const location: GeoLocationResult = response.data

        if (location.city && location.country) {
          return `${location.city}, ${location.country}`
        } else if (location.country) {
          return location.country
        }
      }

      // Fallback nếu API không trả về kết quả hợp lệ
      return 'Vị trí không xác định'
    } catch (error) {
      this.logger.error(`Lỗi khi lấy thông tin vị trí từ IP ${ip}: ${error.message}`)

      // Giá trị mặc định giả lập trong trường hợp lỗi
      const firstOctet = parseInt(ip.split('.')[0], 10)

      if (firstOctet < 100) return 'Hà Nội, Việt Nam'
      else if (firstOctet < 150) return 'Hồ Chí Minh, Việt Nam'
      else if (firstOctet < 200) return 'Singapore'
      else return 'Vị trí không xác định'
    }
  }
}
