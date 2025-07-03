import { Injectable } from '@nestjs/common'
import { UAParser } from 'ua-parser-js'

export interface ParsedUserAgent {
  browser?: string
  browserVersion?: string
  os?: string
  osVersion?: string
  deviceType?: string
  deviceVendor?: string
  deviceModel?: string
  deviceName: string
  raw: string
}

@Injectable()
export class UserAgentService {
  parse(userAgentString?: string): ParsedUserAgent {
    const originalUA = this.getOriginalUserAgentString(userAgentString)
    const ua = originalUA || ''

    const parser = new UAParser(ua)
    const result = parser.getResult()

    const { browser, os, device } = result

    const browserName = browser.name
    const browserVersion = browser.version
    const osName = os.name
    const osVersion = os.version
    const deviceVendor = device.vendor
    const deviceModel = device.model
    // Mặc định là 'desktop' cho lưu lượng truy cập web nếu không xác định được loại
    const deviceType = device.type || 'desktop'

    const getDeviceName = (): string => {
      if (deviceVendor && deviceModel) {
        // Tránh các tên dư thừa như "Apple iPhone" nếu model đã là "iPhone"
        if (deviceModel.toLowerCase().includes(deviceVendor.toLowerCase())) {
          return deviceModel
        }
        return `${deviceVendor} ${deviceModel}`
      }

      const browserPart = browserName || 'Trình duyệt không xác định'
      const osPart = osName || 'Hệ điều hành không xác định'

      if (osPart !== 'Hệ điều hành không xác định') {
        return `${browserPart} trên ${osPart}`
      }

      return browserPart
    }

    return {
      browser: browserName || 'Unknown',
      browserVersion: browserVersion || 'Unknown',
      os: osName || 'Unknown',
      osVersion: osVersion || 'Unknown',
      deviceType: deviceType,
      deviceVendor: deviceVendor || 'Unknown',
      deviceModel: deviceModel || 'Unknown',
      deviceName: getDeviceName(),
      raw: ua,
    }
  }

  private getOriginalUserAgentString(userAgent?: any): string {
    if (!userAgent) return ''
    if (typeof userAgent === 'string') {
      return userAgent
    }
    if (Array.isArray(userAgent)) {
      return userAgent.length > 0 ? String(userAgent[0]) : ''
    }
    return String(userAgent)
  }
}
