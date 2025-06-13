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
  app: string
  raw: string
}

@Injectable()
export class UserAgentService {
  private readonly defaultResult: Omit<ParsedUserAgent, 'app' | 'raw' | 'deviceName'> = {
    browser: 'Unknown',
    browserVersion: 'Unknown',
    os: 'Unknown',
    osVersion: 'Unknown',
    deviceType: 'Unknown',
    deviceVendor: 'Unknown',
    deviceModel: 'Unknown'
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  parse(userAgentString?: string, appIdentifier?: string, enhancedHeaders?: Record<string, any>): ParsedUserAgent {
    // Safely extract the original user agent string for parsing
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
    const deviceType = device.type || 'desktop' // Default to desktop for web traffic

    const getDeviceName = (): string => {
      if (deviceVendor && deviceModel) {
        // Avoid redundant names like "Apple iPhone" if model is already "iPhone"
        if (deviceModel.toLowerCase().includes(deviceVendor.toLowerCase())) {
          return deviceModel
        }
        return `${deviceVendor} ${deviceModel}`
      }

      const browserPart = browserName || 'Trình duyệt không rõ'
      const osPart = osName || 'HĐH không rõ'

      if (osPart !== 'HĐH không rõ') {
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
      app: this.determineApp(originalUA, appIdentifier),
      raw: ua
    }
  }

  private determineApp(userAgent: string, appIdentifier?: string): string {
    if (appIdentifier) return appIdentifier

    const ua = this.sanitizeUserAgentString(userAgent)
    if (ua.includes('shopsifu-mobile-app')) {
      return 'MobileApp'
    }
    if (ua.includes('shopsifu-desktop-app')) {
      return 'DesktopApp'
    }
    return 'WebApp'
  }

  /**
   * Safely sanitize and normalize user agent string
   */
  private sanitizeUserAgentString(userAgent?: any): string {
    if (!userAgent) return ''

    // Handle various types that might be passed
    if (typeof userAgent === 'string') {
      return userAgent.toLowerCase()
    }

    if (Array.isArray(userAgent)) {
      return userAgent.length > 0 ? String(userAgent[0]).toLowerCase() : ''
    }

    // Convert any other type to string and then lowercase
    return String(userAgent).toLowerCase()
  }

  /**
   * Get the original user agent string without modification
   */
  private getOriginalUserAgentString(userAgent?: any): string {
    if (!userAgent) return ''

    // Handle various types that might be passed
    if (typeof userAgent === 'string') {
      return userAgent
    }

    if (Array.isArray(userAgent)) {
      return userAgent.length > 0 ? String(userAgent[0]) : ''
    }

    // Convert any other type to string
    return String(userAgent)
  }
}
