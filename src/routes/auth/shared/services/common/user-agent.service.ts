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
  app: string
  raw: string
}

@Injectable()
export class UserAgentService {
  private readonly defaultResult: Omit<ParsedUserAgent, 'app' | 'raw'> = {
    browser: 'Unknown',
    browserVersion: '',
    os: 'Unknown',
    osVersion: '',
    deviceType: 'Unknown',
    deviceVendor: 'Unknown',
    deviceModel: 'Unknown'
  }

  parse(userAgentString?: string, appIdentifier?: string): ParsedUserAgent {
    const raw = userAgentString || 'No-User-Agent'
    if (!userAgentString) {
      return { ...this.defaultResult, app: appIdentifier || 'Unknown', raw }
    }

    const parser = new UAParser(userAgentString)
    const result = parser.getResult()

    let deviceType = result.device.type
    if (!deviceType) {
      // Fallback for desktop devices that don't have a type
      if (['Windows', 'Mac OS', 'Linux'].includes(result.os.name || '')) {
        deviceType = 'mobile' // Default to mobile for desktop OS
      } else {
        deviceType = 'tablet' // Default to tablet for unknown OS
      }
    }

    return {
      browser: result.browser.name,
      browserVersion: result.browser.version,
      os: result.os.name,
      osVersion: result.os.version,
      deviceType: deviceType.charAt(0).toUpperCase() + deviceType.slice(1), // Capitalize
      deviceVendor: result.device.vendor,
      deviceModel: result.device.model,
      app: this.determineApp(userAgentString, appIdentifier),
      raw: userAgentString
    }
  }

  private determineApp(userAgent: string, appIdentifier?: string): string {
    if (appIdentifier) return appIdentifier
    // This is a placeholder for your own app identification logic
    if (userAgent.includes('Shopsifu-MobileApp')) return 'MobileApp'
    return 'WebApp'
  }
}
