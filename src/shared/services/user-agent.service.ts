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

  parse(userAgentString?: string, appIdentifier?: string): ParsedUserAgent {
    if (!userAgentString || typeof userAgentString !== 'string') {
      return {
        ...this.defaultResult,
        deviceName: 'Unknown Device',
        app: this.determineApp('', appIdentifier),
        raw: ''
      }
    }

    const parser = new UAParser(userAgentString)
    const result = parser.getResult()

    const deviceType = result.device.type ?? 'desktop'
    let deviceName: string

    if (result.device.vendor && result.device.model) {
      deviceName = `${result.device.vendor} ${result.device.model}`
    } else if (result.os.name) {
      deviceName = `${result.browser.name ?? 'Unknown Browser'} on ${result.os.name}`
    } else {
      deviceName = result.browser.name ? `${result.browser.name} on Unknown OS` : 'Unknown Device'
    }

    // Refine names for better user experience
    if (result.os.name === 'Mac OS') {
      deviceName = 'Mac'
    } else if (result.os.name === 'iOS') {
      deviceName = deviceType === 'mobile' ? 'iPhone' : 'iPad'
    }

    return {
      browser: result.browser.name ?? 'Unknown',
      browserVersion: result.browser.version ?? 'Unknown',
      os: result.os.name ?? 'Unknown',
      osVersion: result.os.version ?? 'Unknown',
      deviceType: result.device.type ?? 'Desktop',
      deviceVendor: result.device.vendor ?? 'Unknown',
      deviceModel: result.device.model ?? 'Unknown',
      deviceName: deviceName.replace('undefined on ', ''),
      app: this.determineApp(userAgentString, appIdentifier),
      raw: userAgentString
    }
  }

  private determineApp(userAgent: string, appIdentifier?: string): string {
    if (appIdentifier) return appIdentifier

    const ua = userAgent.toLowerCase()
    if (ua.includes('shopsifu-mobile-app')) {
      return 'MobileApp'
    }
    if (ua.includes('shopsifu-desktop-app')) {
      return 'DesktopApp'
    }
    return 'WebApp'
  }
}
