import { Injectable, Logger } from '@nestjs/common'
import { Request } from 'express'
import { UserAgentService } from './user-agent.service'
import { GeolocationService } from './geolocation.service'

export interface EnhancedDeviceInfo {
  userAgent: string
  userAgentInfo: any
  ipAddress: string
  location: any
  fingerprint: string
  clientHints: ClientHints
  securityHeaders: SecurityHeaders
  acceptHeaders: AcceptHeaders
  connectionInfo: ConnectionInfo
  timestamp: number
}

export interface ClientHints {
  platform?: string
  mobile?: boolean
  architecture?: string
  model?: string
  platformVersion?: string
  uaFullVersion?: string
  brands?: Array<{ brand: string; version: string }>
}

export interface SecurityHeaders {
  secFetchSite?: string
  secFetchMode?: string
  secFetchUser?: string
  secFetchDest?: string
  secChUa?: string
  secChUaMobile?: string
  secChUaPlatform?: string
  secChUaArch?: string
  secChUaModel?: string
  secChUaPlatformVersion?: string
  secChUaFullVersionList?: string
}

export interface AcceptHeaders {
  accept?: string
  acceptLanguage?: string
  acceptEncoding?: string
  acceptCharset?: string
}

export interface ConnectionInfo {
  connection?: string
  upgradeInsecureRequests?: string
  cacheControl?: string
  pragma?: string
  dnt?: string
}

/**
 * Service for advanced device fingerprinting and context extraction
 * Combines multiple data sources for robust device identification
 */
@Injectable()
export class DeviceFingerprintService {
  private readonly logger = new Logger(DeviceFingerprintService.name)

  constructor(
    private readonly userAgentService: UserAgentService,
    private readonly geolocationService: GeolocationService
  ) {}

  /**
   * Extract comprehensive device information from request
   */
  async extractDeviceInfo(req: Request): Promise<EnhancedDeviceInfo> {
    const startTime = Date.now()

    try {
      // Extract basic info
      const userAgent = this.extractUserAgent(req)
      const ipAddress = this.extractRealIP(req)

      // Extract all relevant headers
      const clientHints = this.extractClientHints(req)
      const securityHeaders = this.extractSecurityHeaders(req)
      const acceptHeaders = this.extractAcceptHeaders(req)
      const connectionInfo = this.extractConnectionInfo(req)

      // Create enhanced headers object for UA parsing
      const enhancedHeaders = {
        ...this.flattenClientHints(clientHints),
        ...this.flattenSecurityHeaders(securityHeaders),
        ...this.flattenAcceptHeaders(acceptHeaders)
      }

      // Parse user agent with enhanced context
      const userAgentInfo = this.userAgentService.parse(userAgent, undefined, enhancedHeaders)

      // Generate comprehensive fingerprint
      const fingerprint = this.generateAdvancedFingerprint({
        userAgent,
        clientHints,
        securityHeaders,
        acceptHeaders,
        connectionInfo
      })

      // Get location info
      const location = await this.geolocationService.getLocationFromIP(ipAddress)

      const deviceInfo: EnhancedDeviceInfo = {
        userAgent,
        userAgentInfo,
        ipAddress,
        location,
        fingerprint,
        clientHints,
        securityHeaders,
        acceptHeaders,
        connectionInfo,
        timestamp: Date.now()
      }

      const processingTime = Date.now() - startTime
      this.logger.debug(`[extractDeviceInfo] Processed in ${processingTime}ms`)
      this.logger.debug(
        `[extractDeviceInfo] Result: ${JSON.stringify({
          ...deviceInfo,
          userAgent: userAgent?.substring(0, 50) + '...'
        })}`
      )

      return deviceInfo
    } catch (error) {
      this.logger.error(`[extractDeviceInfo] Error: ${error.message}`, error.stack)

      // Return fallback info
      return this.createFallbackDeviceInfo(req)
    }
  }

  /**
   * Extract real IP address with proxy support
   */
  private extractRealIP(req: Request): string {
    // Try multiple headers in order of preference
    const candidates = [
      req.headers['cf-connecting-ip'], // Cloudflare
      req.headers['x-real-ip'], // Nginx
      req.headers['x-forwarded-for'], // Standard proxy header
      req.headers['x-client-ip'], // Apache
      req.headers['x-cluster-client-ip'], // Cluster
      req.headers['forwarded-for'],
      req.headers['forwarded'],
      req.connection?.remoteAddress,
      req.socket?.remoteAddress,
      req.ip
    ].filter(Boolean)

    for (const candidate of candidates) {
      if (typeof candidate === 'string') {
        // Handle comma-separated IPs (take the first one)
        const ip = candidate.split(',')[0].trim()
        if (this.isValidIP(ip)) {
          return ip
        }
      }
    }

    return 'Unknown'
  }

  /**
   * Extract user agent with fallbacks
   */
  private extractUserAgent(req: Request): string {
    const userAgent = req.headers['user-agent'] || req.headers['User-Agent'] || req.get('User-Agent') || ''

    if (Array.isArray(userAgent)) {
      return userAgent[0] || ''
    }

    return userAgent
  }

  /**
   * Extract Client Hints headers
   */
  private extractClientHints(req: Request): ClientHints {
    const parseUaBrands = (header?: string) => {
      if (!header) return undefined
      try {
        // Parse format: "Google Chrome";v="91", "Chromium";v="91"
        return header
          .split(',')
          .map((brand) => {
            const match = brand.trim().match(/"([^"]+)";v="([^"]+)"/)
            return match ? { brand: match[1], version: match[2] } : null
          })
          .filter(Boolean) as Array<{ brand: string; version: string }>
      } catch {
        return undefined
      }
    }

    return {
      platform: this.getHeader(req, 'sec-ch-ua-platform')?.replace(/"/g, ''),
      mobile: this.getHeader(req, 'sec-ch-ua-mobile') === '?1',
      architecture: this.getHeader(req, 'sec-ch-ua-arch')?.replace(/"/g, ''),
      model: this.getHeader(req, 'sec-ch-ua-model')?.replace(/"/g, ''),
      platformVersion: this.getHeader(req, 'sec-ch-ua-platform-version')?.replace(/"/g, ''),
      uaFullVersion: this.getHeader(req, 'sec-ch-ua-full-version')?.replace(/"/g, ''),
      brands: parseUaBrands(this.getHeader(req, 'sec-ch-ua'))
    }
  }

  /**
   * Extract security-related headers
   */
  private extractSecurityHeaders(req: Request): SecurityHeaders {
    return {
      secFetchSite: this.getHeader(req, 'sec-fetch-site'),
      secFetchMode: this.getHeader(req, 'sec-fetch-mode'),
      secFetchUser: this.getHeader(req, 'sec-fetch-user'),
      secFetchDest: this.getHeader(req, 'sec-fetch-dest'),
      secChUa: this.getHeader(req, 'sec-ch-ua'),
      secChUaMobile: this.getHeader(req, 'sec-ch-ua-mobile'),
      secChUaPlatform: this.getHeader(req, 'sec-ch-ua-platform'),
      secChUaArch: this.getHeader(req, 'sec-ch-ua-arch'),
      secChUaModel: this.getHeader(req, 'sec-ch-ua-model'),
      secChUaPlatformVersion: this.getHeader(req, 'sec-ch-ua-platform-version'),
      secChUaFullVersionList: this.getHeader(req, 'sec-ch-ua-full-version-list')
    }
  }

  /**
   * Extract accept-related headers
   */
  private extractAcceptHeaders(req: Request): AcceptHeaders {
    return {
      accept: this.getHeader(req, 'accept'),
      acceptLanguage: this.getHeader(req, 'accept-language'),
      acceptEncoding: this.getHeader(req, 'accept-encoding'),
      acceptCharset: this.getHeader(req, 'accept-charset')
    }
  }

  /**
   * Extract connection-related headers
   */
  private extractConnectionInfo(req: Request): ConnectionInfo {
    return {
      connection: this.getHeader(req, 'connection'),
      upgradeInsecureRequests: this.getHeader(req, 'upgrade-insecure-requests'),
      cacheControl: this.getHeader(req, 'cache-control'),
      pragma: this.getHeader(req, 'pragma'),
      dnt: this.getHeader(req, 'dnt')
    }
  }

  /**
   * Generate advanced device fingerprint
   */
  private generateAdvancedFingerprint(data: {
    userAgent: string
    clientHints: ClientHints
    securityHeaders: SecurityHeaders
    acceptHeaders: AcceptHeaders
    connectionInfo: ConnectionInfo
  }): string {
    const components = [
      // Core components
      data.userAgent,
      data.acceptHeaders.acceptLanguage,
      data.acceptHeaders.acceptEncoding,

      // Client Hints
      data.clientHints.platform,
      data.clientHints.mobile?.toString(),
      data.clientHints.architecture,
      data.clientHints.model,
      data.clientHints.brands?.map((b) => `${b.brand}:${b.version}`).join(','),

      // Security headers
      data.securityHeaders.secChUa,
      data.securityHeaders.secFetchSite,
      data.securityHeaders.secFetchMode,

      // Connection info
      data.connectionInfo.upgradeInsecureRequests,
      data.connectionInfo.dnt
    ].filter(Boolean)

    const combinedString = components.join('|')

    // Create a hash-like fingerprint
    return Buffer.from(combinedString)
      .toString('base64')
      .replace(/[^A-Za-z0-9]/g, '')
      .substring(0, 32)
  }

  /**
   * Validate IP address
   */
  private isValidIP(ip: string): boolean {
    // Basic IP validation (IPv4 and IPv6)
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/

    return ipv4Regex.test(ip) || ipv6Regex.test(ip)
  }

  /**
   * Safe header extraction
   */
  private getHeader(req: Request, name: string): string | undefined {
    const header = req.headers[name.toLowerCase()]
    if (Array.isArray(header)) {
      return header[0]
    }
    return header
  }

  /**
   * Flatten client hints for UA service
   */
  private flattenClientHints(hints: ClientHints): Record<string, string> {
    return {
      'sec-ch-ua-platform': hints.platform || '',
      'sec-ch-ua-mobile': hints.mobile ? '?1' : '?0',
      'sec-ch-ua-arch': hints.architecture || '',
      'sec-ch-ua-model': hints.model || ''
    }
  }

  /**
   * Flatten security headers for UA service
   */
  private flattenSecurityHeaders(headers: SecurityHeaders): Record<string, string> {
    return Object.fromEntries(
      Object.entries(headers)
        .filter(([_, value]) => value !== undefined)
        .map(([key, value]) => [key.replace(/([A-Z])/g, '-$1').toLowerCase(), value!])
    )
  }

  /**
   * Flatten accept headers for UA service
   */
  private flattenAcceptHeaders(headers: AcceptHeaders): Record<string, string> {
    return Object.fromEntries(
      Object.entries(headers)
        .filter(([_, value]) => value !== undefined)
        .map(([key, value]) => [key.replace(/([A-Z])/g, '-$1').toLowerCase(), value!])
    )
  }

  /**
   * Create fallback device info when extraction fails
   */
  private createFallbackDeviceInfo(req: Request): EnhancedDeviceInfo {
    const userAgent = this.extractUserAgent(req)
    const ipAddress = this.extractRealIP(req)

    return {
      userAgent,
      userAgentInfo: this.userAgentService.parse(userAgent),
      ipAddress,
      location: { display: 'Unknown Location', timezone: 'UTC' },
      fingerprint: Buffer.from(userAgent + ipAddress)
        .toString('base64')
        .substring(0, 32),
      clientHints: {},
      securityHeaders: {},
      acceptHeaders: {},
      connectionInfo: {},
      timestamp: Date.now()
    }
  }
}
