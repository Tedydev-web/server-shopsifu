import { Injectable, Logger } from '@nestjs/common'
import { createHash } from 'crypto'
import { Request } from 'express'
import { GeolocationService, GeoLocationResult } from './geolocation.service'
import { ParsedUserAgent, UserAgentService } from './user-agent.service'
import { extractRealIpFromRequest } from '../../utils/http.utils'

export interface EnhancedDeviceInfo {
  userAgent: ParsedUserAgent
  ip: string
  location: GeoLocationResult
  fingerprint: string
  acceptHeaders: {
    language?: string | string[]
    encoding?: string | string[]
    accept?: string | string[]
  }
  clientHints: Record<string, any>
}

@Injectable()
export class DeviceFingerprintService {
  private readonly logger = new Logger(DeviceFingerprintService.name)

  constructor(
    private readonly userAgentService: UserAgentService,
    private readonly geolocationService: GeolocationService
  ) {}

  async extractInfo(req: Request): Promise<EnhancedDeviceInfo> {
    const ip = extractRealIpFromRequest(req)
    const uaString = req.headers['user-agent'] || ''

    const [userAgent, location] = await Promise.all([
      this.userAgentService.parse(uaString),
      this.geolocationService.getLocationFromIP(ip)
    ])

    const acceptHeaders = {
      language: req.headers['accept-language'],
      encoding: req.headers['accept-encoding'],
      accept: req.headers['accept']
    }

    // Extract Client Hints (Sec-CH-UA-*)
    const clientHints = Object.keys(req.headers)
      .filter((key) => key.startsWith('sec-ch-ua'))
      .reduce((acc, key) => {
        acc[key] = req.headers[key]
        return acc
      }, {})

    const fingerprintSource = {
      ua: userAgent.raw,
      browser: userAgent.browser,
      os: userAgent.os,
      deviceType: userAgent.deviceType,
      lang: acceptHeaders.language,
      encoding: acceptHeaders.encoding,
      clientHints
    }

    const fingerprint = createHash('sha256').update(JSON.stringify(fingerprintSource)).digest('hex')

    return {
      userAgent,
      ip,
      location,
      fingerprint,
      acceptHeaders,
      clientHints
    }
  }
}
