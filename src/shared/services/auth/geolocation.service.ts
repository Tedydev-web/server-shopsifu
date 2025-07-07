import { Injectable, Logger } from '@nestjs/common'
import axios from 'axios'
import envConfig from 'src/shared/config'

export interface GeoLocationResult {
  country?: string
  city?: string
  lat?: number
  lon?: number
  timezone?: string
  query: string
  display: string
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name)
  private readonly ipCache = new Map<string, { location: GeoLocationResult; timestamp: number }>()
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 hours
  private readonly isDev: boolean

  constructor() {
    this.isDev = envConfig.NODE_ENV === 'development'
  }

  async getLocationFromIP(ip: string | null | undefined): Promise<GeoLocationResult> {
    if (!ip || this.isLocalIP(ip)) {
      return this.getFallbackLocation(ip || '127.0.0.1')
    }

    const cached = this.ipCache.get(ip)
    if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
      return cached.location
    }

    try {
      const response = await axios.get(
        `http://ip-api.com/json/${ip}?fields=status,message,country,city,lat,lon,timezone,query`
      )

      if (response.data.status !== 'success') {
        this.logger.warn(`Failed to geolocate IP ${ip}: ${response.data.message}`)
        return this.getFallbackLocation(ip)
      }

      const location: GeoLocationResult = {
        ...response.data,
        display: [response.data.city, response.data.country].filter(Boolean).join(', ')
      }

      this.ipCache.set(ip, { location, timestamp: Date.now() })
      return location
    } catch (error) {
      this.logger.error(`Error during IP geolocation for ${ip}:`, error)
      return this.getFallbackLocation(ip)
    }
  }

  private isLocalIP(ip: string): boolean {
    // Always treat localhost addresses as local IPs
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
      return true
    }

    // In development mode, also treat private IP ranges as local
    if (this.isDev) {
      const parts = ip.split('.').map(Number)
      return (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168)
      )
    }

    // In production, only treat private IP ranges as local
    const parts = ip.split('.').map(Number)
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    )
  }

  private getFallbackLocation(ip: string): GeoLocationResult {
    return {
      query: ip,
      display: this.isDev ? 'Local Development' : 'Unknown Location'
    }
  }
}
