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
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 hours
  private readonly DEFAULT_LOCATION: GeoLocationResult = {
    display: 'Vietnam',
    timezone: 'Asia/Ho_Chi_Minh'
  }
  private isDevMode = false

  constructor(private readonly configService: ConfigService) {
    this.isDevMode = this.configService.get('NODE_ENV') !== 'production'
  }

  /**
   * Get location information from an IP address, with caching and error handling.
   */
  async getLocationFromIP(ip: string): Promise<GeoLocationResult> {
    // Check for local IP
    if (!ip || this.isLocalIP(ip)) {
      return this.DEFAULT_LOCATION
    }

    // Check cache
    const cachedResult = this.ipCache.get(ip)
    if (cachedResult && Date.now() - cachedResult.timestamp < this.CACHE_DURATION) {
      this.logger.debug(`[getLocationFromIP] Returning cached result for IP ${ip}: ${cachedResult.location.display}`)
      return cachedResult.location
    }

    try {
      // Development environment - return mock value to avoid excessive API calls
      if (this.isDevMode) {
        const devLocation = this.getDevModeLocation(ip)
        this.ipCache.set(ip, { location: devLocation, timestamp: Date.now() })
        return devLocation
      }

      // Call the actual IP geolocation API
      const response = await this.callIPGeolocationAPI(ip)

      // Cache the result
      this.ipCache.set(ip, { location: response, timestamp: Date.now() })
      return response
    } catch (error) {
      this.logger.error(`Error getting location information from IP ${ip}: ${error.message}`)

      // Return a suitable value based on the IP
      const fallbackLocation = this.getFallbackLocation(ip)
      this.ipCache.set(ip, { location: fallbackLocation, timestamp: Date.now() })
      return fallbackLocation
    }
  }

  /**
   * Check if the IP is a local IP.
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
   * Create a mock value for the development environment based on the IP.
   */
  private getDevModeLocation(ip: string): GeoLocationResult {
    // Create diverse mock locations based on the last part of the IP
    const ipParts = ip.split('.')
    const lastPart = parseInt(ipParts[ipParts.length - 1], 10)

    // Create a list of mock cities
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
   * Call the actual IP Geolocation API.
   */
  private async callIPGeolocationAPI(ip: string): Promise<GeoLocationResult> {
    // Set a timeout to avoid waiting too long
    const timeoutMs = 2000

    try {
      // Use ip-api.com - free API with a limit of 45 requests/minute
      const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon,timezone`, {
        timeout: timeoutMs
      })

      if (response.data && response.data.status !== 'fail') {
        const { country, city, lat, lon, timezone } = response.data
        const display = city && country ? `${city}, ${country}` : country || 'Unknown Location'
        return { country, city, lat, lon, timezone, display }
      }

      // Fallback if the API does not return the expected result
      throw new Error('Could not determine location from API data')
    } catch (error) {
      // Try another API if the first one fails
      try {
        const response = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: timeoutMs })

        if (response.data && !response.data.error) {
          const { country_name, city, latitude, longitude, timezone } = response.data
          const display = city && country_name ? `${city}, ${country_name}` : country_name || 'Unknown Location'
          return { country: country_name, city, lat: latitude, lon: longitude, timezone, display }
        }
      } catch (innerError) {
        this.logger.error(`Error calling fallback API: ${innerError.message}`)
      }

      throw error // Re-throw the error to be handled at a higher level
    }
  }

  /**
   * Return a fallback location based on the IP when APIs fail.
   */
  private getFallbackLocation(ip: string): GeoLocationResult {
    // Create a location based on the first octet of the IP
    try {
      const firstOctet = parseInt(ip.split('.')[0], 10)

      if (isNaN(firstOctet)) {
        return { display: 'Vietnam', timezone: 'Asia/Ho_Chi_Minh' } // Fallback for IPv6 or other formats
      }

      if (firstOctet < 100)
        return { city: 'Hanoi', country: 'Vietnam', display: 'Hanoi, Vietnam', timezone: 'Asia/Ho_Chi_Minh' }
      else if (firstOctet < 150)
        return {
          city: 'Ho Chi Minh',
          country: 'Vietnam',
          display: 'Ho Chi Minh, Vietnam',
          timezone: 'Asia/Ho_Chi_Minh'
        }
      else if (firstOctet < 200) return { country: 'Singapore', display: 'Singapore', timezone: 'Asia/Singapore' }
      else return { country: 'Asia', display: 'Asia', timezone: 'Asia/Bangkok' }
    } catch (error) {
      return { display: 'Vietnam', timezone: 'Asia/Ho_Chi_Minh' } // Final fallback
    }
  }
}
