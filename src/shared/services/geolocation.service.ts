import { Injectable, Logger } from '@nestjs/common'
import geoip from 'geoip-lite'

export interface GeolocationData {
  country?: string
  region?: string
  city?: string
  ll?: [number, number] // [latitude, longitude]
  timezone?: string
  ip?: string
}

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name)

  lookup(ip: string): GeolocationData | null {
    if (!ip) {
      return null
    }

    // Handle localhost or private IPs which geoip-lite cannot lookup
    if (ip === '127.0.0.1' || ip === '::1' || this.isPrivateIP(ip)) {
      return {
        ip,
        city: 'Local/Private',
        country: 'N/A'
      }
    }

    try {
      const geo = geoip.lookup(ip)
      if (geo) {
        return {
          ip,
          country: geo.country,
          region: geo.region,
          city: geo.city,
          ll: geo.ll,
          timezone: geo.timezone
        }
      }
      return { ip, country: 'Unknown', city: 'Unknown' } // Return a default for unresolvable public IPs
    } catch {
      return null
    }
  }

  private isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(Number)
    if (parts.length === 4) {
      return (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168)
      )
    }
    // Basic IPv6 private checks (simplified)
    if (ip.startsWith('fd') || ip.startsWith('fc00::')) {
      return true
    }
    return false
  }

  // Periodically update the geoip database (optional but recommended for accuracy)
  // This can be a cron job or a startup task.
  // geoip.reloadData();
  // Or for async: await geoip.reloadDataASync();
  // For now, we'll rely on the bundled data.
}
