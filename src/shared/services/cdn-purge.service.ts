import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

/**
 * Dịch vụ trừu tượng hóa purge CDN theo Surrogate-Key hoặc URL
 * Hỗ trợ các nhà cung cấp: Cloudflare / Fastly / Vercel (HTTP API)
 */
@Injectable()
export class CdnPurgeService {
  private readonly logger = new Logger(CdnPurgeService.name)

  constructor(private readonly configService: ConfigService) {}

  /**
   * Purge theo danh sách Surrogate-Keys (nên dùng khi CDN hỗ trợ)
   */
  async purgeBySurrogateKeys(keys: string[]): Promise<void> {
    try {
      if (!keys || keys.length === 0) return
      // Placeholder: Tùy CDN, thực hiện HTTP request tới API purge keys
      this.logger.log(`CDN purge by surrogate-keys: ${keys.join(', ')}`)
    } catch (error) {
      this.logger.warn(`CDN purge by surrogate-keys failed: ${error?.message}`)
    }
  }

  /**
   * Purge theo danh sách URL
   */
  async purgeByUrls(urls: string[]): Promise<void> {
    try {
      if (!urls || urls.length === 0) return
      // Placeholder: Tùy CDN, thực hiện HTTP request tới API purge urls
      this.logger.log(`CDN purge by urls: ${urls.join(', ')}`)
    } catch (error) {
      this.logger.warn(`CDN purge by urls failed: ${error?.message}`)
    }
  }
}
