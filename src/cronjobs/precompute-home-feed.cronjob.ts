import { CACHE_MANAGER } from '@nestjs/cache-manager'
import { Inject, Injectable, Logger } from '@nestjs/common'
import { Cron, CronExpression } from '@nestjs/schedule'
import { Cache } from 'cache-manager'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { ProductRepo } from 'src/routes/product/product.repo'
import {
  PRODUCT_LIST_CACHE_PREFIX,
  PRODUCT_LIST_TTL_MS,
  PRODUCT_LIST_VERSION_KEY
} from 'src/shared/constants/product.constant'

@Injectable()
export class PrecomputeHomeFeedCronjob {
  private readonly logger = new Logger(PrecomputeHomeFeedCronjob.name)

  constructor(
    private readonly productRepo: ProductRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {}

  @Cron(CronExpression.EVERY_30_SECONDS)
  async handle() {
    try {
      const langArray = ['vi', 'en']
      const version = (await this.cacheManager.get<number>(PRODUCT_LIST_VERSION_KEY)) || 1
      for (const lang of langArray) {
        const key = `${PRODUCT_LIST_CACHE_PREFIX}:home:v${version}:lang:${lang}`
        const data = await this.productRepo.list({
          page: 1,
          limit: 10,
          languageId: lang,
          isPublic: true,
          orderBy: 'desc',
          sortBy: 'createdAt'
        } as any)
        const response = {
          message: this.i18n.t('product.product.success.GET_SUCCESS'),
          data: data.data,
          metadata: data.metadata
        }
        await this.cacheManager.set(key, response, PRODUCT_LIST_TTL_MS)
      }
    } catch (err) {
      this.logger.warn(`Precompute home feed failed: ${String(err)}`)
    }
  }
}
