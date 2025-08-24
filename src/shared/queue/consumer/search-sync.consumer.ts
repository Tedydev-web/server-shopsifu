import { Injectable, Logger } from '@nestjs/common'
import { Processor, WorkerHost } from '@nestjs/bullmq'
import { Job } from 'bullmq'
import { SearchSyncService } from '../../services/search-sync.service'
import {
  SEARCH_SYNC_QUEUE_NAME,
  SYNC_PRODUCT_JOB,
  SYNC_PRODUCTS_BATCH_JOB,
  DELETE_PRODUCT_JOB
} from '../../constants/search-sync.constant'
import { SyncProductJobType, SyncProductsBatchJobType } from '../../models/search-sync.model'

@Injectable()
@Processor(SEARCH_SYNC_QUEUE_NAME)
export class SearchSyncConsumer extends WorkerHost {
  private readonly logger = new Logger(SearchSyncConsumer.name)

  constructor(private readonly searchSyncService: SearchSyncService) {
    super()
  }

  /**
   * Xử lý job đồng bộ một sản phẩm
   */
  async process(job: Job<SyncProductJobType, any, string>): Promise<void> {
    try {
      switch (job.name) {
        case SYNC_PRODUCT_JOB:
          await this.searchSyncService.syncProductToES(job.data)
          break
        case SYNC_PRODUCTS_BATCH_JOB:
          await this.searchSyncService.syncProductsBatchToES(job.data as unknown as SyncProductsBatchJobType)
          break
        case DELETE_PRODUCT_JOB:
          await this.searchSyncService.syncProductToES({
            productId: job.data.productId,
            action: 'delete'
          })
          break
        default:
          this.logger.warn(`Unknown job type: ${job.name}`)
      }
    } catch (error) {
      throw error
    }
  }
}
