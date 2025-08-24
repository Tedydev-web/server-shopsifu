import { InjectQueue } from '@nestjs/bullmq'
import { Injectable, Logger } from '@nestjs/common'
import { Queue } from 'bullmq'
import {
  SEARCH_SYNC_QUEUE_NAME,
  SYNC_PRODUCT_JOB,
  SYNC_PRODUCTS_BATCH_JOB,
  DELETE_PRODUCT_JOB,
  JOB_OPTIONS
} from 'src/shared/constants/search-sync.constant'
import { SyncProductJobType, SyncProductsBatchJobType } from 'src/shared/models/search-sync.model'
import { generateSearchSyncJobId } from 'src/shared/helpers'

@Injectable()
export class SearchSyncProducer {
  private readonly logger = new Logger(SearchSyncProducer.name)

  constructor(@InjectQueue(SEARCH_SYNC_QUEUE_NAME) private searchSyncQueue: Queue) {}

  /**
   * Enqueue job đồng bộ một sản phẩm
   */
  async enqueueSyncProduct(jobData: SyncProductJobType) {
    return this.searchSyncQueue.add(SYNC_PRODUCT_JOB, jobData, {
      jobId: generateSearchSyncJobId('product', jobData.productId),
      ...JOB_OPTIONS
    })
  }

  /**
   * Enqueue job đồng bộ nhiều sản phẩm
   */
  async enqueueSyncProductsBatch(jobData: SyncProductsBatchJobType) {
    return this.searchSyncQueue.add(SYNC_PRODUCTS_BATCH_JOB, jobData, {
      jobId: generateSearchSyncJobId('batch', Date.now().toString()),
      ...JOB_OPTIONS
    })
  }

  /**
   * Enqueue job xóa sản phẩm khỏi search index
   */
  async enqueueDeleteProduct(productId: string) {
    return this.searchSyncQueue.add(
      DELETE_PRODUCT_JOB,
      { productId },
      {
        jobId: generateSearchSyncJobId('delete', productId),
        ...JOB_OPTIONS
      }
    )
  }
}
