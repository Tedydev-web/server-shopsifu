import { Injectable, Logger } from '@nestjs/common'
import { Queue } from 'bullmq'
import { ConfigService } from '@nestjs/config'
import { SearchSyncService } from './search-sync.service'
import {
  SEARCH_SYNC_QUEUE_NAME,
  SYNC_PRODUCT_JOB,
  SYNC_PRODUCTS_BATCH_JOB,
  DELETE_PRODUCT_JOB,
  JOB_OPTIONS
} from '../constants/search-sync.constant'
import { SyncProductJobType, SyncProductsBatchJobType } from '../models/search-sync.model'

@Injectable()
export class SearchSyncQueueService {
  private readonly logger = new Logger(SearchSyncQueueService.name)
  public readonly queue: Queue

  constructor(
    private readonly searchSyncService: SearchSyncService,
    private readonly configService: ConfigService
  ) {
    this.queue = new Queue(SEARCH_SYNC_QUEUE_NAME, {
      connection: {
        host: this.configService.get('redis.host'),
        port: this.configService.get('redis.port'),
        password: this.configService.get('redis.password')
      }
    })
  }

  /**
   * Thêm job đồng bộ một sản phẩm
   */
  async addSyncProductJob(productId: string, action: 'create' | 'update' | 'delete' = 'create') {
    const jobData: SyncProductJobType = {
      productId,
      action
    }

    try {
      await this.queue.add(SYNC_PRODUCT_JOB, jobData, {
        attempts: JOB_OPTIONS.ATTEMPTS,
        backoff: JOB_OPTIONS.BACKOFF,
        removeOnComplete: JOB_OPTIONS.REMOVE_ON_COMPLETE,
        removeOnFail: JOB_OPTIONS.REMOVE_ON_FAIL
      })

      this.logger.log(`✅ Added sync job for product ${productId} with action: ${action}`)
    } catch (error) {
      this.logger.error(`❌ Failed to add sync job for product ${productId}:`, error)
      throw error
    }
  }

  /**
   * Thêm job đồng bộ nhiều sản phẩm (batch)
   */
  async addSyncProductsBatchJob(productIds: string[], action: 'create' | 'update' | 'delete' = 'create') {
    const jobData: SyncProductsBatchJobType = {
      productIds,
      action
    }

    try {
      await this.queue.add(SYNC_PRODUCTS_BATCH_JOB, jobData, {
        attempts: JOB_OPTIONS.ATTEMPTS,
        backoff: JOB_OPTIONS.BACKOFF,
        removeOnComplete: JOB_OPTIONS.REMOVE_ON_COMPLETE,
        removeOnFail: JOB_OPTIONS.REMOVE_ON_FAIL
      })

      this.logger.log(`✅ Added batch sync job for ${productIds.length} products with action: ${action}`)
    } catch (error) {
      this.logger.error(`❌ Failed to add batch sync job:`, error)
      throw error
    }
  }

  /**
   * Thêm job xóa sản phẩm khỏi ES
   */
  async addDeleteProductJob(productId: string) {
    try {
      await this.queue.add(
        DELETE_PRODUCT_JOB,
        { productId },
        {
          attempts: JOB_OPTIONS.ATTEMPTS,
          backoff: JOB_OPTIONS.BACKOFF,
          removeOnComplete: JOB_OPTIONS.REMOVE_ON_COMPLETE,
          removeOnFail: JOB_OPTIONS.REMOVE_ON_FAIL
        }
      )

      this.logger.log(`✅ Added delete job for product ${productId}`)
    } catch (error) {
      this.logger.error(`❌ Failed to add delete job for product ${productId}:`, error)
      throw error
    }
  }

  /**
   * Lấy thông tin queue
   */
  async getQueueInfo() {
    try {
      const [waiting, active, completed, failed] = await Promise.all([
        this.queue.getWaiting(),
        this.queue.getActive(),
        this.queue.getCompleted(),
        this.queue.getFailed()
      ])

      return {
        waiting: waiting.length,
        active: active.length,
        completed: completed.length,
        failed: failed.length
      }
    } catch (error) {
      this.logger.error('Failed to get queue info:', error)
      throw error
    }
  }

  /**
   * Xóa tất cả jobs trong queue
   */
  async clearQueue() {
    try {
      // Clean completed jobs
      await this.queue.clean(0, 0, 'completed')
      // Clean failed jobs
      await this.queue.clean(0, 0, 'failed')
      // Clean waiting jobs
      await this.queue.clean(0, 0, 'waiting')
      this.logger.log('✅ Cleared search sync queue')
    } catch (error) {
      this.logger.error('Failed to clear queue:', error)
      throw error
    }
  }

  /**
   * Pause queue
   */
  async pauseQueue() {
    try {
      await this.queue.pause()
      this.logger.log('⏸️ Paused search sync queue')
    } catch (error) {
      this.logger.error('Failed to pause queue:', error)
      throw error
    }
  }

  /**
   * Resume queue
   */
  async resumeQueue() {
    try {
      await this.queue.resume()
      this.logger.log('▶️ Resumed search sync queue')
    } catch (error) {
      this.logger.error('Failed to resume queue:', error)
      throw error
    }
  }
}
