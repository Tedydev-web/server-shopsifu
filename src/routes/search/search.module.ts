import { Module } from '@nestjs/common'
import { SearchController } from './search.controller'
import { SearchSyncService } from 'src/shared/services/search-sync.service'
import { SearchSyncQueueService } from 'src/shared/services/search-sync-queue.service'
import { SearchSyncConsumer } from 'src/shared/consumers/search-sync.consumer'
import { BullModule } from '@nestjs/bullmq'
import { SEARCH_SYNC_QUEUE_NAME } from 'src/shared/constants/search-sync.constant'

@Module({
  imports: [
    BullModule.registerQueue({
      name: SEARCH_SYNC_QUEUE_NAME
    })
  ],
  controllers: [SearchController],
  providers: [SearchSyncService, SearchSyncQueueService, SearchSyncConsumer],
  exports: [SearchSyncService, SearchSyncQueueService]
})
export class SearchModule {}
