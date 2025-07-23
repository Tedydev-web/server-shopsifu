import { Module } from '@nestjs/common'
import { DiscountController } from './discount.controller'
import { DiscountService } from './discount.service'
import { DiscountRepo } from './discount.repo'
import { ManageDiscountService } from './manage-discount/manage-discount.service'
import { ManageDiscountController } from './manage-discount/manage-discount.controller'

@Module({
  controllers: [DiscountController, ManageDiscountController],
  providers: [DiscountService, DiscountRepo, ManageDiscountService],
  exports: [DiscountService, DiscountRepo]
})
export class DiscountModule {}
