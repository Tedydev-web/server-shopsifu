import { Module } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import { DiscountController } from './discount.controller'
import { DiscountService } from './discount.service'
import { ManageDiscountController } from './manage-discount/manage-discount.controller'
import { ManageDiscountService } from './manage-discount/manage-discount.service'

@Module({
  controllers: [DiscountController, ManageDiscountController],
  providers: [DiscountRepo, DiscountService, ManageDiscountService],
  exports: [DiscountRepo, DiscountService, ManageDiscountService]
})
export class DiscountModule {}
