import { Module } from '@nestjs/common'
import { DiscountRepo } from './discount.repo'
import { ManageDiscountController } from './manage-discount/manage-discount.controller'
import { ManageDiscountService } from './manage-discount/manage-discount.service'

@Module({
  controllers: [ManageDiscountController],
  providers: [DiscountRepo, ManageDiscountService],
  exports: [DiscountRepo, ManageDiscountService]
})
export class DiscountModule {}
