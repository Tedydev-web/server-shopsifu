import { Module } from '@nestjs/common'
import { ManageDiscountController } from 'src/routes/discount/manage-discount/manage-discount.controller'
import { ManageDiscountService } from 'src/routes/discount/manage-discount/manage-discount.service'
import { DiscountController } from 'src/routes/discount/discount.controller'
import { DiscountRepo } from 'src/routes/discount/discount.repo'
import { DiscountService } from 'src/routes/discount/discount.service'

@Module({
  providers: [DiscountService, ManageDiscountService, DiscountRepo],
  controllers: [DiscountController, ManageDiscountController]
})
export class DiscountModule {}
