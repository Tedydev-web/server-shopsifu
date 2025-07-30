import { Module } from '@nestjs/common'
import { DiscountService } from './discount.service'
import { DiscountController } from './discount.controller'

@Module({
  providers: [DiscountService],
  controllers: [DiscountController]
})
export class DiscountModule {}
