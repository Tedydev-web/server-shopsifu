import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { ShippingController } from './shipping-ghn.controller'
import { ShippingService } from './shipping-ghn.service'
import { ShippingRepo } from './shipping-ghn.repo'

@Module({
  imports: [ConfigModule],
  controllers: [ShippingController],
  providers: [ShippingService, ShippingRepo]
})
export class ShippingModule {}
