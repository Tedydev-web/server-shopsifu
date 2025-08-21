import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { ShippingController } from './shipping.controller'
import { ShippingService } from './shipping.service'
import { ShippingRepo } from './shipping.repo'

@Module({
  imports: [ConfigModule],
  controllers: [ShippingController],
  providers: [ShippingService, ShippingRepo]
})
export class ShippingModule {}
