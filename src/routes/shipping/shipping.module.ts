import { Module } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { ShippingController } from './shipping.controller'
import { ShippingService } from './shipping.service'
import { Ghn } from 'giaohangnhanh'
import { GHN_CLIENT } from '../../shared/constants/shipping.constants'

@Module({
  imports: [ConfigModule],
  controllers: [ShippingController],
  providers: [
    ShippingService,
    {
      provide: GHN_CLIENT,
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const token = configService.get<string>('GHN_TOKEN')
        const shopIdRaw = configService.get<string>('GHN_SHOP_ID')
        const host = configService.get<string>('GHN_HOST')
        const testModeRaw = configService.get<string>('GHN_TEST_MODE')
        if (!token) throw new Error('GHN_TOKEN is required in environment variables')
        if (!shopIdRaw) throw new Error('GHN_SHOP_ID is required in environment variables')
        if (!host) throw new Error('GHN_HOST is required in environment variables')
        const shopId = Number(shopIdRaw)
        if (!Number.isFinite(shopId) || shopId <= 0) throw new Error('GHN_SHOP_ID must be a positive number')
        const testMode = String(testModeRaw ?? 'true').toLowerCase() === 'true'
        return new Ghn({ token, shopId, host, testMode })
      }
    }
  ],
  exports: [ShippingService, GHN_CLIENT]
})
export class ShippingModule {}
