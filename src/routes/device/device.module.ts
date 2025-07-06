import { Module } from '@nestjs/common'
import { DeviceController } from './device.controller'
import { DeviceService } from './device.service'
import { DeviceRepository } from './device.repository'

@Module({
  controllers: [DeviceController],
  providers: [DeviceService, DeviceRepository],
  exports: [DeviceService, DeviceRepository]
})
export class DeviceModule {}
