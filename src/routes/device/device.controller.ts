import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Patch,
  UseGuards,
} from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResponseDTO } from 'src/shared/dtos/core.dto'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { DeviceResponseDto, RenameDeviceDto } from './device.dto'
import { DeviceService } from './device.service'

@Controller('devices')
@UseGuards(AccessTokenGuard)
@ZodSerializerDto(DeviceResponseDto)
export class DeviceController {
  constructor(private readonly deviceService: DeviceService) {}

  @Get()
  async listDevicesForUser(@ActiveUser('userId') userId: number) {
    return this.deviceService.listDevicesForUser(userId)
  }

  @Patch(':id')
  async renameDevice(
    @ActiveUser('userId') userId: number,
    @Param('id', ParseIntPipe) deviceId: number,
    @Body() body: RenameDeviceDto,
  ) {
    return this.deviceService.renameDevice(userId, deviceId, body.name)
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(MessageResponseDTO)
  async revokeDevice(@ActiveUser('userId') userId: number, @Param('id', ParseIntPipe) deviceId: number) {
    return this.deviceService.revokeDevice(userId, deviceId)
  }
}
