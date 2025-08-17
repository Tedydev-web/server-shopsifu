import { Body, Controller, Delete, Get, Param, Post, Put } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ProfileService } from './profile.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { GetUserProfileResDTO, UpdateProfileResDTO } from 'src/shared/dtos/shared-user.dto'
import {
  ChangePasswordBodyDTO,
  UpdateMeBodyDTO,
  CreateAddressBodyDTO,
  UpdateAddressBodyDTO,
  GetAddressParamsDTO,
  GetUserAddressesResDTO,
  GetUserAddressDetailResDTO,
  CreateAddressResDTO,
  UpdateAddressResDTO
} from './profile.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  @ZodSerializerDto(GetUserProfileResDTO)
  getProfile(@ActiveUser() user: AccessTokenPayload) {
    return this.profileService.getProfile(user)
  }

  @Put()
  @ZodSerializerDto(UpdateProfileResDTO)
  updateProfile(@Body() body: UpdateMeBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.profileService.updateProfile({ user, body } as any)
  }

  @Put('change-password')
  @ZodSerializerDto(MessageResDTO)
  changePassword(@Body() body: ChangePasswordBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.profileService.changePassword({ user, body } as any)
  }

  // Address management endpoints
  @Get('addresses')
  @ZodSerializerDto(GetUserAddressesResDTO)
  getAddresses(@ActiveUser() user: AccessTokenPayload) {
    return this.profileService.getAddresses(user)
  }

  @Get('addresses/:addressId')
  @ZodSerializerDto(GetUserAddressDetailResDTO)
  getAddressById(@Param() params: GetAddressParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.profileService.getAddressById(params.addressId, user)
  }

  @Post('addresses')
  @ZodSerializerDto(CreateAddressResDTO)
  createAddress(@Body() body: CreateAddressBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.profileService.createAddress(body as any, user)
  }

  @Put('addresses/:addressId')
  @ZodSerializerDto(UpdateAddressResDTO)
  updateAddress(
    @Param() params: GetAddressParamsDTO,
    @Body() body: UpdateAddressBodyDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.profileService.updateAddress(params.addressId, body, user)
  }

  @Delete('addresses/:addressId')
  @ZodSerializerDto(MessageResDTO)
  deleteAddress(@Param() params: GetAddressParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.profileService.deleteAddress(params.addressId, user)
  }
}
