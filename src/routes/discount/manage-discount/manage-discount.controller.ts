import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateDiscountBodyDTO,
  GetManageDiscountsQueryDTO,
  GetDiscountDetailResDTO,
  GetDiscountParamsDTO,
  GetDiscountsResDTO,
  UpdateDiscountBodyDTO,
  UpdateDiscountResDTO
} from '../discount.dto'
import { ManageDiscountService } from './manage-discount.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('manage-discount/discounts')
export class ManageDiscountController {
  constructor(private readonly manageDiscountService: ManageDiscountService) {}

  @Get()
  @ZodSerializerDto(GetDiscountsResDTO)
  list(@Query() query: GetManageDiscountsQueryDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.list({
      query,
      roleNameRequest: user.roleName,
      userIdRequest: user.userId
    })
  }

  @Get(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  findById(@Param() params: GetDiscountParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.getDetail({
      discountId: params.discountId,
      roleNameRequest: user.roleName,
      userIdRequest: user.userId
    })
  }

  @Post()
  @ZodSerializerDto(GetDiscountDetailResDTO)
  create(@Body() body: CreateDiscountBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.create({
      data: body,
      createdById: user.userId,
      roleName: user.roleName
    })
  }

  @Put(':discountId')
  @ZodSerializerDto(UpdateDiscountResDTO)
  update(
    @Body() body: UpdateDiscountBodyDTO,
    @Param() params: GetDiscountParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.manageDiscountService.update({
      data: body,
      discountId: params.discountId,
      updatedById: user.userId,
      roleNameRequest: user.roleName
    })
  }

  @Delete(':discountId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetDiscountParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.delete({
      discountId: params.discountId,
      deletedById: user.userId,
      roleNameRequest: user.roleName
    })
  }
}
