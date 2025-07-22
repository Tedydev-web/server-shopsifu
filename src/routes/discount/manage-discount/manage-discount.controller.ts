import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  GetDiscountsResDTO,
  GetDiscountDetailResDTO,
  GetDiscountParamsDTO,
  CreateDiscountBodyDTO,
  UpdateDiscountBodyDTO,
  GetManageDiscountsQueryDTO
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
    return this.manageDiscountService.list({ query, user })
  }

  @Get(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  findById(@Param() params: GetDiscountParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.findById(params.discountId, user)
  }

  @Post()
  @ZodSerializerDto(GetDiscountDetailResDTO)
  create(@Body() body: CreateDiscountBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.create({ data: body, user })
  }

  @Put(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  update(
    @Param() params: GetDiscountParamsDTO,
    @Body() body: UpdateDiscountBodyDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.manageDiscountService.update({ id: params.discountId, data: body, user })
  }

  @Delete(':discountId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetDiscountParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.delete(params.discountId, user)
  }
}
