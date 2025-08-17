import { Controller, Get, Post, Put, Delete, Query, Param, Body } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { ManageDiscountService } from './manage-discount.service'
import {
  GetManageDiscountsQueryDTO,
  GetManageDiscountsResDTO,
  GetDiscountParamsDTO,
  GetDiscountDetailResDTO,
  CreateDiscountBodyDTO,
  UpdateDiscountBodyDTO,
  CreateDiscountResDTO,
  UpdateDiscountResDTO
} from '../discount.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'

@Controller('manage-discount/discounts')
export class ManageDiscountController {
  constructor(private readonly manageDiscountService: ManageDiscountService) {}

  @Get()
  @ZodSerializerDto(GetManageDiscountsResDTO)
  list(@Query() query: GetManageDiscountsQueryDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.list({ query, user } as any)
  }

  @Get(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  findById(@Param() params: GetDiscountParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.getDetail({ discountId: params.discountId, user })
  }

  @Post()
  @ZodSerializerDto(CreateDiscountResDTO)
  create(@Body() body: CreateDiscountBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.create({ data: body, user } as any)
  }

  @Put(':discountId')
  @ZodSerializerDto(UpdateDiscountResDTO)
  update(
    @Body() body: UpdateDiscountBodyDTO,
    @Param() params: GetDiscountParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.manageDiscountService.update({ data: body, discountId: params.discountId, user } as any)
  }

  @Delete(':discountId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetDiscountParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageDiscountService.delete({ discountId: params.discountId, user })
  }
}
