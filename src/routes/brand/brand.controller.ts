import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateBrandBodyDTO,
  GetBrandDetailResDTO,
  GetBrandParamsDTO,
  GetBrandsResDTO,
  UpdateBrandBodyDTO
} from 'src/routes/brand/brand.dto'
import { BrandService } from 'src/routes/brand/brand.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { PaginationQueryDTO } from 'src/shared/dtos/request.dto'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('brands')
export class BrandController {
  constructor(private readonly brandService: BrandService) {}

  @Get()
  @IsPublic()
  @ZodSerializerDto(GetBrandsResDTO)
  list(@Query() query: PaginationQueryDTO) {
    return this.brandService.list(query as any)
  }

  @Get(':brandId')
  @IsPublic()
  @ZodSerializerDto(GetBrandDetailResDTO)
  findById(@Param() params: GetBrandParamsDTO) {
    return this.brandService.findById(params.brandId)
  }

  @Post()
  @ZodSerializerDto(GetBrandDetailResDTO)
  create(@Body() body: CreateBrandBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.brandService.create({ data: body, user } as any)
  }

  @Put(':brandId')
  @ZodSerializerDto(GetBrandDetailResDTO)
  update(@Body() body: UpdateBrandBodyDTO, @Param() params: GetBrandParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.brandService.update({ data: body, id: params.brandId, user })
  }

  @Delete(':brandId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetBrandParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.brandService.delete({ id: params.brandId, user })
  }
}
