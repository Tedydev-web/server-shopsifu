import { Body, Controller, Delete, Get, Param, Post, Put } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateBrandTranslationBodyDTO,
  GetBrandTranslationDetailResDTO,
  GetBrandTranslationParamsDTO,
  UpdateBrandTranslationBodyDTO
} from 'src/routes/brand/brand-translation/brand-translation.dto'
import { BrandTranslationService } from 'src/routes/brand/brand-translation/brand-translation.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('brand-translations')
export class BrandTranslationController {
  constructor(private readonly brandTranslationService: BrandTranslationService) {}

  @Get(':brandTranslationId')
  @ZodSerializerDto(GetBrandTranslationDetailResDTO)
  findById(@Param() params: GetBrandTranslationParamsDTO) {
    return this.brandTranslationService.findById(params.brandTranslationId)
  }

  @Post()
  @ZodSerializerDto(GetBrandTranslationDetailResDTO)
  create(@Body() body: CreateBrandTranslationBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.brandTranslationService.create({ data: body, user } as any)
  }

  @Put(':brandTranslationId')
  @ZodSerializerDto(GetBrandTranslationDetailResDTO)
  update(
    @Body() body: UpdateBrandTranslationBodyDTO,
    @Param() params: GetBrandTranslationParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.brandTranslationService.update({ data: body, id: params.brandTranslationId, user })
  }

  @Delete(':brandTranslationId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetBrandTranslationParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.brandTranslationService.delete({ id: params.brandTranslationId, user })
  }
}
