import { Controller, Get, Post, Put, Delete, Body, Param, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { LanguageService } from 'src/routes/language/language.service'
import {
  CreateLanguageBodyDTO,
  UpdateLanguageBodyDTO,
  GetLanguagesResDTO,
  GetLanguageDetailResDTO,
  CreateLanguageResDTO,
  UpdateLanguageResDTO,
  DeleteLanguageResDTO,
  GetLanguageParamsDTO,
  LanguagePaginationQueryDTO,
} from 'src/routes/language/language.dto'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { RequireCreate, RequireDelete, RequireRead, RequireUpdate } from 'src/shared/decorators/permission.decorator'

@Controller('languages')
export class LanguageController {
  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @RequireRead('language')
  @ZodSerializerDto(GetLanguagesResDTO)
  async findAll(@Query() query: LanguagePaginationQueryDTO) {
    const result = await this.languageService.findAll(query)
    return {
      message: 'language.success.GET_LANGUAGES',
      data: result.data,
      metadata: result.metadata,
    }
  }

  @Get(':languageId')
  @RequireRead('language')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  async findById(@Param() params: GetLanguageParamsDTO) {
    const language = await this.languageService.findById(params.languageId)
    return {
      message: 'language.success.GET_LANGUAGE_DETAIL',
      data: language,
    }
  }

  @Post()
  @RequireCreate('language')
  @ZodSerializerDto(CreateLanguageResDTO)
  async create(@Body() body: CreateLanguageBodyDTO, @ActiveUser('userId') userId: number) {
    const language = await this.languageService.create(body, userId)
    return {
      message: 'language.success.CREATE_LANGUAGE',
      data: language,
    }
  }

  @Put(':languageId')
  @RequireUpdate('language')
  @ZodSerializerDto(UpdateLanguageResDTO)
  async update(
    @Param() params: GetLanguageParamsDTO,
    @Body() body: UpdateLanguageBodyDTO,
    @ActiveUser('userId') userId: number,
  ) {
    const language = await this.languageService.update(params.languageId, body, userId)
    return {
      message: 'language.success.UPDATE_LANGUAGE',
      data: language,
    }
  }

  @Delete(':languageId')
  @RequireDelete('language')
  @ZodSerializerDto(DeleteLanguageResDTO)
  async delete(@Param() params: GetLanguageParamsDTO, @ActiveUser('userId') userId: number) {
    const language = await this.languageService.delete(params.languageId, userId)
    return {
      message: 'language.success.DELETE_LANGUAGE',
      data: language,
    }
  }
}
