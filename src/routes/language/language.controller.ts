import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  Post,
  Put,
  Query,
  UseGuards
} from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateLanguageBodyDTO,
  GetLanguageDetailResDTO,
  GetLanguageParamsDTO,
  GetLanguagesQueryDTO,
  GetLanguagesResDTO,
  RestoreLanguageBodyDTO,
  UpdateLanguageBodyDTO
} from 'src/routes/language/language.dto'
import { LanguageService } from 'src/routes/language/language.service'
import { ActiveUser } from '../auth/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { SkipThrottle, Throttle } from '@nestjs/throttler'
import { Roles } from '../../routes/auth/decorators/roles.decorator'
import { RolesGuard } from '../auth/guards/roles.guard'
import { IsPublic } from '../../routes/auth/decorators/auth.decorator'

@Controller('languages')
@UseGuards(RolesGuard)
export class LanguageController {
  private readonly logger = new Logger(LanguageController.name)

  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @ZodSerializerDto(GetLanguagesResDTO)
  @SkipThrottle()
  @IsPublic()
  findAll(@Query() query: GetLanguagesQueryDTO) {
    this.logger.debug(`Finding all languages with query: ${JSON.stringify(query)}`)
    return this.languageService.findAll(query)
  }

  @Get(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  @SkipThrottle()
  @IsPublic()
  findById(@Param() params: GetLanguageParamsDTO, @Query('includeDeleted') includeDeleted?: boolean) {
    this.logger.debug(`Finding language by ID: ${params.languageId}, includeDeleted: ${includeDeleted}`)
    return this.languageService.findById(params.languageId, includeDeleted)
  }

  @Post()
  @ZodSerializerDto(GetLanguageDetailResDTO)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  create(@Body() body: CreateLanguageBodyDTO, @ActiveUser('userId') userId: number) {
    this.logger.debug(`Creating language: ${JSON.stringify(body)}`)
    return this.languageService.create({
      data: body,
      createdById: userId
    })
  }

  @Put(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  @Throttle({ short: { limit: 10, ttl: 10000 } })
  @Roles('Admin')
  update(
    @Body() body: UpdateLanguageBodyDTO,
    @Param() params: GetLanguageParamsDTO,
    @ActiveUser('userId') userId: number
  ) {
    this.logger.debug(`Updating language ${params.languageId}: ${JSON.stringify(body)}`)
    return this.languageService.update({
      data: body,
      id: params.languageId,
      updatedById: userId
    })
  }

  @Delete(':languageId')
  @ZodSerializerDto(MessageResDTO)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  delete(
    @Param() params: GetLanguageParamsDTO,
    @ActiveUser('userId') userId: number,
    @Query('hardDelete') hardDelete?: boolean
  ) {
    this.logger.debug(`Deleting language ${params.languageId}, hardDelete: ${hardDelete}`)
    return this.languageService.delete(params.languageId, userId, hardDelete)
  }

  @Post(':languageId/restore')
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(GetLanguageDetailResDTO)
  @Throttle({ short: { limit: 5, ttl: 10000 } })
  @Roles('Admin')
  restore(
    @Param() params: GetLanguageParamsDTO,
    @Body() _: RestoreLanguageBodyDTO,
    @ActiveUser('userId') userId: number
  ) {
    this.logger.debug(`Restoring language ${params.languageId}`)
    return this.languageService.restore(params.languageId, userId)
  }
}
