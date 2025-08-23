import { Body, Controller, Delete, Get, Header, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateCategoryBodyDTO,
  GetCategoryDetailResDTO,
  GetCategoryParamsDTO,
  GetAllCategoriesResDTO,
  UpdateCategoryBodyDTO,
  GetAllCategoriesQueryDTO
} from 'src/routes/category/category.dto'
import { CategoryService } from 'src/routes/category/category.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('categories')
export class CategoryController {
  constructor(private readonly categoryService: CategoryService) {}

  /**
   * 📂 Category tree với hierarchical caching - categories rất ít thay đổi
   */
  @Get()
  @IsPublic()
  @ZodSerializerDto(GetAllCategoriesResDTO)
  @Header('Cache-Control', 'public, max-age=1800, s-maxage=1800, stale-while-revalidate=3600')
  @Header('Vary', 'Accept-Language')
  @Header('X-Cache-Strategy', 'redis+cdn+hierarchical')
  findAll(@Query() query: GetAllCategoriesQueryDTO) {
    return this.categoryService.findAll(query.parentCategoryId)
  }

  /**
   * 🎯 Category detail với stable caching - category info rất ổn định
   */
  @Get(':categoryId')
  @IsPublic()
  @ZodSerializerDto(GetCategoryDetailResDTO)
  @Header('Cache-Control', 'public, max-age=3600, s-maxage=3600, stale-while-revalidate=7200')
  @Header('Vary', 'Accept-Language')
  @Header('X-Cache-Strategy', 'redis+cdn+stable')
  findById(@Param() params: GetCategoryParamsDTO) {
    return this.categoryService.findById(params.categoryId)
  }

  @Post()
  @ZodSerializerDto(GetCategoryDetailResDTO)
  create(@Body() body: CreateCategoryBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.categoryService.create({ data: body, user } as any)
  }

  @Put(':categoryId')
  @ZodSerializerDto(GetCategoryDetailResDTO)
  update(
    @Body() body: UpdateCategoryBodyDTO,
    @Param() params: GetCategoryParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.categoryService.update({ data: body, id: params.categoryId, user } as any)
  }

  @Delete(':categoryId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetCategoryParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.categoryService.delete({ id: params.categoryId, user })
  }
}
