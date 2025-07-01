import { Body, Controller, Delete, Get, Param, Post, Put } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateLanguageBodyDTO,
  GetLanguageDetailResDTO,
  GetLanguageParamsDTO,
  GetLanguagesResDTO,
  UpdateLanguageBodyDTO,
} from 'src/routes/language/language.dto'
import { LanguageService } from 'src/routes/language/language.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'

@Controller('languages')
export class LanguageController {
  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @ZodSerializerDto(GetLanguagesResDTO)
  findAll() {
    return this.languageService.findAll()
  }

  @Get(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  findById(@Param() params: GetLanguageParamsDTO) {
    return this.languageService.findById(params.languageId)
  }

  @Post()
  @ZodSerializerDto(GetLanguageDetailResDTO)
  create(@Body() body: CreateLanguageBodyDTO, @ActiveUser('userId') userId: number) {
    return this.languageService.create({
      data: body,
      createdById: userId,
    })
  }
  // Không cho phép cập nhật id: Vì id là mã ngôn ngữ do người dùng tạo (ví dụ: 'en', 'vi'), nó nên bất biến (immutable). Nếu cần thay đổi id, bạn nên xóa ngôn ngữ cũ và tạo mới.

  // Kiểm tra soft delete: Theo nguyên tắc chung của soft delete, không nên cho phép cập nhật bản ghi đã bị xóa trừ khi có yêu cầu đặc biệt (ví dụ: khôi phục hoặc chỉnh sửa dữ liệu lịch sử).

  @Put(':languageId')
  @ZodSerializerDto(GetLanguageDetailResDTO)
  update(
    @Body() body: UpdateLanguageBodyDTO,
    @Param() params: GetLanguageParamsDTO,
    @ActiveUser('userId') userId: number,
  ) {
    return this.languageService.update({
      data: body,
      id: params.languageId,
      updatedById: userId,
    })
  }

  @Delete(':languageId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetLanguageParamsDTO) {
    return this.languageService.delete(params.languageId)
  }
}
