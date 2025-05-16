
# Quy trình xây dựng API CRUD cho Language

Dưới đây là các bước chi tiết để xây dựng API CRUD cho model Language trong schema.prisma:

## Bước 1: Tạo cấu trúc thư mục

```bash
mkdir -p src/routes/language
```

## Bước 2: Tạo các files cần thiết sử dụng NestJS CLI

```bash
nest g module routes/language
nest g controller routes/language
nest g service routes/language
touch src/routes/language/language.model.ts
touch src/routes/language/language.dto.ts
touch src/routes/language/language.repo.ts
touch src/routes/language/error.model.ts
```

## Bước 3: Định nghĩa model với Zod

```typescript
// src/routes/language/language.model.ts
import { z } from 'zod'

export const LanguageSchema = z.object({
  id: z.number(),
  name: z.string().min(1).max(500),
  code: z.string().min(2).max(10),
  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const CreateLanguageSchema = LanguageSchema
  .pick({
    name: true,
    code: true
  })
  .strict()

export const UpdateLanguageSchema = CreateLanguageSchema
  .partial()
  .strict()

export type LanguageType = z.infer<typeof LanguageSchema>
export type CreateLanguageType = z.infer<typeof CreateLanguageSchema>
export type UpdateLanguageType = z.infer<typeof UpdateLanguageSchema>
```

## Bước 4: Tạo DTO từ Zod schema

```typescript
// src/routes/language/language.dto.ts
import { createZodDto } from 'nestjs-zod'
import { 
  CreateLanguageSchema, 
  UpdateLanguageSchema, 
  LanguageSchema 
} from './language.model'

export class CreateLanguageDTO extends createZodDto(CreateLanguageSchema) {}
export class UpdateLanguageDTO extends createZodDto(UpdateLanguageSchema) {}
export class LanguageDTO extends createZodDto(LanguageSchema) {}
```

## Bước 5: Định nghĩa lỗi

```typescript
// src/routes/language/error.model.ts
import { NotFoundException, UnprocessableEntityException } from '@nestjs/common'

export const LanguageNotFoundException = new NotFoundException([
  {
    message: 'ERROR.LANGUAGE_NOT_FOUND',
    path: 'id'
  }
])

export const LanguageCodeExistsException = new UnprocessableEntityException([
  {
    message: 'ERROR.LANGUAGE_CODE_EXISTS',
    path: 'code'
  }
])
```

## Bước 6: Tạo Repository

```typescript
// src/routes/language/language.repo.ts
import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { CreateLanguageType, LanguageType, UpdateLanguageType } from './language.model'

@Injectable()
export class LanguageRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async findAll(): Promise<LanguageType[]> {
    return this.prismaService.language.findMany({
      where: {
        deletedAt: null
      }
    })
  }

  async findById(id: number): Promise<LanguageType | null> {
    return this.prismaService.language.findUnique({
      where: { id, deletedAt: null }
    })
  }

  async create(data: CreateLanguageType, userId?: number): Promise<LanguageType> {
    return this.prismaService.language.create({
      data: {
        ...data,
        createdById: userId
      }
    })
  }

  async update(id: number, data: UpdateLanguageType, userId?: number): Promise<LanguageType> {
    return this.prismaService.language.update({
      where: { id },
      data: {
        ...data,
        updatedById: userId
      }
    })
  }

  async delete(id: number): Promise<LanguageType> {
    return this.prismaService.language.update({
      where: { id },
      data: {
        deletedAt: new Date()
      }
    })
  }
}
```

## Bước 7: Tạo Service

```typescript
// src/routes/language/language.service.ts
import { Injectable } from '@nestjs/common'
import { LanguageRepository } from './language.repo'
import { CreateLanguageType, UpdateLanguageType } from './language.model'
import { LanguageNotFoundException } from './error.model'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageCodeExistsException } from './error.model'

@Injectable()
export class LanguageService {
  constructor(private readonly languageRepo: LanguageRepository) {}

  async findAll() {
    return this.languageRepo.findAll()
  }

  async findById(id: number) {
    const language = await this.languageRepo.findById(id)
    if (!language) {
      throw LanguageNotFoundException
    }
    return language
  }

  async create(data: CreateLanguageType, userId?: number) {
    try {
      return await this.languageRepo.create(data, userId)
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageCodeExistsException
      }
      throw error
    }
  }

  async update(id: number, data: UpdateLanguageType, userId?: number) {
    try {
      // Kiểm tra tồn tại
      await this.findById(id)
      return await this.languageRepo.update(id, data, userId)
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageCodeExistsException
      }
      throw error
    }
  }

  async delete(id: number) {
    // Kiểm tra tồn tại
    await this.findById(id)
    return this.languageRepo.delete(id)
  }
}
```

## Bước 8: Tạo Controller

```typescript
// src/routes/language/language.controller.ts
import { 
  Body, 
  Controller, 
  Delete, 
  Get, 
  HttpStatus, 
  Param, 
  Post, 
  Put 
} from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { LanguageService } from './language.service'
import { CreateLanguageDTO, UpdateLanguageDTO } from './language.dto'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { ApiResponseDTO } from 'src/shared/dtos/response.dto'

@Controller('languages')
export class LanguageController {
  constructor(private readonly languageService: LanguageService) {}

  @Get()
  @ZodSerializerDto(ApiResponseDTO)
  async findAll() {
    const languages = await this.languageService.findAll()
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'LANGUAGE.FOUND_ALL_SUCCESSFULLY'
      },
      data: languages
    }
  }

  @Get(':id')
  @ZodSerializerDto(ApiResponseDTO)
  async findOne(@Param('id') id: string) {
    const language = await this.languageService.findById(+id)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'LANGUAGE.FOUND_SUCCESSFULLY'
      },
      data: language
    }
  }

  @Post()
  @ZodSerializerDto(ApiResponseDTO)
  async create(@Body() createLanguageDto: CreateLanguageDTO, @ActiveUser('userId') userId?: number) {
    const language = await this.languageService.create(createLanguageDto, userId)
    return {
      success: true,
      statusCode: HttpStatus.CREATED,
      message: {
        code: 'LANGUAGE.CREATED_SUCCESSFULLY'
      },
      data: language
    }
  }

  @Put(':id')
  @ZodSerializerDto(ApiResponseDTO)
  async update(
    @Param('id') id: string, 
    @Body() updateLanguageDto: UpdateLanguageDTO,
    @ActiveUser('userId') userId?: number
  ) {
    const language = await this.languageService.update(+id, updateLanguageDto, userId)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'LANGUAGE.UPDATED_SUCCESSFULLY'
      },
      data: language
    }
  }

  @Delete(':id')
  @ZodSerializerDto(ApiResponseDTO)
  async remove(@Param('id') id: string) {
    await this.languageService.delete(+id)
    return {
      success: true,
      statusCode: HttpStatus.OK,
      message: {
        code: 'LANGUAGE.DELETED_SUCCESSFULLY'
      }
    }
  }
}
```

## Bước 9: Cập nhật Module

```typescript
// src/routes/language/language.module.ts
import { Module } from '@nestjs/common'
import { LanguageController } from './language.controller'
import { LanguageService } from './language.service'
import { LanguageRepository } from './language.repo'

@Module({
  controllers: [LanguageController],
  providers: [LanguageService, LanguageRepository],
  exports: [LanguageService]
})
export class LanguageModule {}
```

## Bước 10: Cập nhật App Module

```typescript
// src/app.module.ts
import { LanguageModule } from 'src/routes/language/language.module'

@Module({
  imports: [
    SharedModule, 
    AuthModule,
    LanguageModule
  ],
  // ... các phần khác không đổi
})
export class AppModule {}
```

## Giải thích quy trình và mục đích:

1. **Model (language.model.ts)**: Định nghĩa cấu trúc dữ liệu sử dụng Zod schema, tạo ra các schema cho:
   - Schema đầy đủ cho Language
   - Schema cho tạo mới (chỉ lấy các trường cần thiết)
   - Schema cho cập nhật (các trường có thể thay đổi)

2. **DTO (language.dto.ts)**: Chuyển đổi Zod schema thành DTO classes:
   - CreateLanguageDTO: Dùng cho request tạo language mới
   - UpdateLanguageDTO: Dùng cho request cập nhật language
   - LanguageDTO: Dùng cho response trả về

3. **Error Model (error.model.ts)**: Định nghĩa các lỗi cụ thể cho API:
   - LanguageNotFoundException: Trả về khi không tìm thấy ngôn ngữ
   - LanguageCodeExistsException: Trả về khi mã ngôn ngữ đã tồn tại

4. **Repository (language.repo.ts)**: Xử lý tương tác với database:
   - Truy vấn dữ liệu (findAll, findById)
   - Thêm, sửa, xóa (create, update, delete)

5. **Service (language.service.ts)**: Chứa logic nghiệp vụ:
   - Xử lý các exceptions
   - Xác thực dữ liệu trước khi thao tác với DB
   - Định hình format dữ liệu

6. **Controller (language.controller.ts)**: Định nghĩa API endpoints:
   - GET /languages: Lấy tất cả ngôn ngữ
   - GET /languages/:id: Lấy ngôn ngữ theo ID
   - POST /languages: Tạo ngôn ngữ mới
   - PUT /languages/:id: Cập nhật ngôn ngữ
   - DELETE /languages/:id: Xóa ngôn ngữ

7. **Module (language.module.ts)**: Đăng ký các components:
   - Controllers: Đăng ký controller
   - Providers: Đăng ký service và repository
   - Exports: Export service để các module khác có thể sử dụng

8. **App Module**: Đăng ký LanguageModule với ứng dụng.

Lưu ý: API đã được tự động áp dụng các tính năng:
- Kiểm tra quyền truy cập thông qua authentication guard
- Response transformation thông qua interceptor
- Validation thông qua Zod
- Xử lý lỗi nhất quán
