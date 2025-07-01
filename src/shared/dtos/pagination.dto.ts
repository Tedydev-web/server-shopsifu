import { createZodDto } from 'nestjs-zod'
import { BasePaginationQuerySchema } from 'src/shared/models/pagination.model'

// ==================== PAGINATION DTOs ====================

export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}
