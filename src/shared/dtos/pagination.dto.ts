import { createZodDto } from 'nestjs-zod'
import { PaginationQuerySchema } from 'src/shared/models/pagination.model'

// ==================== PAGINATION DTOs ====================

export class PaginationQueryDTO extends createZodDto(PaginationQuerySchema) {}
