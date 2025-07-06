import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { PaginationQueryDTO } from '../dtos/pagination.dto'

/**
 * Decorator để extract pagination query từ request
 * Sử dụng: @Pagination() query: PaginationQueryDTO
 */
export const Pagination = createParamDecorator((data: unknown, ctx: ExecutionContext): PaginationQueryDTO => {
  const request = ctx.switchToHttp().getRequest()
  const query = request.query

  return {
    page: Number(query.page) || 1,
    limit: Number(query.limit) || 10,
    sortOrder: query.sortOrder || 'desc',
    sortBy: query.sortBy
  }
})
