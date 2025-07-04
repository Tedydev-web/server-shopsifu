import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { BasePaginationQueryType } from '../models/pagination.model'

/**
 * Decorator để extract pagination query từ request
 * Sử dụng: @Pagination() query: BasePaginationQueryType
 */
export const Pagination = createParamDecorator((data: unknown, ctx: ExecutionContext): BasePaginationQueryType => {
  const request = ctx.switchToHttp().getRequest()
  const query = request.query

  return {
    limit: Number(query.limit) || 10,
    offset: Number(query.offset) || 0,
    sortOrder: query.sortOrder || 'desc',
    sortBy: query.sortBy,
    search: query.search,
  }
})
