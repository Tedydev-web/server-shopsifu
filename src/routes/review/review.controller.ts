import { Body, Controller, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ReviewService } from './review.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import {
  CreateReviewBodyDTO,
  CreateReviewResDTO,
  GetReviewDetailParamsDTO,
  GetReviewsDTO,
  GetReviewsParamsDTO,
  UpdateReviewBodyDTO,
  UpdateReviewResDTO
} from 'src/routes/review/review.dto'
import { PaginationQueryDTO } from 'src/shared/dtos/request.dto'
import { IsPublic } from 'src/shared/decorators/auth.decorator'

@Controller('reviews')
export class ReviewController {
  constructor(private readonly reviewService: ReviewService) {}

  @IsPublic()
  @Get('/products/:productId')
  @ZodSerializerDto(GetReviewsDTO)
  getReviews(@Param() params: GetReviewsParamsDTO, @Query() pagination: PaginationQueryDTO) {
    return this.reviewService.list(params.productId, pagination as any)
  }

  @Post()
  @ZodSerializerDto(CreateReviewResDTO)
  createReview(@Body() body: CreateReviewBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.reviewService.create(user, body as any)
  }

  @Put(':reviewId')
  @ZodSerializerDto(UpdateReviewResDTO)
  updateReview(
    @Body() body: UpdateReviewBodyDTO,
    @ActiveUser() user: AccessTokenPayload,
    @Param() params: GetReviewDetailParamsDTO
  ) {
    return this.reviewService.update({ user, body, reviewId: params.reviewId } as any)
  }
}
