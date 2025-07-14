import { Body, Controller, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ReviewService } from './review.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import {
  CreateReviewBodyDTO,
  CreateReviewResDTO,
  GetReviewDetailParamsDTO,
  GetReviewsDTO,
  GetReviewsParamsDTO,
  UpdateReviewBodyDTO,
  UpdateReviewResDTO,
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
    return this.reviewService.list(params.productId, pagination)
  }

  @Post()
  @ZodSerializerDto(CreateReviewResDTO)
  updateReview(@Body() body: CreateReviewBodyDTO, @ActiveUser('userId') userId: number) {
    return this.reviewService.create(userId, body)
  }

  @Put(':reviewId')
  @ZodSerializerDto(UpdateReviewResDTO)
  changePassword(
    @Body() body: UpdateReviewBodyDTO,
    @ActiveUser('userId') userId: number,
    @Param() params: GetReviewDetailParamsDTO,
  ) {
    return this.reviewService.update({
      userId,
      body,
      reviewId: params.reviewId,
    })
  }
}
