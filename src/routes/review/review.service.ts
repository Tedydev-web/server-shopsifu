import { Injectable } from '@nestjs/common'
import { CreateReviewBodyType, UpdateReviewBodyType } from 'src/routes/review/review.model'
import { ReviewRepository } from 'src/routes/review/review.repo'
import { PaginationQueryType } from 'src/shared/models/request.model'

@Injectable()
export class ReviewService {
  constructor(private readonly reviewRepository: ReviewRepository) {}

  list(productId: string, pagination: PaginationQueryType) {
    return this.reviewRepository.list(productId, pagination)
  }

  async create(userId: string, body: CreateReviewBodyType) {
    return this.reviewRepository.create(userId, body)
  }

  async update({ userId, reviewId, body }: { userId: string; reviewId: string; body: UpdateReviewBodyType }) {
    return this.reviewRepository.update({
      userId,
      reviewId,
      body
    })
  }
}
