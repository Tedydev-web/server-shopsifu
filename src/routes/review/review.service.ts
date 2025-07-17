import { Injectable } from '@nestjs/common'
import { CreateReviewBodyType, UpdateReviewBodyType } from 'src/routes/review/review.model'
import { ReviewRepository } from 'src/routes/review/review.repo'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class ReviewService {
  constructor(
    private readonly reviewRepository: ReviewRepository,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async list(productId: string, pagination: PaginationQueryType) {
    const data = await this.reviewRepository.list(productId, pagination)
    return {
      message: this.i18n.t('review.review.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async create(userId: string, body: CreateReviewBodyType) {
    const review = await this.reviewRepository.create(userId, body)
    return {
      message: this.i18n.t('review.review.success.CREATE_SUCCESS'),
      data: review
    }
  }

  async update({ userId, reviewId, body }: { userId: string; reviewId: string; body: UpdateReviewBodyType }) {
    const review = await this.reviewRepository.update({
      userId,
      reviewId,
      body
    })
    return {
      message: this.i18n.t('review.review.success.UPDATE_SUCCESS'),
      data: review
    }
  }
}
