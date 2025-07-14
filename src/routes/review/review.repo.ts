import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common'
import {
  CreateReviewBodyType,
  CreateReviewResType,
  GetReviewsType,
  UpdateReviewBodyType,
  UpdateReviewResType,
} from 'src/routes/review/review.model'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class ReviewRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async list(productId: number, pagination: PaginationQueryType): Promise<GetReviewsType> {
    const skip = (pagination.page - 1) * pagination.limit
    const take = pagination.limit

    const [totalItems, data] = await Promise.all([
      this.prismaService.review.count({
        where: {
          productId,
        },
      }),
      this.prismaService.review.findMany({
        where: {
          productId,
        },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              avatar: true,
            },
          },
          medias: true,
        },
        skip,
        take,
        orderBy: {
          createdAt: 'desc',
        },
      }),
    ])
    return {
      data,
      totalItems,
      page: pagination.page,
      limit: pagination.limit,
      totalPages: Math.ceil(totalItems / pagination.limit),
    }
  }

  private async validateOrder({ orderId, userId }: { orderId: number; userId: number }) {
    const order = await this.prismaService.order.findUnique({
      where: {
        id: orderId,
        userId,
      },
    })
    // Mua hàng thì mới được review
    if (!order) {
      throw new BadRequestException('Đơn hàng không tồn tại hoặc không thuộc về bạn')
    }

    // Đơn hàng đã giao thì mới được review
    if (order.status !== OrderStatus.DELIVERED) {
      throw new BadRequestException('Đơn hàng chưa được giao')
    }
    return order
  }

  private async validateUpdateReview({ reviewId, userId }: { reviewId: number; userId: number }) {
    const review = await this.prismaService.review.findUnique({
      where: {
        id: reviewId,
        userId,
      },
    })
    if (!review) {
      throw new NotFoundException('Đánh giá không tồn tại hoặc không thuộc về bạn')
    }
    if (review.updateCount >= 1) {
      throw new BadRequestException('Bạn chỉ được phép sửa đánh giá 1 lần')
    }
    return review
  }

  async create(userId: number, body: CreateReviewBodyType): Promise<CreateReviewResType> {
    const { content, medias, productId, orderId, rating } = body
    await this.validateOrder({
      orderId,
      userId,
    })
    return this.prismaService.$transaction(async (tx) => {
      const review = await tx.review
        .create({
          data: {
            content,
            rating,
            productId,
            orderId,
            userId,
          },
          include: {
            user: {
              select: {
                id: true,
                name: true,
                avatar: true,
              },
            },
          },
        })
        .catch((error) => {
          if (isUniqueConstraintPrismaError(error)) {
            throw new ConflictException('Bạn đã đánh giá sản phẩm này rồi')
          }
          throw error
        })
      const reviewMedias = await tx.reviewMedia.createManyAndReturn({
        data: medias.map((media) => ({
          url: media.url,
          type: media.type,
          reviewId: review.id,
        })),
      })
      return {
        ...review,
        medias: reviewMedias,
      }
    })
  }

  async update({
    userId,
    reviewId,
    body,
  }: {
    userId: number
    reviewId: number
    body: UpdateReviewBodyType
  }): Promise<UpdateReviewResType> {
    const { content, medias, productId, orderId, rating } = body
    await Promise.all([
      this.validateOrder({
        orderId,
        userId,
      }),
      this.validateUpdateReview({
        reviewId,
        userId,
      }),
    ])
    return this.prismaService.$transaction(async (tx) => {
      const review = await tx.review.update({
        where: {
          id: reviewId,
        },
        data: {
          content,
          rating,
          productId,
          orderId,
          userId,
          updateCount: {
            increment: 1,
          },
        },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              avatar: true,
            },
          },
        },
      })

      await tx.reviewMedia.deleteMany({
        where: {
          reviewId,
        },
      })
      const reviewMedias = await tx.reviewMedia.createManyAndReturn({
        data: medias.map((media) => ({
          url: media.url,
          type: media.type,
          reviewId: review.id,
        })),
      })
      return {
        ...review,
        medias: reviewMedias,
      }
    })
  }
}
