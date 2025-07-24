import { Injectable, Logger } from '@nestjs/common'
import { Cron, CronExpression } from '@nestjs/schedule'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountStatus } from 'src/shared/constants/discount.constant'

@Injectable()
export class ExpireDiscountCronjob {
  private readonly logger = new Logger(ExpireDiscountCronjob.name)

  constructor(private readonly prisma: PrismaService) {}

  @Cron(CronExpression.EVERY_HOUR)
  async handleExpireDiscounts() {
    const now = new Date()
    const result = await this.prisma.discount.updateMany({
      where: {
        endDate: { lt: now },
        discountStatus: DiscountStatus.ACTIVE
      },
      data: { discountStatus: DiscountStatus.EXPIRED }
    })
    if (result.count > 0) {
      this.logger.log(`Đã cập nhật ${result.count} discount hết hạn thành EXPIRED.`)
    }
  }
}
