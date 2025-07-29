import { registerAs } from '@nestjs/config'

export default registerAs(
  'payment',
  (): Record<string, any> => ({
    vnpay: {
      tmnCode: process.env.VNPAY_TMN_CODE,
      secureSecret: process.env.VNPAY_SECURE_SECRET
    }
  })
)
