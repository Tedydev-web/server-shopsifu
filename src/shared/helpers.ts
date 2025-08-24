import { Prisma } from '@prisma/client'
import { randomInt } from 'crypto'
import path from 'path'
import { v4 as uuidv4 } from 'uuid'

// Type Predicate
export function isUniqueConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002'
}

export function isNotFoundPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025'
}

export function isForeignKeyConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2003'
}

export const generateOTP = () => {
  return String(randomInt(100000, 1000000))
}

export const generateRandomFilename = (filename: string) => {
  const ext = path.extname(filename)
  return `${uuidv4()}${ext}`
}

export const generateCancelPaymentJobId = (paymentId: number) => {
  return `paymentId-${paymentId}`
}

export const generateShippingWebhookJobId = (orderCode: string) => {
  return `shipping-webhook-${orderCode}`
}

export const generateSearchSyncJobId = (type: string, identifier: string) => {
  return `search-sync-${type}-${identifier}`
}

export const generateRoomUserId = (userId: string) => {
  return `userId-${userId}`
}

export const generateRoomPaymentId = (paymentId: number) => {
  return `paymentId-${paymentId}`
}

export const generateRoomUserDevice = (userId: string, deviceId: string) => {
  return `userDevice-${userId}-${deviceId}`
}

export function calculateDiscountAmount(discount: any, orderTotal: number): number {
  let discountAmount = 0
  if (discount.discountType === 'FIX_AMOUNT') {
    discountAmount = discount.value
  } else if (discount.discountType === 'PERCENTAGE') {
    discountAmount = Math.floor(orderTotal * (discount.value / 100))
    if (discount.maxDiscountValue && discountAmount > discount.maxDiscountValue) {
      discountAmount = discount.maxDiscountValue
    }
  }
  return Math.min(discountAmount, orderTotal)
}
/**
 * Lấy ngày hiện tại theo múi giờ GMT+7
 * @returns Ngày theo định dạng yyyyMMddHHmmss
 */
export const getDateInGMT7 = (): number => {
  const now = new Date()
  const gmt7Offset = 7 * 60 // GMT+7 in minutes
  const gmt7Time = new Date(now.getTime() + gmt7Offset * 60 * 1000)

  const year = gmt7Time.getUTCFullYear()
  const month = String(gmt7Time.getUTCMonth() + 1).padStart(2, '0')
  const day = String(gmt7Time.getUTCDate()).padStart(2, '0')
  const hours = String(gmt7Time.getUTCHours()).padStart(2, '0')
  const minutes = String(gmt7Time.getUTCMinutes()).padStart(2, '0')
  const seconds = String(gmt7Time.getUTCSeconds()).padStart(2, '0')

  return parseInt(`${year}${month}${day}${hours}${minutes}${seconds}`)
}

/**
 * Validate discount eligibility cho order
 */
export function validateDiscountForOrder(
  discount: any,
  orderTotal: number,
  productIds: string[],
  categoryIds: string[],
  brandIds: string[],
  userUsageCount: number = 0
): boolean {
  // Kiểm tra minOrderValue
  if (discount.minOrderValue > 0 && orderTotal < discount.minOrderValue) {
    return false
  }

  // Kiểm tra maxUsesPerUser
  if (discount.maxUsesPerUser > 0 && userUsageCount >= discount.maxUsesPerUser) {
    return false
  }

  // Kiểm tra discountApplyType SPECIFIC
  if (discount.discountApplyType === 'SPECIFIC') {
    const hasValidProduct =
      discount.products.length > 0 && productIds.some((productId) => discount.products.some((p) => p.id === productId))
    const hasValidCategory =
      discount.categories.length > 0 &&
      categoryIds.some((categoryId) => discount.categories.some((c) => c.id === categoryId))
    const hasValidBrand =
      discount.brands.length > 0 && brandIds.some((brandId) => discount.brands.some((b) => b.id === brandId))

    if (!hasValidProduct && !hasValidCategory && !hasValidBrand) {
      return false
    }
  }

  return true
}

/**
 * Prepare discount data cho DiscountSnapshot
 */
export function prepareDiscountSnapshotData(discount: any, discountAmount: number, targetInfo?: any) {
  return {
    name: discount.name,
    description: discount.description,
    discountType: discount.discountType,
    value: discount.value,
    code: discount.code,
    maxDiscountValue: discount.maxDiscountValue,
    discountAmount: discountAmount,
    minOrderValue: discount.minOrderValue,
    isPlatform: discount.isPlatform,
    voucherType: discount.voucherType,
    displayType: discount.displayType,
    discountApplyType: discount.discountApplyType,
    targetInfo: targetInfo || null,
    discountId: discount.id
  }
}

export function normalizePhoneForGHN(phone: string | null | undefined): string {
  if (!phone) return ''
  const trimmed: string = String(phone).trim()
  if (trimmed.length === 0) return ''
  const e164Vietnam: boolean = trimmed.startsWith('+84')
  const raw: string = e164Vietnam ? `0${trimmed.slice(3)}` : trimmed
  const digitsOnly: string = raw.replace(/\D/g, '')
  // Yêu cầu: 10 số, đầu số di động VN hợp lệ: 03x, 056/058/059, 07x, 08x, 09x
  const isValidMobileVN: boolean = /^0(3\d|56|58|59|7\d|8\d|9\d)\d{7}$/.test(digitsOnly)
  if (!isValidMobileVN) return ''
  return digitsOnly
}
