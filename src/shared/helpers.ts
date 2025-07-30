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

export const generateRoomUserId = (userId: string) => {
  return `userId-${userId}`
}

export function calculateDiscountAmount(discount: any, orderTotal: number): number {
  let discountAmount = 0
  if (discount.type === 'FIX_AMOUNT') {
    discountAmount = discount.value
  } else if (discount.type === 'PERCENTAGE') {
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
