import { Prisma } from '@prisma/client'
import { randomInt } from 'crypto'

// Type Predicate
export function isUniqueConstraintPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002'
}

export function isNotFoundPrismaError(error: any): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025'
}

// export const generateOTP = () => {
//   return String(randomInt(100000, 1000000))
// }
export const generateOTP = (): string => {
  return String(randomInt(0, 1000000)).padStart(6, '0')
}
