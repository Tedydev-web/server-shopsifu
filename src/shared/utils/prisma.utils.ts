// Database Error Type Guards (không cần import trực tiếp từ Prisma)
export function isUniqueConstraintPrismaError(error: any): boolean {
  return error?.code === 'P2002'
}

export function isNotFoundPrismaError(error: any): boolean {
  return error?.code === 'P2025'
}
