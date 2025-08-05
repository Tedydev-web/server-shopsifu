import { PrismaClient } from '@prisma/client'
import { logger, CONFIG } from './import-utils'

export async function importAddresses(
  users: Array<{ id: string }>,
  creatorUserId: string,
  tx: PrismaClient
): Promise<{ addressCount: number; userAddressCount: number }> {
  const addressesToCreate: Array<{
    name: string
    recipient?: string
    phoneNumber?: string
    province: string
    district: string
    ward: string
    street: string
    addressType: 'HOME' | 'OFFICE' | 'OTHER'
    createdById: string
    userId: string
    isDefault: boolean
    createdAt: Date
    updatedAt: Date
  }> = []
  const userAddressesToCreate: Array<{
    userId: string
    addressId: string
    createdAt: Date
    updatedAt: Date
  }> = []
  users.forEach((user) => {
    const numAddresses = Math.floor(Math.random() * 3) + 1
    for (let i = 0; i < numAddresses; i++) {
      const now = new Date()
      addressesToCreate.push({
        name: `Địa chỉ ${i + 1}`,
        recipient: `Người nhận ${i + 1}`,
        phoneNumber:
          '+84' +
          Math.floor(Math.random() * 1000000000)
            .toString()
            .padStart(9, '0'),
        province: 'Hà Nội',
        district: 'Cầu Giấy',
        ward: 'Dịch Vọng',
        street: `Đường ${i + 1}`,
        addressType: 'HOME',
        createdById: creatorUserId,
        userId: user.id,
        isDefault: i === 0,
        createdAt: now,
        updatedAt: now
      })
    }
  })
  let addressCount = 0
  let userAddressCount = 0
  const copyBatchSize = CONFIG.COPY_BATCH_SIZE
  const copyChunks = Array.from({ length: Math.ceil(addressesToCreate.length / copyBatchSize) }, (_, i) =>
    addressesToCreate.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )
  for (const chunk of copyChunks) {
    const addressData = chunk.map(({ userId, isDefault, ...data }) => data)
    await tx.address.createMany({ data: addressData })
    const createdAddressData = await tx.address.findMany({
      where: { name: { in: chunk.map((a) => a.name) } },
      select: { id: true, name: true }
    })
    const userAddresses = chunk
      .map((address) => {
        const createdAddress = createdAddressData.find((a) => a.name === address.name)
        return createdAddress
          ? {
              userId: address.userId,
              addressId: createdAddress.id,
              createdAt: address.createdAt,
              updatedAt: address.updatedAt
            }
          : null
      })
      .filter((ua): ua is { userId: string; addressId: string; createdAt: Date; updatedAt: Date } => ua !== null)
    if (userAddresses.length) {
      await tx.userAddress.createMany({ data: userAddresses, skipDuplicates: true })
    }
    addressCount += chunk.length
    userAddressCount += userAddresses.length
  }
  logger.log(`✅ Imported ${addressCount} addresses and ${userAddressCount} user-address relationships`)
  return { addressCount, userAddressCount }
}
