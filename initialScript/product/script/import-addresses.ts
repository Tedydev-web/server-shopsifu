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
    // GHN ID fields - sử dụng dữ liệu thực tế từ GHN API
    provinceId?: number
    districtId?: number
    wardCode?: string
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

  // Lấy danh sách users với role để phân biệt
  const usersWithRole = await tx.user.findMany({
    where: { id: { in: users.map((u) => u.id) } },
    include: { role: true }
  })

  usersWithRole.forEach((user) => {
    const numAddresses = Math.floor(Math.random() * 3) + 1

    // Tạo địa chỉ cho từng user
    for (let i = 0; i < numAddresses; i++) {
      const now = new Date()

      // Nếu là SELLER (shop), tạo địa chỉ shop với thông tin đầy đủ và GHN ID
      if (user.role.name === 'SELLER') {
        addressesToCreate.push({
          name: `Địa chỉ shop ${i + 1}`,
          recipient: `Shop Owner`,
          phoneNumber: '+84901234567',
          province: 'Hồ Chí Minh',
          district: 'Quận 1',
          ward: 'Phường Bến Nghé',
          // GHN ID thực tế cho TP.HCM - Quận 1 - Phường Bến Nghé
          // Dựa trên dữ liệu từ GHN API mà bạn đã cung cấp
          provinceId: 202, // Hồ Chí Minh
          districtId: 1451, // Quận 1
          wardCode: '20109', // Phường Bến Nghé
          street: `${100 + i} Đường Nguyễn Huệ`,
          addressType: 'OFFICE',
          createdById: creatorUserId,
          userId: user.id,
          isDefault: i === 0, // Địa chỉ đầu tiên là default
          createdAt: now,
          updatedAt: now
        })
      } else {
        // Nếu là CLIENT, tạo địa chỉ nhà với GHN ID
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
          // GHN ID thực tế cho Hà Nội - Cầu Giấy - Dịch Vọng
          provinceId: 201, // Hà Nội
          districtId: 1490, // Cầu Giấy
          wardCode: '1008005', // Dịch Vọng
          street: `Đường ${i + 1}`,
          addressType: 'HOME',
          createdById: creatorUserId,
          userId: user.id,
          isDefault: i === 0,
          createdAt: now,
          updatedAt: now
        })
      }
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
