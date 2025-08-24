import { PrismaClient } from '@prisma/client'
import { ShopeeProduct, CONFIG, logger } from './import-utils'
import { HashingService } from '../../../src/shared/services/hashing.service'

const hashingService = new HashingService()

export async function importUsers(
  entities: Map<string, ShopeeProduct | string>,
  roleName: 'SELLER' | 'CLIENT',
  creatorUserId: string,
  tx: PrismaClient
): Promise<Map<string, string>> {
  const role = await tx.role.findFirst({ where: { name: roleName } })
  if (!role) throw new Error(`${roleName} role not found`)
  const existingUsers = await tx.user.findMany({
    where: { role: { name: roleName }, deletedAt: null },
    select: { id: true, email: true }
  })
  const userMap = new Map<string, string>()
  const existingEmails = new Map(
    existingUsers.map((u) => [u.email.split('.')[0].replace(roleName.toLowerCase(), ''), u.id])
  )
  const usersToCreate: Array<{
    email: string
    name: string
    password: string
    phoneNumber: string
    avatar: string
    status: 'ACTIVE'
    roleId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
    key: string
  }> = []
  const userDataPromises: Promise<{
    email: string
    name: string
    password: string
    phoneNumber: string
    avatar: string
    status: 'ACTIVE'
    roleId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
    key: string
  }>[] = []
  let index = 1
  for (const [key, data] of entities) {
    const email = `${roleName.toLowerCase()}${index}.shopsifu.ecommerce@gmail.com`
    if (existingEmails.has(key)) {
      userMap.set(key, existingEmails.get(key)!)
      index++
      continue
    }
    const name = typeof data === 'string' ? data : data.seller_name
    userDataPromises.push(
      hashingService
        .hash(`${roleName.charAt(0).toUpperCase() + roleName.slice(1).toLowerCase()}25`)
        .then((hashedPassword) => ({
          email,
          name,
          password: hashedPassword,
          phoneNumber:
            '+84' +
            Math.floor(Math.random() * 1000000000)
              .toString()
              .padStart(9, '0'),
          avatar: CONFIG.DEFAULT_AVATAR,
          status: 'ACTIVE' as const,
          roleId: role.id,
          createdById: creatorUserId,
          createdAt: new Date(),
          updatedAt: new Date(),
          key
        }))
    )
    index++
  }
  const userDataResults = await Promise.all(userDataPromises)
  usersToCreate.push(...userDataResults)
  const copyBatchSize = CONFIG.COPY_BATCH_SIZE * 2
  const copyChunks = Array.from({ length: Math.ceil(usersToCreate.length / copyBatchSize) }, (_, i) =>
    usersToCreate.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )
  for (let i = 0; i < copyChunks.length; i++) {
    const chunk = copyChunks[i]
    const userData = chunk.map(({ key, ...data }) => data)
    await tx.user.createMany({ data: userData, skipDuplicates: true })
    const createdUsers = await tx.user.findMany({
      where: {
        email: { in: userData.map((u) => u.email) },
        role: { name: roleName },
        deletedAt: null
      },
      select: { id: true, email: true }
    })
    chunk.forEach((userWithKey) => {
      const createdUser = createdUsers.find((u) => u.email === userWithKey.email)
      if (createdUser) {
        userMap.set(userWithKey.key, createdUser.id)
      }
    })
  }
  logger.log(`✅ Imported ${userMap.size} users for role ${roleName}`)
  return userMap
}
