#!/usr/bin/env node

import { PrismaClient } from '@prisma/client'
import { logger, CONFIG } from './import-utils'

// GHN API Configuration
const GHN_CONFIG = {
  BASE_URL: process.env.GHN_BASE_URL || process.env.APP_URL || 'https://api.shopsifu.live',
  ENDPOINTS: {
    PROVINCES: '/shipping/ghn/address/provinces',
    DISTRICTS: '/shipping/ghn/address/districts',
    WARDS: '/shipping/ghn/address/wards'
  },
  TIMEOUT: 30000,
  RETRY: {
    MAX_ATTEMPTS: 3,
    DELAY: 1000
  }
}

function buildGHNUrl(endpoint: string): string {
  return `${GHN_CONFIG.BASE_URL}${endpoint}`
}

function getEnvironment(): string {
  if (process.env.NODE_ENV) return process.env.NODE_ENV
  if (process.env.APP_ENVIRONMENT) return process.env.APP_ENVIRONMENT

  if (GHN_CONFIG.BASE_URL.includes('localhost') || GHN_CONFIG.BASE_URL.includes('127.0.0.1')) {
    return 'local'
  }
  if (GHN_CONFIG.BASE_URL.includes('shopsifu.live')) {
    return 'production'
  }
  if (GHN_CONFIG.BASE_URL.includes('staging') || GHN_CONFIG.BASE_URL.includes('dev')) {
    return 'staging'
  }

  return 'unknown'
}

// GHN API Interfaces
interface GHNProvince {
  ProvinceID: number
  ProvinceName: string
}

interface GHNDistrict {
  DistrictID: number
  DistrictName: string
  ProvinceID: number
}

interface GHNWard {
  WardCode: string
  WardName: string
  DistrictID: number
}

interface GHNAddress {
  province: string
  district: string
  ward: string
  provinceId: number
  districtId: number
  wardCode: string
  street: string
}

// Main import function
async function importFullAddressesFromGHN(
  users: Array<{ id: string; role: { name: string } }>,
  creatorUserId: string,
  tx: PrismaClient
): Promise<{ addressCount: number; userAddressCount: number }> {
  try {
    logger.log('🌏 Bắt đầu import địa chỉ từ TẤT CẢ 64 tỉnh thành GHN API...')

    // 1. Lấy tất cả provinces từ GHN API
    logger.log('🔄 Đang lấy danh sách TẤT CẢ tỉnh/thành từ GHN API...')
    const provincesUrl = buildGHNUrl(GHN_CONFIG.ENDPOINTS.PROVINCES)
    logger.log(`🌐 Gọi API: ${provincesUrl}`)
    const provincesResponse = await fetch(provincesUrl)

    if (!provincesResponse.ok) {
      throw new Error(`Không thể lấy danh sách tỉnh/thành: ${provincesResponse.statusText}`)
    }

    const provincesData = await provincesResponse.json()
    const provinces: GHNProvince[] = provincesData.data || []
    logger.log(`📍 Tìm thấy ${provinces.length} tỉnh/thành`)

    // Lọc bỏ các tỉnh test/fake
    const realProvinces = provinces.filter(
      (p) =>
        !p.ProvinceName.toLowerCase().includes('test') &&
        !p.ProvinceName.toLowerCase().includes('alert') &&
        !p.ProvinceName.toLowerCase().includes('ngoc')
    )

    logger.log(`🎯 Lọc được ${realProvinces.length} tỉnh thành thực tế từ ${provinces.length} tỉnh ban đầu`)

    const allGhnAddresses: GHNAddress[] = []

    // 2. Lấy addresses từ TẤT CẢ provinces thực tế
    for (let i = 0; i < realProvinces.length; i++) {
      const province = realProvinces[i]
      logger.log(
        `🔄 [${i + 1}/${realProvinces.length}] Đang xử lý ${province.ProvinceName} (ID: ${province.ProvinceID})...`
      )

      try {
        // Lấy districts của province này
        const districtsUrl = buildGHNUrl(`${GHN_CONFIG.ENDPOINTS.DISTRICTS}?provinceId=${province.ProvinceID}`)
        const districtsResponse = await fetch(districtsUrl)

        if (!districtsResponse.ok) {
          logger.warn(`⚠️  Không thể lấy districts cho ${province.ProvinceName}`)
          continue
        }

        const districtsData = await districtsResponse.json()
        const districts: GHNDistrict[] = districtsData.data || []

        if (districts.length === 0) {
          logger.warn(`⚠️  ${province.ProvinceName} không có districts`)
          continue
        }

        logger.log(`  📍 ${province.ProvinceName}: ${districts.length} districts`)

        // Lấy một số districts đại diện (tối đa 10 districts/province)
        const selectedDistricts = districts.slice(0, Math.min(10, districts.length))

        for (const district of selectedDistricts) {
          try {
            // Lấy wards của district này
            const wardsUrl = buildGHNUrl(`${GHN_CONFIG.ENDPOINTS.WARDS}?districtId=${district.DistrictID}`)
            const wardsResponse = await fetch(wardsUrl)

            if (!wardsResponse.ok) {
              logger.warn(`⚠️  Không thể lấy wards cho ${district.DistrictName}`)
              continue
            }

            const wardsData = await wardsResponse.json()
            const wards: GHNWard[] = wardsData.data || []

            if (wards.length === 0) {
              logger.warn(`⚠️  ${district.DistrictName} không có wards`)
              continue
            }

            // Lấy một số wards đại diện (tối đa 5 wards/district)
            const selectedWards = wards.slice(0, Math.min(5, wards.length))

            for (const ward of selectedWards) {
              // Tạo nhiều địa chỉ street khác nhau cho mỗi ward
              const streetVariations = [
                `Đường ${Math.floor(Math.random() * 100) + 1}`,
                `Phố ${Math.floor(Math.random() * 50) + 1}`,
                `Ngõ ${Math.floor(Math.random() * 200) + 1}`,
                `Số ${Math.floor(Math.random() * 500) + 1}`,
                `Hẻm ${Math.floor(Math.random() * 100) + 1}`
              ]

              for (const street of streetVariations) {
                allGhnAddresses.push({
                  province: province.ProvinceName,
                  district: district.DistrictName,
                  ward: ward.WardName,
                  provinceId: province.ProvinceID,
                  districtId: district.DistrictID,
                  wardCode: ward.WardCode,
                  street: street
                })
              }
            }

            // Thêm delay nhỏ để tránh rate limit
            await new Promise((resolve) => setTimeout(resolve, 50))
          } catch (error) {
            logger.warn(`⚠️  Lỗi khi xử lý district ${district.DistrictName}: ${error.message}`)
          }
        }

        // Thêm delay giữa các provinces
        await new Promise((resolve) => setTimeout(resolve, 100))
      } catch (error) {
        logger.warn(`⚠️  Lỗi khi xử lý province ${province.ProvinceName}: ${error.message}`)
      }
    }

    logger.log(`🎯 Thu thập được ${allGhnAddresses.length} địa chỉ từ ${realProvinces.length} tỉnh thành thực tế`)

    if (allGhnAddresses.length === 0) {
      throw new Error('Không thu thập được địa chỉ nào từ GHN API')
    }

    // 3. Tạo addresses cho users
    const addressesToCreate: Array<{
      name: string
      recipient?: string
      phoneNumber: string
      province: string
      district: string
      ward: string
      provinceId: number
      districtId: number
      wardCode: string
      street: string
      addressType: 'HOME' | 'OFFICE'
      createdById: string
      userId: string
      isDefault: boolean
      createdAt: Date
      updatedAt: Date
    }> = []

    logger.log(`🔄 Đang tạo địa chỉ cho ${users.length} users...`)

    users.forEach((user, userIndex) => {
      // Mỗi user sẽ có 2-3 địa chỉ từ các tỉnh khác nhau
      const numAddresses = Math.floor(Math.random() * 2) + 2 // 2-3 địa chỉ

      for (let i = 0; i < numAddresses; i++) {
        const now = new Date()
        // Chọn ngẫu nhiên địa chỉ từ danh sách đã thu thập
        const addressData = allGhnAddresses[Math.floor(Math.random() * allGhnAddresses.length)]

        if (user.role.name === 'SELLER') {
          // Địa chỉ shop
          addressesToCreate.push({
            name: `Shop ${addressData.province} ${i + 1}`,
            recipient: `Shopsifu ${addressData.province}`,
            phoneNumber: '+84901234567',
            province: addressData.province,
            district: addressData.district,
            ward: addressData.ward,
            provinceId: addressData.provinceId,
            districtId: addressData.districtId,
            wardCode: addressData.wardCode,
            street: `${100 + i} ${addressData.street}`,
            addressType: 'OFFICE',
            createdById: creatorUserId,
            userId: user.id,
            isDefault: i === 0,
            createdAt: now,
            updatedAt: now
          })
        } else {
          // Địa chỉ nhà
          addressesToCreate.push({
            name: `Nhà ${addressData.province} ${i + 1}`,
            recipient: `Người nhận ${addressData.province} ${i + 1}`,
            phoneNumber:
              '0' +
              Math.floor(Math.random() * 1000000000)
                .toString()
                .padStart(9, '0'),
            province: addressData.province,
            district: addressData.district,
            ward: addressData.ward,
            provinceId: addressData.provinceId,
            districtId: addressData.districtId,
            wardCode: addressData.wardCode,
            street: `${i + 1} ${addressData.street}`,
            addressType: 'HOME',
            createdById: creatorUserId,
            userId: user.id,
            isDefault: i === 0,
            createdAt: now,
            updatedAt: now
          })
        }
      }

      // Log progress mỗi 500 users
      if ((userIndex + 1) % 500 === 0) {
        logger.log(`📊 Đã xử lý ${userIndex + 1}/${users.length} users`)
      }
    })

    logger.log(`📦 Tạo được ${addressesToCreate.length} addresses để import`)

    // 4. Tạo addresses trong database (batch processing)
    let addressCount = 0
    let userAddressCount = 0
    const copyBatchSize = CONFIG.COPY_BATCH_SIZE
    const copyChunks = Array.from({ length: Math.ceil(addressesToCreate.length / copyBatchSize) }, (_, i) =>
      addressesToCreate.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
    )

    logger.log(`🔄 Bắt đầu import ${copyChunks.length} batches vào database...`)

    for (let chunkIndex = 0; chunkIndex < copyChunks.length; chunkIndex++) {
      const chunk = copyChunks[chunkIndex]

      try {
        // Tạo addresses
        const addressData = chunk.map(({ userId, isDefault, ...data }) => data)
        await tx.address.createMany({ data: addressData })

        // Lấy addresses vừa tạo
        const createdAddressData = await tx.address.findMany({
          where: {
            name: { in: chunk.map((a) => a.name) },
            createdById: creatorUserId
          },
          select: { id: true, name: true }
        })

        // Tạo user-address relationships
        const userAddresses = chunk
          .map((address) => {
            const createdAddress = createdAddressData.find((a) => a.name === address.name)
            return createdAddress
              ? {
                  userId: address.userId,
                  addressId: createdAddress.id,
                  isDefault: address.isDefault,
                  createdAt: address.createdAt,
                  updatedAt: address.updatedAt
                }
              : null
          })
          .filter(
            (ua): ua is { userId: string; addressId: string; isDefault: boolean; createdAt: Date; updatedAt: Date } =>
              ua !== null
          )

        if (userAddresses.length) {
          await tx.userAddress.createMany({ data: userAddresses, skipDuplicates: true })
        }

        addressCount += chunk.length
        userAddressCount += userAddresses.length

        logger.log(`✅ Batch ${chunkIndex + 1}/${copyChunks.length}: ${chunk.length} addresses`)
      } catch (error) {
        logger.error(`❌ Lỗi batch ${chunkIndex + 1}: ${error.message}`)
        throw error
      }
    }

    logger.log(
      `✅ Imported ${addressCount} addresses và ${userAddressCount} user-address relationships từ ${realProvinces.length} tỉnh thành thực tế`
    )

    // 5. Thống kê theo tỉnh thành
    const provinceStats = await tx.address.groupBy({
      by: ['province'],
      _count: { province: true },
      where: { createdById: creatorUserId }
    })

    logger.log(`📊 Thống kê địa chỉ theo tỉnh thành:`)
    provinceStats.forEach((stat) => {
      logger.log(`  📍 ${stat.province}: ${stat._count.province} addresses`)
    })

    return { addressCount, userAddressCount }
  } catch (error) {
    logger.error(`❌ Lỗi khi import địa chỉ từ GHN API: ${error.message}`)
    throw error
  }
}

// Main execution function
async function main() {
  const prisma = new PrismaClient()

  try {
    logger.log('🌏 Bắt đầu xóa và import lại địa chỉ từ TẤT CẢ 64 tỉnh thành GHN API...')
    logger.log(`🔧 Environment: ${getEnvironment()}`)
    logger.log(`🌐 Base URL: ${GHN_CONFIG.BASE_URL}`)

    await prisma.$connect()

    // 1. Xóa tất cả user-address relationships
    logger.log('🧹 Bước 1: Xóa user-address relationships...')
    const deletedUserAddresses = await prisma.userAddress.deleteMany({})
    logger.log(`✅ Đã xóa ${deletedUserAddresses.count} user-address relationships`)

    // 2. Xóa tất cả addresses
    logger.log('🧹 Bước 2: Xóa tất cả addresses...')
    const deletedAddresses = await prisma.address.deleteMany({})
    logger.log(`✅ Đã xóa ${deletedAddresses.count} addresses`)

    // 3. Lấy danh sách users
    logger.log('🔄 Bước 3: Lấy danh sách users...')
    const users = await prisma.user.findMany({
      where: { deletedAt: null },
      select: {
        id: true,
        role: { select: { name: true } }
      }
    })
    logger.log(`📊 Tìm thấy ${users.length} users`)

    if (users.length === 0) {
      throw new Error('Không tìm thấy users nào để tạo địa chỉ')
    }

    // 4. Lấy creator user
    const creatorUser = await prisma.user.findFirst({
      where: {
        email: 'admin@shopsifu.com',
        deletedAt: null
      }
    })

    if (!creatorUser) {
      throw new Error('Không tìm thấy creator user (admin@shopsifu.com)')
    }

    logger.log(`👤 Creator: ${creatorUser.email} (${creatorUser.id})`)

    // 5. Import địa chỉ mới từ TẤT CẢ tỉnh thành
    logger.log('🚀 Bước 4: Import địa chỉ mới từ TẤT CẢ 64 tỉnh thành...')
    const result = await importFullAddressesFromGHN(users, creatorUser.id, prisma)

    logger.log(`🎉 Hoàn thành!`)
    logger.log(`📊 Kết quả:`)
    logger.log(`  - Addresses mới: ${result.addressCount}`)
    logger.log(`  - User-address relationships: ${result.userAddressCount}`)

    // 6. Kiểm tra và thống kê cuối cùng
    logger.log('🔍 Bước 5: Kiểm tra thống kê cuối cùng...')

    const totalAddresses = await prisma.address.count()
    const totalUserAddresses = await prisma.userAddress.count()
    const totalDefaultAddresses = await prisma.userAddress.count({
      where: { isDefault: true }
    })
    const totalUsers = await prisma.user.count({
      where: { deletedAt: null }
    })
    const totalProvinces = await prisma.address.groupBy({
      by: ['province'],
      _count: { province: true }
    })

    logger.log(`📈 Thống kê cuối cùng:`)
    logger.log(`  - Tổng users: ${totalUsers}`)
    logger.log(`  - Tổng addresses: ${totalAddresses}`)
    logger.log(`  - Tổng user-address relationships: ${totalUserAddresses}`)
    logger.log(`  - Tổng default addresses: ${totalDefaultAddresses}`)
    logger.log(`  - Tổng số tỉnh thành có địa chỉ: ${totalProvinces.length}`)

    // Hiển thị top 10 tỉnh có nhiều địa chỉ nhất
    const top10Provinces = totalProvinces.sort((a, b) => b._count.province - a._count.province).slice(0, 10)

    logger.log(`🏆 Top 10 tỉnh thành có nhiều địa chỉ nhất:`)
    top10Provinces.forEach((province, index) => {
      logger.log(`  ${index + 1}. ${province.province}: ${province._count.province} addresses`)
    })

    if (totalDefaultAddresses === totalUsers) {
      logger.log('✅ Tất cả users đều có địa chỉ default!')
    } else {
      logger.warn(`⚠️  Có ${totalUsers - totalDefaultAddresses} users chưa có địa chỉ default`)
    }

    logger.log('🎊 Import địa chỉ từ TẤT CẢ 64 tỉnh thành hoàn thành!')
  } catch (error) {
    logger.error(`❌ Lỗi: ${error.message}`)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

// Run if called directly
if (require.main === module) {
  main()
    .then(() => {
      logger.log('✅ Script hoàn thành thành công')
      process.exit(0)
    })
    .catch((error) => {
      logger.error(`❌ Script thất bại: ${error.message}`)
      process.exit(1)
    })
}

export { importFullAddressesFromGHN, main }
