import { Injectable } from '@nestjs/common'
import { PermissionType } from 'src/shared/models/shared-permission.model'
import { RoleType } from 'src/shared/models/shared-role.model'
import { UserType, AddressType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  CreateAddressBodyType,
  UpdateAddressBodyType,
  GetUserAddressesResType,
  GetUserAddressDetailResType
} from 'src/routes/profile/profile.model'

type UserIncludeRolePermissionsType = UserType & { role: RoleType & { permissions: PermissionType[] } }

export type WhereUniqueUserType = { id: string } | { email: string }

@Injectable()
export class SharedUserRepository {
  constructor(private readonly prismaService: PrismaService) {}

  findUnique(where: WhereUniqueUserType): Promise<UserType | null> {
    return this.prismaService.user.findFirst({
      where: {
        ...where,
        deletedAt: null
      }
    })
  }

  findUniqueIncludeRolePermissions(
    where: WhereUniqueUserType
  ): Promise<(UserIncludeRolePermissionsType & { orders: any[] }) | null> {
    return this.prismaService.user.findFirst({
      where: {
        ...where,
        deletedAt: null
      },
      include: {
        role: {
          include: {
            permissions: {
              where: {
                deletedAt: null
              }
            }
          }
        },
        orders: {
          where: { deletedAt: null },
          include: { items: true }
        }
      }
    })
  }

  /**
   * Lấy orders của user với items để tính statistics
   */
  async getUserOrders(userId: string): Promise<any[]> {
    return this.prismaService.order.findMany({
      where: {
        userId,
        deletedAt: null
      },
      include: {
        items: true
      }
    })
  }

  update(where: { id: string }, data: Partial<UserType>): Promise<UserType | null> {
    return this.prismaService.user.update({
      where: {
        ...where,
        deletedAt: null
      },
      data
    })
  }

  // ==================== ADDRESS MANAGEMENT METHODS ====================

  async listAddressesByUserId(userId: string): Promise<GetUserAddressesResType['data']> {
    const userAddresses = await this.prismaService.userAddress.findMany({
      where: {
        userId,
        address: {
          deletedAt: null
        }
      },
      include: {
        address: true
      },
      orderBy: {
        isDefault: 'desc'
      }
    })

    return userAddresses.map((userAddress) => ({
      ...userAddress.address,
      recipient: userAddress.address.recipient || undefined,
      phoneNumber: userAddress.address.phoneNumber || undefined,
      isDefault: userAddress.isDefault
    }))
  }

  async findAddressById(addressId: string, userId: string): Promise<GetUserAddressDetailResType['data'] | null> {
    const userAddress = await this.prismaService.userAddress.findFirst({
      where: {
        addressId,
        userId,
        address: {
          deletedAt: null
        }
      },
      include: {
        address: true
      }
    })

    if (!userAddress) {
      return null
    }

    return {
      ...userAddress.address,
      recipient: userAddress.address.recipient || undefined,
      phoneNumber: userAddress.address.phoneNumber || undefined,
      isDefault: userAddress.isDefault
    }
  }

  async createAddress(data: CreateAddressBodyType, userId: string): Promise<GetUserAddressDetailResType['data']> {
    return this.prismaService.$transaction(async (tx) => {
      // Lấy thông tin user để làm default cho recipient và phoneNumber nếu không được truyền
      const user = await tx.user.findUnique({
        where: { id: userId },
        select: { name: true, phoneNumber: true }
      })

      if (!user) {
        throw new Error('User not found')
      }

      // Nếu không truyền recipient hoặc phoneNumber, lấy từ user profile
      const addressData: any = {
        name: data.name,
        addressType: data.addressType,
        createdById: userId,
        recipient: data.recipient || user.name,
        phoneNumber: data.phoneNumber || user.phoneNumber
      }
      if (data.province) addressData.province = data.province
      if (data.district) addressData.district = data.district
      if (data.ward) addressData.ward = data.ward
      if (data.street) addressData.street = data.street
      if (data.provinceId !== undefined) addressData.provinceId = data.provinceId
      if (data.districtId !== undefined) addressData.districtId = data.districtId
      if (data.wardCode !== undefined) addressData.wardCode = data.wardCode

      const address = await tx.address.create({
        data: addressData
      })

      // Xử lý isDefault - ưu tiên giá trị client truyền lên
      let isDefault = false
      if (data.isDefault === true) {
        // Nếu client truyền isDefault: true, unset các địa chỉ mặc định khác
        await tx.userAddress.updateMany({
          where: {
            userId,
            isDefault: true
          },
          data: {
            isDefault: false
          }
        })
        isDefault = true
      } else if (data.isDefault === false) {
        // Nếu client truyền isDefault: false, giữ nguyên
        isDefault = false
      } else if (data.addressType === 'HOME') {
        // Chỉ áp dụng logic cũ khi client không truyền isDefault
        await tx.userAddress.updateMany({
          where: {
            userId,
            isDefault: true
          },
          data: {
            isDefault: false
          }
        })
        isDefault = true
      }

      const userAddress = await tx.userAddress.create({
        data: {
          userId,
          addressId: address.id,
          isDefault
        },
        include: {
          address: true
        }
      })

      return {
        ...userAddress.address,
        recipient: userAddress.address.recipient || undefined,
        phoneNumber: userAddress.address.phoneNumber || undefined,
        isDefault: userAddress.isDefault
      }
    })
  }

  async updateAddress(
    addressId: string,
    data: UpdateAddressBodyType,
    userId: string
  ): Promise<GetUserAddressDetailResType['data']> {
    // Verify user owns this address
    const userAddress = await this.prismaService.userAddress.findFirst({
      where: {
        addressId,
        userId,
        address: {
          deletedAt: null
        }
      }
    })

    if (!userAddress) {
      throw new Error('Address not found or access denied')
    }

    // Xử lý isDefault khi cập nhật
    if (data.isDefault) {
      // Unset các địa chỉ mặc định khác
      await this.prismaService.userAddress.updateMany({
        where: {
          userId,
          isDefault: true,
          NOT: { addressId }
        },
        data: {
          isDefault: false
        }
      })
      // Đặt địa chỉ này là mặc định
      await this.prismaService.userAddress.update({
        where: {
          id: userAddress.id
        },
        data: {
          isDefault: true
        }
      })
    } else if (data.isDefault === false) {
      // Nếu truyền false thì bỏ mặc định địa chỉ này
      await this.prismaService.userAddress.update({
        where: {
          id: userAddress.id
        },
        data: {
          isDefault: false
        }
      })
    }

    // Loại bỏ field isDefault khỏi data trước khi update Address
    const { isDefault, ...addressData } = data

    const address = await this.prismaService.address.update({
      where: {
        id: addressId,
        deletedAt: null
      },
      data: {
        ...addressData,
        updatedById: userId
      }
    })

    // Lấy lại trạng thái isDefault mới nhất
    const updatedUserAddress = await this.prismaService.userAddress.findUnique({
      where: { id: userAddress.id },
      include: { address: true }
    })

    return {
      ...address,
      recipient: address.recipient || undefined,
      phoneNumber: address.phoneNumber || undefined,
      isDefault: updatedUserAddress?.isDefault ?? false
    }
  }

  async deleteAddress(addressId: string, userId: string): Promise<AddressType> {
    // Verify user owns this address
    const userAddress = await this.prismaService.userAddress.findFirst({
      where: {
        addressId,
        userId,
        address: {
          deletedAt: null
        }
      }
    })

    if (!userAddress) {
      throw new Error('Address not found or access denied')
    }

    return this.prismaService.$transaction(async (tx) => {
      // Soft delete the address
      const address = await tx.address.update({
        where: {
          id: addressId
        },
        data: {
          deletedAt: new Date(),
          deletedById: userId
        }
      })

      // Remove the user-address relationship
      await tx.userAddress.delete({
        where: {
          userId_addressId: {
            userId,
            addressId
          }
        }
      })

      return {
        ...address,
        recipient: address.recipient || undefined,
        phoneNumber: address.phoneNumber || undefined
      }
    })
  }
}
