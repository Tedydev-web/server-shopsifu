import { Injectable } from '@nestjs/common'
import { InvalidPasswordException, NotFoundRecordException } from 'src/shared/error'
import {
  ChangePasswordBodyType,
  UpdateMeBodyType,
  CreateAddressBodyType,
  UpdateAddressBodyType,
  GetUserAddressesResType,
  GetUserAddressDetailResType,
} from './profile.model'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class ProfileService {
  constructor(
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly hashingService: HashingService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async getProfile(user: AccessTokenPayload) {
    const [userData, addresses] = await Promise.all([
      this.sharedUserRepository.findUniqueIncludeRolePermissions({
        id: user.userId
      }),
      this.sharedUserRepository.listAddressesByUserId(user.userId)
    ])

    if (!userData) {
      throw NotFoundRecordException
    }

    // Tính statistics trực tiếp từ userData.orders
    const totalOrders = userData.orders?.length ?? 0
    const totalSpent =
      userData.orders?.reduce((sum, order) => {
        const orderTotal =
          order.items?.reduce((itemSum, item) => itemSum + Number(item.skuPrice) * item.quantity, 0) ?? 0
        return sum + orderTotal
      }, 0) ?? 0
    const memberSince = userData.createdAt

    return {
      message: this.i18n.t('profile.success.GET_PROFILE'),
      data: {
        ...userData,
        addresses,
        statistics: {
          totalOrders,
          totalSpent,
          memberSince
        }
      }
    }
  }

  async updateProfile({ user, body }: { user: AccessTokenPayload; body: UpdateMeBodyType }) {
    try {
      const userData = await this.sharedUserRepository.update(
        { id: user.userId },
        {
          ...body,
          updatedById: user.userId
        }
      )
      return {
        message: this.i18n.t('profile.success.UPDATE_PROFILE'),
        data: userData
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async changePassword({
    user,
    body
  }: {
    user: AccessTokenPayload
    body: Omit<ChangePasswordBodyType, 'confirmNewPassword'>
  }) {
    try {
      const { password, newPassword } = body
      const userData = await this.sharedUserRepository.findUnique({
        id: user.userId
      })
      if (!userData) {
        throw NotFoundRecordException
      }
      const isPasswordMatch = await this.hashingService.compare(password, userData.password)
      if (!isPasswordMatch) {
        throw InvalidPasswordException
      }
      const hashedPassword = await this.hashingService.hash(newPassword)

      await this.sharedUserRepository.update(
        { id: user.userId },
        {
          password: hashedPassword,
          updatedById: user.userId
        }
      )
      return {
        message: this.i18n.t('profile.success.CHANGE_PASSWORD')
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async getAddresses(user: AccessTokenPayload): Promise<GetUserAddressesResType> {
    const addresses = await this.sharedUserRepository.listAddressesByUserId(user.userId)
    return {
      message: this.i18n.t('profile.success.GET_ADDRESSES'),
      data: addresses
    }
  }

  async getAddressById(addressId: string, user: AccessTokenPayload): Promise<GetUserAddressDetailResType> {
    const address = await this.sharedUserRepository.findAddressById(addressId, user.userId)
    if (!address) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('profile.success.GET_ADDRESS_DETAIL'),
      data: address
    }
  }

  async createAddress(data: CreateAddressBodyType, user: AccessTokenPayload): Promise<GetUserAddressDetailResType> {
    const address = await this.sharedUserRepository.createAddress(data, user.userId)
    return {
      message: this.i18n.t('profile.success.CREATE_ADDRESS'),
      data: address
    }
  }

  async updateAddress(
    addressId: string,
    data: UpdateAddressBodyType,
    user: AccessTokenPayload
  ): Promise<GetUserAddressDetailResType> {
    const address = await this.sharedUserRepository.updateAddress(addressId, data, user.userId)
    return {
      message: this.i18n.t('profile.success.UPDATE_ADDRESS'),
      data: address
    }
  }

  async deleteAddress(addressId: string, user: AccessTokenPayload) {
    await this.sharedUserRepository.deleteAddress(addressId, user.userId)
    return {
      message: this.i18n.t('profile.success.DELETE_ADDRESS')
    }
  }
}
