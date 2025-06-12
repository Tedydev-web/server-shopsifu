import { createZodDto } from 'nestjs-zod'
import {
  CompleteUserCreationSchema,
  CreateUserSchema,
  InitiateUserCreationSchema,
  UpdateUserSchema,
  UserResponseSchema
} from './user.schema'

export class CreateUserDto extends createZodDto(CreateUserSchema) {}

export class InitiateUserCreationDto extends createZodDto(InitiateUserCreationSchema) {}

export class CompleteUserCreationDto extends createZodDto(CompleteUserCreationSchema) {}

export class UpdateUserDto extends createZodDto(UpdateUserSchema) {}

export class UserDto extends createZodDto(UserResponseSchema) {
  constructor(partial: Partial<UserDto>) {
    super()
    Object.assign(this, partial)
  }

  static fromEntity(entity: any): UserDto {
    return new UserDto({
      id: entity.id,
      email: entity.email,
      status: entity.status,
      roleId: entity.roleId,
      isEmailVerified: entity.isEmailVerified || false,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      userProfile: entity.userProfile
        ? {
            firstName: entity.userProfile.firstName,
            lastName: entity.userProfile.lastName,
            username: entity.userProfile.username,
            phoneNumber: entity.userProfile.phoneNumber,
            bio: entity.userProfile.bio,
            avatar: entity.userProfile.avatar,
            countryCode: entity.userProfile.countryCode,
            isPhoneNumberVerified: entity.userProfile.isPhoneNumberVerified || false
          }
        : null
    })
  }
}
