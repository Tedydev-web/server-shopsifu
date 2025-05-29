import { Controller, Get, Patch, Body, UseGuards, Ip, Logger, UseInterceptors, Post } from '@nestjs/common'
import { ProfileService } from './profile.service'
import {
  UserProfileResponseDTO,
  UpdateProfileBodyDTO,
  RequestEmailChangeBodyDTO,
  VerifyNewEmailBodyDTO
} from './profile.dto'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import {
  PasswordReverificationGuard,
  AllowWithoutPasswordReverification
} from '../auth/guards/password-reverification.guard'
import { UseZodSchemas, createSchemaOption, hasProperty } from 'src/shared/decorators/use-zod-schema.decorator'
import { DynamicZodSerializerInterceptor } from 'src/shared/interceptor/dynamic-zod-serializer.interceptor'
import { UserProfileResponseSchema } from './profile.model'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { MessageResSchema } from 'src/shared/models/response.model'

@UseGuards(AuthenticationGuard, PasswordReverificationGuard) // Apply to all routes in this controller
@Controller('profile')
@UseInterceptors(
  new DynamicZodSerializerInterceptor([createSchemaOption(UserProfileResponseSchema, hasProperty('id'))])
)
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name)

  constructor(private readonly profileService: ProfileService) {}

  @Get('me')
  @AllowWithoutPasswordReverification() // Reading profile doesn't require password reverification
  async getCurrentUserProfile(@ActiveUser('userId') userId: number): Promise<UserProfileResponseDTO> {
    this.logger.debug(`Received request to get current user profile for user ID: ${userId}`)
    const result = await this.profileService.getCurrentUserProfile(userId)
    // DynamicZodSerializerInterceptor sẽ handle việc cast sang DTO
    return result as unknown as UserProfileResponseDTO
  }

  @Patch('me')
  // Updating profile might require password reverification depending on global setup
  // If specific fields require it, it should be handled in the service or a specific guard.
  async updateCurrentUserProfile(
    @ActiveUser('userId') userId: number,
    @Body() body: UpdateProfileBodyDTO,
    @Ip() ipAddress: string,
    @UserAgent() userAgent: string
  ): Promise<UserProfileResponseDTO> {
    this.logger.debug(`Received request to update profile for user ID: ${userId}`)
    const result = await this.profileService.updateCurrentUserProfile(userId, body, ipAddress, userAgent)
    return result as unknown as UserProfileResponseDTO
  }

  @Post('me/request-email-change')
  @UseZodSchemas(createSchemaOption(MessageResSchema, hasProperty('message')))
  async requestEmailChange(
    @ActiveUser('userId') userId: number,
    @Body() body: RequestEmailChangeBodyDTO,
    @Ip() ipAddress: string,
    @UserAgent() userAgent: string
  ): Promise<MessageResDTO> {
    this.logger.debug(`User ID ${userId} requesting email change to ${body.email}`)
    const result = await this.profileService.requestEmailChange(userId, body.email, ipAddress, userAgent)
    return result as unknown as MessageResDTO
  }

  @Post('me/verify-new-email')
  // UserProfileResponseSchema is already handled by the class-level interceptor
  async verifyNewEmail(
    @ActiveUser('userId') userId: number,
    @Body() body: VerifyNewEmailBodyDTO,
    @Ip() ipAddress: string,
    @UserAgent() userAgent: string
  ): Promise<UserProfileResponseDTO> {
    this.logger.debug(`User ID ${userId} attempting to verify new email.`)
    const result = await this.profileService.verifyNewEmail(userId, body.token, body.otp, ipAddress, userAgent)
    return result as unknown as UserProfileResponseDTO
  }
}
