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

@UseGuards(AuthenticationGuard, PasswordReverificationGuard)
@Controller('profile')
@UseInterceptors(
  new DynamicZodSerializerInterceptor([createSchemaOption(UserProfileResponseSchema, hasProperty('id'))])
)
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name)

  constructor(private readonly profileService: ProfileService) {}

  @Get('me')
  @AllowWithoutPasswordReverification()
  async getCurrentUserProfile(@ActiveUser('userId') userId: number): Promise<UserProfileResponseDTO> {
    const result = await this.profileService.getCurrentUserProfile(userId)

    return result as unknown as UserProfileResponseDTO
  }

  @Patch('me')
  async updateCurrentUserProfile(
    @ActiveUser('userId') userId: number,
    @Body() body: UpdateProfileBodyDTO,
    @Ip() ipAddress: string,
    @UserAgent() userAgent: string
  ): Promise<UserProfileResponseDTO> {
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
    const result = await this.profileService.requestEmailChange(userId, body.email, ipAddress, userAgent)
    return result as unknown as MessageResDTO
  }

  @Post('me/verify-new-email')
  async verifyNewEmail(
    @ActiveUser('userId') userId: number,
    @Body() body: VerifyNewEmailBodyDTO,
    @Ip() ipAddress: string,
    @UserAgent() userAgent: string
  ): Promise<UserProfileResponseDTO> {
    const result = await this.profileService.verifyNewEmail(userId, body.token, body.otp, ipAddress, userAgent)
    return result as unknown as UserProfileResponseDTO
  }
}
