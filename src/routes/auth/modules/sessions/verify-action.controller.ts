import { Controller, Post, Body, Ip, HttpStatus, HttpCode, Logger, Query } from '@nestjs/common'
import { ActiveUser } from 'src/routes/auth/decorators/active-user.decorator'
import { UserAgent } from 'src/shared/decorators/user-agent.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { SessionsService } from './sessions.service'
import { z } from 'zod'
import { createZodDto } from 'nestjs-zod'

// Schema cho xác thực hành động
export const VerifyActionSchema = z.object({
  action: z.enum(['revoke-sessions', 'trust-device', 'untrust-device']),
  verificationToken: z.string().optional(),
  otpCode: z.string().optional(),
  sessionIds: z.array(z.string()).optional(),
  deviceIds: z.array(z.number()).optional(),
  revokeAll: z.boolean().default(false),
  excludeCurrentSession: z.boolean().default(true)
})

export class VerifyActionDto extends createZodDto(VerifyActionSchema) {}

@Controller('auth/sessions/verify-action')
export class VerifyActionController {
  private readonly logger = new Logger(VerifyActionController.name)

  constructor(private readonly sessionsService: SessionsService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  async verifyAction(
    @ActiveUser() activeUser: AccessTokenPayload,
    @Body() body: VerifyActionDto,
    @Query('action') actionQuery: string,
    @Ip() ip: string,
    @UserAgent() userAgent: string
  ) {
    const action = body.action || actionQuery

    this.logger.debug(`[verifyAction] Đang xác thực hành động ${action} cho user ${activeUser.userId}`)

    if (action === 'revoke-sessions') {
      // Chuyển các tham số từ body vào options
      const options = {
        sessionIds: body.sessionIds,
        deviceIds: body.deviceIds,
        revokeAllUserSessions: body.revokeAll,
        excludeCurrentSession: body.excludeCurrentSession
      }

      // Gọi service để thực hiện thu hồi với thông tin xác thực
      const result = await this.sessionsService.revokeItems(
        activeUser.userId,
        options,
        activeUser,
        body.verificationToken,
        body.otpCode,
        ip,
        userAgent
      )

      return {
        statusCode: HttpStatus.OK,
        message: result.message,
        data: {
          revokedSessionsCount: result.revokedSessionsCount,
          untrustedDevicesCount: result.untrustedDevicesCount,
          revokedSessionIds: result.revokedSessionIds || [],
          revokedDeviceIds: result.revokedDeviceIds || [],
          requiresAdditionalVerification: result.requiresAdditionalVerification || false,
          verificationRedirectUrl: result.verificationRedirectUrl
        }
      }
    }

    // Xử lý các hành động khác trong tương lai
    return {
      statusCode: HttpStatus.BAD_REQUEST,
      message: 'Hành động không hợp lệ hoặc chưa được hỗ trợ'
    }
  }
}
