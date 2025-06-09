import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger, Inject } from '@nestjs/common'
import { UserAuthRepository } from 'src/shared/repositories/auth'
import { HashingService } from 'src/shared/services/hashing.service'
import { HASHING_SERVICE } from 'src/shared/constants/injection.tokens'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth/auth.constants'

@Injectable()
export class BasicAuthGuard implements CanActivate {
  private readonly logger = new Logger(BasicAuthGuard.name)

  constructor(
    private readonly userAuthRepository: UserAuthRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    try {
      const authHeader = request.headers.authorization

      if (!authHeader || !authHeader.startsWith('Basic ')) {
        throw new UnauthorizedException('Basic authentication required')
      }

      const base64Credentials = authHeader.split(' ')[1]
      const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8')
      const [email, password] = credentials.split(':')

      if (!email || !password) {
        throw new UnauthorizedException('Invalid credentials format')
      }

      // Tìm user theo email
      const user = await this.userAuthRepository.findByEmail(email)

      if (!user) {
        throw new UnauthorizedException('Invalid credentials')
      }

      // Kiểm tra mật khẩu
      const isPasswordValid = await this.hashingService.compare(password, user.password)

      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid credentials')
      }

      // Thiết lập thông tin user vào request
      request[REQUEST_USER_KEY] = {
        userId: user.id,
        email: user.email,
        roleId: user.roleId,
        roleName: user.role?.name
      }

      return true
    } catch (error) {
      this.logger.error(`Basic authentication failed: ${error.message}`)
      if (error instanceof UnauthorizedException) {
        throw error // Re-throw the original, more specific UnauthorizedException
      }
      // For other types of errors, wrap them in a generic UnauthorizedException
      throw new UnauthorizedException('Authentication failed')
    }
  }
}
