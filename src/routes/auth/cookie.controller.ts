import { Controller, Get, Res, Req } from '@nestjs/common'
import { Response, Request } from 'express'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { CookieService } from 'src/shared/services/cookie.service'
import { CSRFService } from 'src/shared/services/csrf.service'

@Controller('cookies')
export class CookieController {
  constructor(
    private readonly cookieService: CookieService,
    private readonly csrfService: CSRFService
  ) {}

  @Get('csrf-token')
  @IsPublic()
  getCSRFToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    // Generate CSRF token using csrf-csrf
    const csrfToken = this.csrfService.generateToken(req, res)

    return {
      message: 'CSRF token generated successfully'
    }
  }

  @Get('clear')
  @IsPublic()
  clearCookies(@Res({ passthrough: true }) res: Response) {
    this.cookieService.clearAuthCookies(res)
    return { message: 'Cookies cleared successfully' }
  }

  @Get('validate')
  @IsPublic()
  validateCSRFToken(@Req() req: Request) {
    const isValid = this.csrfService.validateToken(req)
    return {
      message: isValid ? 'CSRF token is valid' : 'CSRF token is invalid',
      isValid
    }
  }
}
