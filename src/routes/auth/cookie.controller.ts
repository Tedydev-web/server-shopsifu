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
    // Generate CSRF secret and token using csrf-csrf
    const csrfToken = this.csrfService.generateToken(req, res)

    // Set the CSRF token in a separate, non-httpOnly cookie for the client
    this.cookieService.setCSRFTokenCookie(res, csrfToken)

    return {
      message: 'CSRF token generated successfully',
      csrfToken
    }
  }
}
