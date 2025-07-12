import { Injectable, NestMiddleware } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { CSRFService } from '../services/csrf.service'

@Injectable()
export class CSRFMiddleware implements NestMiddleware {
	constructor(private readonly csrfService: CSRFService) {}

	use(req: Request, res: Response, next: NextFunction) {
		// Skip CSRF protection for ignored methods
		if (this.csrfService.shouldIgnoreMethod(req.method)) {
			return next()
		}

		// Apply CSRF protection
		const protectionMiddleware = this.csrfService.getProtectionMiddleware()
		protectionMiddleware(req, res, next)
	}
}
