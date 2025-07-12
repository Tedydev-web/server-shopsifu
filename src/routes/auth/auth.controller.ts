import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common'

import { JwtRefreshGuard } from 'src/shared/request/guards/jwt.refresh.guard'

import { AuthService } from './auth.service'
import { LoginBodyType, RegisterBodyType } from './auth.model'
import { AuthUser } from 'src/shared/request/decorators/request.user.decorator'
import { IAuthUser } from 'src/shared/request/interfaces/request.interface'

@Controller({
	version: '1',
	path: '/auth'
})
export class AuthPublicController {
	constructor(private readonly authService: AuthService) {}

	@Post('login')
	public login(@Body() payload: LoginBodyType & { userAgent: string; ip: string }) {
		return this.authService.login(payload)
	}

	@Post('signup')
	public signup(@Body() payload: RegisterBodyType) {
		return this.authService.signup(payload)
	}

	@Get('refresh-token')
	@UseGuards(JwtRefreshGuard)
	public refreshTokens(@AuthUser() user: IAuthUser) {
		return this.authService.refreshTokens(user)
	}
}
