import { Module } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { GoogleService } from 'src/routes/auth/google.service'
import { APP_BULL_QUEUES } from 'src/shared/enums/app.enum'
import { BullModule } from '@nestjs/bullmq'
import { JwtAccessStrategy } from './providers/access-jwt.strategy'
import { JwtRefreshStrategy } from './providers/refresh-jwt.strategy'
import { HelperModule } from 'src/shared/helper/helper.module'
import { PassportModule } from '@nestjs/passport'

@Module({
	imports: [
		HelperModule,
		PassportModule,
		BullModule.registerQueue({
			name: APP_BULL_QUEUES.EMAIL
		})
	],
	providers: [AuthService, AuthRepository, GoogleService, JwtAccessStrategy, JwtRefreshStrategy],
	exports: [JwtAccessStrategy, JwtRefreshStrategy],
	controllers: [AuthController]
})
export class AuthModule {}
