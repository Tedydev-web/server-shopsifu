import { Module } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { GoogleService } from 'src/routes/auth/google.service'

@Module({
  providers: [AuthService, AuthRepository, GoogleService],
  controllers: [AuthController],
})
export class AuthModule {}
