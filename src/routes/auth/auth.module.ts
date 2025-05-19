import { Module } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { RolesService } from 'src/routes/auth/roles.service'
import { GoogleService } from 'src/routes/auth/google.service'

@Module({
  providers: [AuthService, RolesService, GoogleService],
  controllers: [AuthController]
})
export class AuthModule {}
