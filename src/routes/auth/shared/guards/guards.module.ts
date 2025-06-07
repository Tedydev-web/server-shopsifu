import { Module, forwardRef } from '@nestjs/common'
import { RolesGuard } from './auth/roles.guard'
import { BasicAuthGuard } from './auth/basic-auth.guard'
import { JwtAuthGuard } from './auth/jwt-auth.guard'
import { RedisProviderModule } from 'src/providers/redis/redis.module'
import { AuthenticationGuard } from './authentication.guard'
import { AuthSharedModule } from '../auth-shared.module'
import { ApiKeyGuard } from './auth/api-key.guard'
import { SessionsModule } from '../../modules/sessions/session.module'

/**
 * Module tập trung quản lý tất cả các guard trong ứng dụng
 */
@Module({
  imports: [RedisProviderModule, forwardRef(() => AuthSharedModule), forwardRef(() => SessionsModule)],
  providers: [AuthenticationGuard, JwtAuthGuard, RolesGuard, BasicAuthGuard, ApiKeyGuard],
  exports: [AuthenticationGuard, JwtAuthGuard, RolesGuard, BasicAuthGuard, ApiKeyGuard]
})
export class GuardsModule {}
