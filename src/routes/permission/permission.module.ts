import { Module } from '@nestjs/common'
import { SharedModule } from 'src/shared/shared.module'
import { PermissionService } from './permission.service'
import { PermissionController } from './permission.controller'
import { PermissionRepo } from './permission.repo'

@Module({
  imports: [SharedModule],
  providers: [PermissionRepo, PermissionService],
  controllers: [PermissionController],
})
export class PermissionModule {}
