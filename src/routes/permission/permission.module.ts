import { Module } from '@nestjs/common'
import { PermissionService } from './permission.service'
import { PermissionRepository } from './permission.repository'
// import { PermissionController } from './permission.controller'; // Uncomment if you have a controller

@Module({
  // controllers: [PermissionController], // Uncomment if you have a controller
  providers: [PermissionService, PermissionRepository],
  exports: [PermissionService, PermissionRepository] // Export services/repositories if other modules need them
})
export class PermissionModule {}
