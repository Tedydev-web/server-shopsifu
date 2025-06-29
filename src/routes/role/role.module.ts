import { Module } from '@nestjs/common'
import { RoleController } from 'src/routes/role/role.controller'
import { RoleRepo } from 'src/routes/role/role.repo'
import { RoleService } from 'src/routes/role/role.service'

@Module({
  providers: [RoleService, RoleRepo],
  controllers: [RoleController],
  exports: [RoleService],
})
export class RoleModule {}
