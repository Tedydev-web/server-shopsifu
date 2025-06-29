import { Module } from '@nestjs/common'
import { SharedModule } from 'src/shared/shared.module'
import { RoleController } from 'src/routes/role/role.controller'
import { RoleRepo } from 'src/routes/role/role.repo'
import { RoleService } from 'src/routes/role/role.service'

@Module({
  imports: [SharedModule],
  providers: [RoleService, RoleRepo],
  controllers: [RoleController],
  exports: [RoleService, RoleRepo],
})
export class RoleModule {}
