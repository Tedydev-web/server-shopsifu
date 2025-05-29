import { Module } from '@nestjs/common'
import { ProfileController } from './profile.controller'
import { ProfileService } from './profile.service'
import { ProfileRepository } from './profile.repo'
import { AuditLogModule } from 'src/routes/audit-log/audit-log.module'
// Import các module cần thiết khác, ví dụ AuthModule, SharedModule nếu cần
// import { AuthModule } from '../auth/auth.module';
// import { SharedModule } from 'src/shared/shared.module';

@Module({
  imports: [AuditLogModule],
  // imports: [AuthModule, SharedModule], // Bỏ comment nếu cần
  controllers: [ProfileController],
  providers: [ProfileService, ProfileRepository],
  exports: [ProfileService, ProfileRepository] // Export nếu các module khác cần dùng
})
export class ProfileModule {}
