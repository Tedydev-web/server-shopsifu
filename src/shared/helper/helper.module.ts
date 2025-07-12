import { Module } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'

// import { AwsModule } from '../aws/aws.module';

import { HelperEncryptionService } from './services/helper.encryption.service'
import { HelperPaginationService } from './services/helper.pagination.service'

@Module({
	// imports: [AwsModule],
	providers: [JwtService, HelperEncryptionService, HelperPaginationService],
	exports: [HelperEncryptionService, HelperPaginationService]
})
export class HelperModule {}
