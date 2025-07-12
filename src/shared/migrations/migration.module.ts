import { Module } from '@nestjs/common';
import { CommandModule } from 'nestjs-command';

import { SharedModule } from 'src/shared/shared.module';

import { EmailMigrationSeed } from './seed/email.seed';

@Module({
	imports: [SharedModule, CommandModule],
	providers: [EmailMigrationSeed],
	exports: [EmailMigrationSeed]
})
export class MigrationModule {}
