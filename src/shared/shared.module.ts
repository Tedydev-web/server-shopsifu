import { Global, Module } from '@nestjs/common'
import { PaymentAPIKeyGuard } from 'src/shared/guards/payment-api-key.guard'
import { APP_GUARD, APP_PIPE, APP_INTERCEPTOR, APP_FILTER } from '@nestjs/core'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { S3Service } from 'src/shared/services/s3.service'
import path from 'path'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { CacheModule } from '@nestjs/cache-manager'
import * as redisStore from 'cache-manager-ioredis'
import { AcceptLanguageResolver, I18nModule, QueryResolver } from 'nestjs-i18n'
import { BullModule } from '@nestjs/bullmq'
import { HttpExceptionFilter } from './filters/http-exception.filter'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import CustomZodValidationPipe from './pipes/custom-zod-validation.pipe'
import { JwtAccessGuard } from './guards/jwt.access.guard'
import { RolesGuard } from './guards/roles.guard'
import { ThrottlerGuard } from '@nestjs/throttler'
import configs from './configs'
import { DatabaseModule } from 'src/shared/database/database.module'

const sharedServices = [DatabaseModule, SharedUserRepository, TwoFactorService, SharedRoleRepository]

@Global()
@Module({
	imports: [
		// Configuration - Global
		ConfigModule.forRoot({
			load: configs,
			isGlobal: true,
			cache: true,
			envFilePath: ['.env'],
			expandVariables: true
		}),

		// Caching - Redis
		CacheModule.registerAsync({
			imports: [ConfigModule],
			useFactory: (configService: ConfigService) => ({
				isGlobal: true,
				store: redisStore,
				host: configService.get('redis.host'),
				port: configService.get('redis.port'),
				password: configService.get('redis.password'),
				tls: configService.get('redis.tls'),
				ttl: 5000
			}),
			inject: [ConfigService]
		}),

		// Queue Management - Bull/Redis
		BullModule.forRootAsync({
			imports: [ConfigModule],
			useFactory: (configService: ConfigService) => ({
				connection: {
					host: configService.get('redis.host'),
					port: Number(configService.get('redis.port')),
					password: configService.get('redis.password'),
					tls: configService.get('redis.tls')
				}
			}),
			inject: [ConfigService]
		}),

		I18nModule.forRoot({
			fallbackLanguage: 'en',
			loaderOptions: {
				path: path.resolve('src/shared/languages/'),
				watch: true
			},
			resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
			typesOutputPath: path.resolve('src/shared/languages/generated/i18n.generated.ts')
		})
	],

	providers: [
		...sharedServices,
		PaymentAPIKeyGuard,
		{
			provide: APP_GUARD,
			useClass: ThrottlerGuard
		},
		{
			provide: APP_GUARD,
			useClass: JwtAccessGuard
		},
		{
			provide: APP_GUARD,
			useClass: RolesGuard
		},
		{
			provide: APP_PIPE,
			useClass: CustomZodValidationPipe
		},
		{ provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
		{
			provide: APP_FILTER,
			useClass: HttpExceptionFilter
		}
	],
	exports: sharedServices
})
export class SharedModule {}
