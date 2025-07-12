import { Global, Module } from '@nestjs/common'
import { PaymentAPIKeyGuard } from 'src/shared/guards/payment-api-key.guard'
import { APP_GUARD, APP_PIPE, APP_INTERCEPTOR, APP_FILTER } from '@nestjs/core'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { CacheModule } from '@nestjs/cache-manager'
import * as redisStore from 'cache-manager-ioredis'
import { BullModule } from '@nestjs/bullmq'
import { HttpExceptionFilter } from './filters/http-exception.filter'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import CustomZodValidationPipe from './pipes/custom-zod-validation.pipe'
import { JwtAccessGuard } from './guards/jwt.access.guard'
import { RolesGuard } from './guards/roles.guard'
import configs from './config'
import { DatabaseModule } from 'src/shared/database/database.module'
import { RequestModule } from './request/request.module'
import { ResponseModule } from './response/response.module'
import { SharedUserRepository } from './repositories/shared-user.repo'
import { SharedRoleRepository } from './repositories/shared-role.repo'
import { HelperEncryptionService } from './helper/services/helper.encryption.service'
import { JwtModule } from '@nestjs/jwt'
import { CustomLoggerModule } from './logger/logger.module'

@Global()
@Module({
	imports: [
		DatabaseModule,
		RequestModule,
		ResponseModule,
		CustomLoggerModule,

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

		// JWT Module
		JwtModule.registerAsync({
			imports: [ConfigModule],
			useFactory: (configService: ConfigService) => ({
				secret: configService.get('jwt.secret'),
				signOptions: {
					expiresIn: configService.get('jwt.accessTokenExpiresIn')
				}
			}),
			inject: [ConfigService]
		})
	],

	providers: [
		PaymentAPIKeyGuard,
		SharedUserRepository,
		SharedRoleRepository,
		HelperEncryptionService,
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
	exports: [DatabaseModule, SharedUserRepository, SharedRoleRepository]
})
export class SharedModule {}
