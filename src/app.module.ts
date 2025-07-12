import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from 'src/routes/auth/auth.module'
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { HttpExceptionFilter } from 'src/shared/filters/http-exception.filter'
import { LanguageModule } from 'src/routes/language/language.module'
import { PermissionModule } from 'src/routes/permission/permission.module'
import { RoleModule } from 'src/routes/role/role.module'
import { ProfileModule } from 'src/routes/profile/profile.module'
import { UserModule } from 'src/routes/user/user.module'
import { MediaModule } from 'src/routes/media/media.module'
import { BrandModule } from 'src/routes/brand/brand.module'
import { BrandTranslationModule } from 'src/routes/brand/brand-translation/brand-translation.module'
import { AcceptLanguageResolver, HeaderResolver, I18nModule, QueryResolver } from 'nestjs-i18n'
import { CategoryModule } from 'src/routes/category/category.module'
import { CategoryTranslationModule } from 'src/routes/category/category-translation/category-translation.module'
import { ProductModule } from 'src/routes/product/product.module'
import { ProductTranslationModule } from 'src/routes/product/product-translation/product-translation.module'
import { CartModule } from 'src/routes/cart/cart.module'
import { OrderModule } from 'src/routes/order/order.module'
import { PaymentModule } from 'src/routes/payment/payment.module'
import { CSRFMiddleware } from 'src/shared/middleware/csrf.middleware'
import { BullModule } from '@nestjs/bullmq'
import envConfig from './shared/config'
import path from 'path'
import { ConfigModule } from '@nestjs/config'
import configs from 'src/shared/configs'

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

		BullModule.forRoot({
			connection: {
				host: envConfig.REDIS_HOST,
				port: envConfig.REDIS_PORT,
				password: envConfig.REDIS_PASSWORD,
				tls: envConfig.REDIS_ENABLE_TLS === 'true' ? {} : null
			}
		}),

		I18nModule.forRoot({
			fallbackLanguage: 'en',
			loaderOptions: {
				path: path.resolve('src/shared/languages/'),
				watch: true
			},
			resolvers: [{ use: QueryResolver, options: ['lang'] }, AcceptLanguageResolver],
			typesOutputPath: path.resolve('src/shared/languages/generated/i18n.generated.ts')
		}),
		SharedModule,
		AuthModule,
		LanguageModule,
		PermissionModule,
		RoleModule,
		ProfileModule,
		UserModule,
		MediaModule,
		BrandModule,
		BrandTranslationModule,
		CategoryModule,
		CategoryTranslationModule,
		ProductModule,
		ProductTranslationModule,
		CartModule,
		OrderModule,
		PaymentModule
	],
	providers: [
		{
			provide: APP_PIPE,
			useClass: CustomZodValidationPipe
		},
		{ provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
		{
			provide: APP_FILTER,
			useClass: HttpExceptionFilter
		}
	]
})
export class AppModule {
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(CSRFMiddleware).forRoutes({ path: '*', method: RequestMethod.ALL })
	}
}
