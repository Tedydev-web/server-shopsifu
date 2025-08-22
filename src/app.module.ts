import { Module } from '@nestjs/common'
import { SharedModule } from 'src/shared/shared.module'
import { AuthModule } from 'src/routes/auth/auth.module'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core'
import CustomZodValidationPipe from 'src/shared/pipes/custom-zod-validation.pipe'
import { ZodSerializerInterceptor } from 'nestjs-zod'
import { HttpExceptionFilter } from 'src/shared/filters/http-exception.filter'
import { PermissionModule } from 'src/routes/permission/permission.module'
import { RoleModule } from 'src/routes/role/role.module'
import { ProfileModule } from 'src/routes/profile/profile.module'
import { UserModule } from 'src/routes/user/user.module'
import { MediaModule } from 'src/routes/media/media.module'
import { BrandModule } from 'src/routes/brand/brand.module'
import { BrandTranslationModule } from 'src/routes/brand/brand-translation/brand-translation.module'
import { CategoryModule } from 'src/routes/category/category.module'
import { CategoryTranslationModule } from 'src/routes/category/category-translation/category-translation.module'
import { ProductModule } from 'src/routes/product/product.module'
import { ProductTranslationModule } from 'src/routes/product/product-translation/product-translation.module'
import { CartModule } from 'src/routes/cart/cart.module'
import { OrderModule } from 'src/routes/order/order.module'
import { SepayModule } from 'src/routes/payment/sepay/sepay.module'
import { VNPayModule } from 'src/routes/payment/vnpay/vnpay.module'
import { WebsocketModule } from 'src/websockets/websocket.module'
import { ThrottlerBehindProxyGuard } from 'src/shared/guards/throttler-behind-proxy.guard'
import { ReviewModule } from 'src/routes/review/review.module'
import { RemoveRefreshTokenCronjob } from 'src/cronjobs/remove-refresh-token.cronjob'
import { TransformInterceptor } from 'src/shared/interceptor/transform.interceptor'
import { ExpireDiscountCronjob } from 'src/cronjobs/expire-discount.cronjob'
import { ScheduleModule } from '@nestjs/schedule'
import { LanguageModule } from 'src/routes/language/language.module'
import { DiscountModule } from './routes/discount/discount.module'
import { SearchModule } from './routes/search/search.module'
import { ShippingModule } from './routes/shipping/ghn/shipping-ghn.module'
import { HealthController } from 'src/health.controller'
import { TerminusModule } from '@nestjs/terminus'

@Module({
  imports: [
    ScheduleModule.forRoot(),
    TerminusModule,
    WebsocketModule,
    SharedModule,
    AuthModule,
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
    SepayModule,
    VNPayModule,
    ReviewModule,
    DiscountModule,
    LanguageModule,
    SearchModule,
    ShippingModule
  ],
  providers: [
    {
      provide: APP_PIPE,
      useClass: CustomZodValidationPipe
    },

    { provide: APP_INTERCEPTOR, useClass: TransformInterceptor },
    { provide: APP_INTERCEPTOR, useClass: ZodSerializerInterceptor },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerBehindProxyGuard
    },
    RemoveRefreshTokenCronjob,
    ExpireDiscountCronjob
  ],
  controllers: [HealthController]
})
export class AppModule {}
