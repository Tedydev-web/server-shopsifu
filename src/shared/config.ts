import z from 'zod'
import fs from 'fs'
import path from 'path'
import { config } from 'dotenv'

config({
	path: '.env'
})
// Kiểm tra coi thử có file .env hay chưa
if (!fs.existsSync(path.resolve('.env'))) {
	console.log('Không tìm thấy file .env')
	process.exit(1)
}

const configSchema = z.object({
	// Application Settings
	NODE_ENV: z.string(),
	APP_NAME: z.string(),
	APP_DEBUG: z.string(),
	APP_LOG_LEVEL: z.string(),
	APP_CORS_ORIGINS: z.string(),

	// HTTP Server Configuration
	HTTP_HOST: z.string(),
	HTTP_PORT: z.string(),
	HTTP_VERSIONING_ENABLE: z.string(),
	HTTP_VERSION: z.string(),

	// Error Tracking - Sentry
	SENTRY_DSN: z.string(),

	// Authentication & JWT
	ACCESS_TOKEN_SECRET: z.string(),
	REFRESH_TOKEN_SECRET: z.string(),
	ACCESS_TOKEN_EXPIRES_IN: z.string(),
	REFRESH_TOKEN_EXPIRES_IN: z.string(),

	// Database Configuration
	DATABASE_URL: z.string(),

	// OTP Configuration
	OTP_EXPIRES_IN: z.string(),

	// Cookie Configuration
	COOKIE_SECRET: z.string(),

	// Google Auth Configuration
	GOOGLE_CLIENT_ID: z.string(),
	GOOGLE_CLIENT_SECRET: z.string(),
	GOOGLE_CLIENT_REDIRECT_URI: z.string(),
	GOOGLE_REDIRECT_URI: z.string(),

	// Admin Configuration
	ADMIN_NAME: z.string(),
	ADMIN_PASSWORD: z.string(),
	ADMIN_EMAIL: z.string(),
	ADMIN_PHONE_NUMBER: z.string(),

	// Resend API Key Configuration
	RESEND_API_KEY: z.string(),

	// AWS S3 Configuration
	S3_REGION: z.string(),
	S3_ACCESS_KEY: z.string(),
	S3_SECRET_KEY: z.string(),
	S3_BUCKET_NAME: z.string(),
	AWS_PRESIGN_LINK_EXPIRES: z.string(),

	// Prefix Static Endpoint Configuration
	PREFIX_STATIC_ENPOINT: z.string(),

	// Redis Configuration
	REDIS_HOST: z.string(),
	REDIS_PORT: z.string().transform(Number),
	REDIS_PASSWORD: z.string(),
	REDIS_ENABLE_TLS: z.string(),

	// Payment API Key Configuration
	PAYMENT_API_KEY: z.string()
})

const configServer = configSchema.safeParse(process.env)

if (!configServer.success) {
	console.log('Các giá trị khai báo trong file .env không hợp lệ')
	console.error(configServer.error)
	process.exit(1)
}

const envConfig = configServer.data

export default envConfig
