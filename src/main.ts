import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import envConfig from 'src/shared/config'
import { COOKIE_DEFINITIONS } from './shared/constants/cookie.constant'
import helmet from 'helmet'
import compression from 'compression'
import { Logger, VersioningType } from '@nestjs/common'
import express from 'express'
import { ExpressAdapter } from '@nestjs/platform-express'
import configs from './shared/configs'

async function bootstrap(): Promise<void> {
	const server = express()
	let app: any

	try {
		// Create app
		app = await NestFactory.create(AppModule, new ExpressAdapter(server), {
			bufferLogs: true
		})

		const logger = app.get(Logger)
		const host = ('app.http.host')
		const port = ('app.http.port')

		// Middleware
		app.use(helmet())
		app.use(compression())
		app.useLogger(logger)
		app.enableCors({
			origin: envConfig.APP_CORS_ORIGINS.split(','),
			credentials: true
		})

		app.enableVersioning({
			type: VersioningType.URI,
			defaultVersion: '1'
		})
		// Cookie parser middleware
		app.use(cookieParser(envConfig.COOKIE_SECRET))

		// Session middleware
		app.use(
			session({
				name: COOKIE_DEFINITIONS.session.name,
				secret: envConfig.COOKIE_SECRET,
				resave: false,
				saveUninitialized: false,
				cookie: COOKIE_DEFINITIONS.session.options
			})
		)
		// Graceful shutdown
		const gracefulShutdown = async (signal: string) => {
			logger.log(`Received ${signal}, shutting down gracefully...`)
			await app.close()
			process.exit(0)
		}

		process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
		process.on('SIGINT', () => gracefulShutdown('SIGINT'))

		// Start server
		await app.listen(port, host)

		const appUrl = await app.getUrl()
		logger.log(`🚀 Server running on: ${appUrl}`)
	} catch (error) {
		console.error('❌ Server failed to start:', error)
		if (app) await app.close()
		process.exit(1)
	}
}

bootstrap()
