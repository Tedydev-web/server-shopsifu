import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import helmet from 'helmet'
import compression from 'compression'
import { Logger, VersioningType } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import express from 'express'
import { ExpressAdapter } from '@nestjs/platform-express'

async function bootstrap(): Promise<void> {
	const server = express()
	let app: any

	try {
		// Create app
		app = await NestFactory.create(AppModule, new ExpressAdapter(server), {
			bufferLogs: true
		})

		const logger = app.get(Logger)
		const config = app.get(ConfigService)
		const host = config.getOrThrow('app.http.host')
		const port = config.getOrThrow('app.http.port')

		// Middleware
		app.use(helmet())
		app.use(compression())
		app.useLogger(logger)
		app.enableCors(config.get('app.cors'))

		app.enableVersioning({
			type: VersioningType.URI,
			defaultVersion: '1'
		})
		// Cookie parser middleware
		app.use(cookieParser(config.getOrThrow('app.cookie.secret')))

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
