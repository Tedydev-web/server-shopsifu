import { WinstonModule, utilities as nestWinstonModuleUtilities } from 'nest-winston'
import * as winston from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'
import appConfig from '../config'

const { errors, combine, json, timestamp, ms, prettyPrint, printf, colorize, splat } = winston.format

export const dailyRotateFileTransport = (level: string, dirname?: string) => {
  return new DailyRotateFile({
    level,
    dirname: dirname || `logs/${level}`,
    filename: `%DATE%-${level}.log`,
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '14d',
    format: combine(errors({ stack: true }), timestamp(), json(), prettyPrint())
  })
}

export const consoleTransport = () => {
  return new winston.transports.Console({
    level: appConfig().NODE_ENV === 'production' ? 'info' : 'silly',
    format:
      appConfig().NODE_ENV === 'production'
        ? combine(timestamp(), ms(), errors({ stack: true }), json())
        : combine(
            errors({ stack: true }),
            timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            ms(),
            nestWinstonModuleUtilities.format.nestLike('Shopsifu', {
              colors: true,
              prettyPrint: true
            })
          )
  })
}

export const winstonLogger = WinstonModule.createLogger({
  levels: winston.config.npm.levels,
  transports: [
    consoleTransport(),
    dailyRotateFileTransport('error'),
    dailyRotateFileTransport('info', 'logs/combined')
  ],
  exceptionHandlers: [
    new DailyRotateFile({
      dirname: 'logs/exceptions',
      filename: '%DATE%-exceptions.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: combine(errors({ stack: true }), timestamp(), json(), prettyPrint())
    })
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      dirname: 'logs/rejections',
      filename: '%DATE%-rejections.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: combine(errors({ stack: true }), timestamp(), json(), prettyPrint())
    })
  ],
  exitOnError: false
})

// Custom log format
const logFormat = printf(({ level, message, timestamp: ts, stack, ...metadata }) => {
  return `${ts} ${level}: ${message}`
})

export const WinstonConfig: winston.LoggerOptions = {
  level: appConfig().NODE_ENV === 'production' ? 'info' : 'silly',
  format: combine(
    errors({ stack: appConfig().NODE_ENV === 'production' ? false : true }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    splat(),
    logFormat
  ),
  transports: [
    consoleTransport(),
    dailyRotateFileTransport('error'),
    dailyRotateFileTransport('info', 'logs/combined')
  ],
  exceptionHandlers: [
    new DailyRotateFile({
      dirname: 'logs/exceptions',
      filename: '%DATE%-exceptions.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: combine(errors({ stack: true }), timestamp(), json(), prettyPrint())
    })
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      dirname: 'logs/rejections',
      filename: '%DATE%-rejections.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: combine(errors({ stack: true }), timestamp(), json(), prettyPrint())
    })
  ],
  exitOnError: false
}
