import { WinstonModule, utilities as nestWinstonModuleUtilities } from 'nest-winston'
import * as winston from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'
import envConfig from '../config'

const { errors, combine, json, timestamp, ms, prettyPrint } = winston.format

const dailyRotateFileTransport = (level: string, dirname?: string) => {
  return new DailyRotateFile({
    level,
    dirname: dirname || `logs/${level}`,
    filename: `%DATE%-${level}.log`,
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '14d',
    format: combine(
      errors({ stack: true }),
      timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSSZ' }),
      winston.format((info) => {
        info.pid = process.pid
        return info
      })(),
      json(),
      prettyPrint()
    )
  })
}

export const winstonLogger = WinstonModule.createLogger({
  levels: winston.config.npm.levels,
  transports: [
    new winston.transports.Console({
      level: envConfig.NODE_ENV === 'production' ? 'info' : 'silly',
      format:
        envConfig.NODE_ENV === 'production'
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
    }),
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
