import { Module } from '@nestjs/common'
import { MulterModule } from '@nestjs/platform-express'
import multer from 'multer'
import path from 'path'
import { MediaController } from 'src/routes/media/media.controller'
import { generateRandomFilename } from 'src/shared/helpers'
import * as fs from 'fs'
import { MediaService } from './media.service'

const UPLOAD_DIR = path.resolve('upload')
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR)
  },
  filename: function (req, file, cb) {
    const newFilename = generateRandomFilename(file.originalname)
    cb(null, newFilename)
  },
})

const uploadDir = path.join(__dirname, '..', '..', '..', '..', 'upload')
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir)
}

@Module({
  imports: [
    MulterModule.register({
      storage,
    }),
  ],
  controllers: [MediaController],
  providers: [MediaService],
})
export class MediaModule {}
