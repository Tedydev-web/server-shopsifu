import { Injectable } from '@nestjs/common'
import { S3Service } from 'src/shared/services/s3.service'
import { unlink } from 'fs/promises'
import { generateRandomFilename } from 'src/shared/helpers'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class MediaService {
  constructor(
    private readonly s3Service: S3Service,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async uploadFile(files: Array<Express.Multer.File>) {
    const result = await Promise.all(
      files.map((file) => {
        return this.s3Service
          .uploadedFile({
            filename: 'images/' + file.filename,
            filepath: file.path,
            contentType: file.mimetype
          })
          .then((res) => {
            return { url: res.Location }
          })
      })
    )
    // Xóa file sau khi upload lên S3
    await Promise.all(
      files.map((file) => {
        return unlink(file.path)
      })
    )
    return {
      message: this.i18n.t('media.media.success.UPLOAD_SUCCESS'),
      data: result
    }
  }

  async getBatchPresignUrls(files: Array<{ filename: string; filesize: number }>) {
    const presignedUrls = await Promise.all(
      files.map(async (file) => {
        const randomFilename = generateRandomFilename(file.filename)
        const presignedUrl = await this.s3Service.createPresignedUrlWithClient(randomFilename)

        return {
          originalFilename: file.filename,
          filename: randomFilename,
          presignedUrl,
          url: presignedUrl.split('?')[0]
        }
      })
    )

    return {
      message: this.i18n.t('media.media.success.GET_BATCH_PRESIGNED_URLS_SUCCESS'),
      data: presignedUrls
    }
  }
}
