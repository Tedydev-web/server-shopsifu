import { Injectable } from '@nestjs/common'
import { S3Service } from 'src/shared/services/s3.service'
import { unlink } from 'fs/promises'
import { generateRandomFilename } from 'src/shared/helpers'
import { PresignedUploadFileBodyType } from 'src/routes/media/media.model'
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
      data: result,
      message: this.i18n.t('media.media.success.UPLOAD_SUCCESS')
    }
  }

  async getPresignUrl(body: PresignedUploadFileBodyType) {
    const randomFilename = generateRandomFilename(body.filename)
    const presignedUrl = await this.s3Service.createPresignedUrlWithClient(randomFilename)
    const url = presignedUrl.split('?')[0]
    return {
      data: {
        presignedUrl,
        url
      },
      message: this.i18n.t('media.media.success.GET_PRESIGNED_URL_SUCCESS')
    }
  }
}
