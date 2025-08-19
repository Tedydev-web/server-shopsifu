import { PutObjectCommand, S3 } from '@aws-sdk/client-s3'
import { Upload } from '@aws-sdk/lib-storage'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { readFileSync } from 'fs'
import mime from 'mime-types'

@Injectable()
export class S3Service {
  private s3: S3

  constructor(private readonly configService: ConfigService) {
    this.s3 = new S3({
      region: this.configService.get<string>('S3_REGION') || 'eu-west-3',
      credentials: {
        secretAccessKey: this.configService.get<string>('S3_SECRET_KEY') || '',
        accessKeyId: this.configService.get<string>('S3_ACCESS_KEY') || ''
      }
    })
  }

  uploadedFile({ filename, filepath, contentType }: { filename: string; filepath: string; contentType: string }) {
    const parallelUploads3 = new Upload({
      client: this.s3,
      params: {
        Bucket: this.configService.get<string>('S3_BUCKET_NAME'),
        Key: filename,
        Body: readFileSync(filepath),
        ContentType: contentType
      },
      tags: [],
      queueSize: 4,
      partSize: 1024 * 1024 * 5,
      leavePartsOnError: false
    })
    return parallelUploads3.done()
  }

  createPresignedUrlWithClient(filename: string) {
    const contentType = mime.lookup(filename) || 'application/octet-stream'
    const command = new PutObjectCommand({
      Bucket: this.configService.get<string>('S3_BUCKET_NAME'),
      Key: filename,
      ContentType: contentType
    })
    return getSignedUrl(this.s3, command, { expiresIn: 300 })
  }
}
