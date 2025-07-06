import { PutObjectCommand, S3 } from '@aws-sdk/client-s3'
import { Upload } from '@aws-sdk/lib-storage'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { Injectable } from '@nestjs/common'
import { readFileSync } from 'fs'
import envConfig from 'src/shared/config'
import mime from 'mime-types'
@Injectable()
export class S3Service {
  private s3: S3
  constructor() {
    this.s3 = new S3({
      endpoint: envConfig().s3.endpoint,
      region: envConfig().s3.region,
      credentials: {
        secretAccessKey: envConfig().s3.secretKey,
        accessKeyId: envConfig().s3.accessKey
      }
    })
  }

  uploadedFile({ filename, filepath, contentType }: { filename: string; filepath: string; contentType: string }) {
    const parallelUploads3 = new Upload({
      client: this.s3,
      params: {
        Bucket: envConfig().s3.bucketName,
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
    const command = new PutObjectCommand({ Bucket: envConfig().s3.bucketName, Key: filename, ContentType: contentType })
    return getSignedUrl(this.s3, command, { expiresIn: 10 })
  }
}
