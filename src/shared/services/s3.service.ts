import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3'
import { Upload } from '@aws-sdk/lib-storage'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { readFileSync } from 'fs'

import mime from 'mime-types'
@Injectable()
export class S3Service {
  private readonly s3Client: S3Client
  private readonly expiresIn: number
  private readonly bucket: string

  constructor(private readonly configService: ConfigService) {
    this.s3Client = new S3Client({
      credentials: {
        accessKeyId: this.configService.get('aws.accessKey') as string,
        secretAccessKey: this.configService.get('aws.secretKey') as string
      },
      region: this.configService.get('aws.region') as string
    })
    this.expiresIn = this.configService.get('aws.s3.linkExpire') as number
    this.bucket = this.configService.get('aws.s3.bucket') as string
  }

  uploadedFile({ filename, filepath, contentType }: { filename: string; filepath: string; contentType: string }) {
    const parallelUploads3 = new Upload({
      client: this.s3Client,
      params: {
        Bucket: this.bucket,
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
      Bucket: this.bucket,
      Key: filename,
      ContentType: contentType
    })
    return getSignedUrl(this.s3Client, command, { expiresIn: this.expiresIn })
  }
}
