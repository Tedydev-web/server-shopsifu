import { useState } from 'react'
import http from './http'
import axios from 'axios'

export default function UploadPage() {
  const [url, setUrl] = useState('')
  const [presignedUrl, setPresignedUrl] = useState('')
  const [isSuccess, setIsSuccess] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const handleUpload = () => {
    console.log(file)
    if (file) {
      // if (file.size > 1 * 1024 * 1024) {
      //   alert('File size must be less than 1MB')
      //   return
      // }
      http
        .post('/media/images/upload/presigned-url', {
          filename: file.name,
          filesize: file.size
        })
        .then((res) => {
          setUrl(res.data.url)
          setPresignedUrl(res.data.presignedUrl)
          return axios.put(res.data.presignedUrl, file, {
            headers: {
              'Content-Type': file.type
            }
          })
        })
        .then(() => {
          setIsSuccess(true)
        })
    }
  }
  return (
    <div>
      <h1>Upload File</h1>
      <div className='upload-area'>
        <input
          type='file'
          accept='image/*'
          onChange={(e) => {
            setFile(e.target.files![0])
          }}
        />
      </div>
      <button onClick={handleUpload}>Upload</button>
      {url && isSuccess && (
        <img
          src={url}
          style={{
            width: '200px',
            height: '200px',
            objectFit: 'cover'
          }}
        />
      )}
      <div>
        <h2>URL</h2>
        <a href={url} target='_blank'>
          {url}
        </a>
      </div>
      <div>
        <h2>Presigned URL</h2>
        <a href={presignedUrl} target='_blank'>
          {presignedUrl}
        </a>
      </div>
    </div>
  )
}
