import * as React from 'react'
import { Tailwind } from '@react-email/tailwind'

export interface OTPEmailProps {
  otpCode: string
  title: string
  deviceInfo?: {
    userAgent: string
    ip: string
    lastActive: Date
    isActive: boolean
  }
}

export default function OTPEmail({ otpCode, title, deviceInfo }: OTPEmailProps) {
  return (
    <Tailwind>
      <div className='max-w-lg mx-auto p-8 bg-white shadow-md rounded-md'>
        <h1 className='text-2xl font-bold text-gray-800 mb-6'>{title}</h1>

        <div className='border-b border-gray-200 mb-6'></div>

        <p className='text-gray-600 mb-4'>Mã OTP của bạn là:</p>

        <div className='bg-gray-100 p-6 rounded-md mb-6'>
          <p className='text-center text-3xl font-bold tracking-wider text-blue-600'>{otpCode}</p>
        </div>

        <p className='text-gray-600 mb-6'>Mã này sẽ hết hạn sau 10 phút. Đừng chia sẻ mã này với bất kỳ ai.</p>

        {deviceInfo && (
          <div className='mt-6 border-t border-gray-200 pt-4'>
            <p className='text-gray-600 text-sm mb-2'>Yêu cầu OTP được gửi từ thiết bị:</p>
            <ul className='text-gray-600 text-xs space-y-1 bg-gray-50 p-3 rounded'>
              <li>
                <span className='font-medium'>Thiết bị:</span> {deviceInfo.userAgent}
              </li>
              <li>
                <span className='font-medium'>Địa chỉ IP:</span> {deviceInfo.ip}
              </li>
              <li>
                <span className='font-medium'>Thời gian:</span>{' '}
                {new Date(deviceInfo.lastActive).toLocaleString('vi-VN')}
              </li>
            </ul>
            <p className='text-xs text-gray-500 mt-2'>
              Nếu đây không phải là bạn, vui lòng bỏ qua email này và liên hệ với chúng tôi ngay lập tức.
            </p>
          </div>
        )}

        <div className='mt-8 text-gray-500 text-xs text-center'>
          <p>© 2024 Shopsifu. Tất cả các quyền được bảo lưu.</p>
        </div>
      </div>
    </Tailwind>
  )
}
