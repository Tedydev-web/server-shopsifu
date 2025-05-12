import * as React from 'react'
import { Tailwind } from '@react-email/tailwind'

export interface PasswordChangedEmailProps {
  title: string
  otpCode: string
  deviceInfo?: {
    userAgent: string
    ip: string
    lastActive: Date
    isActive: boolean
  }
}

export default function PasswordChangedEmail({ title, otpCode, deviceInfo }: PasswordChangedEmailProps) {
  return (
    <Tailwind>
      <div className='max-w-lg mx-auto p-8 bg-white shadow-md rounded-md'>
        <h1 className='text-2xl font-bold text-gray-800 mb-6'>{title}</h1>

        <div className='border-b border-gray-200 mb-6'></div>

        <p className='text-gray-600 mb-4'>Mật khẩu tài khoản Shopsifu của bạn đã được thay đổi thành công.</p>

        <p className='text-gray-600 mb-6'>
          Nếu bạn không thực hiện thay đổi này, vui lòng liên hệ với bộ phận hỗ trợ của chúng tôi ngay lập tức.
        </p>

        {deviceInfo && (
          <div className='mt-6 border-t border-gray-200 pt-4'>
            <p className='text-gray-600 text-sm mb-2'>Thay đổi mật khẩu được thực hiện từ thiết bị:</p>
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
              Nếu đây không phải là bạn, vui lòng liên hệ với chúng tôi ngay lập tức để bảo vệ tài khoản của bạn.
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
