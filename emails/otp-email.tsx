import { Heading, Hr, Preview, Section, Text } from '@react-email/components'
import React from 'react'
import EmailLayout from './email-layout'
import I18nEmail from 'src/i18n/vi/email.json' // Import the new i18n file
import { TypeOfVerificationCodeType } from 'src/routes/auth/shared/constants/auth.constants'

type OtpType = TypeOfVerificationCodeType

interface OtpEmailProps {
  otpCode: string
  otpType: OtpType
  lang?: 'vi' | 'en'
}

// Map OTP types to the i18n keys
const i18nMap = I18nEmail.Email.otp

export default function OtpEmail({ otpCode, otpType, lang = 'vi' }: OtpEmailProps) {
  // Get the content for the specific OTP type, or fallback to default
  const content = i18nMap[otpType] || i18nMap.default
  const common = i18nMap.common

  return (
    <EmailLayout title={content.subject} preview={content.subject} lang={lang}>
      <Section style={upperSection}>
        <Heading style={h1}>{content.headline}</Heading>
        <Text style={mainText}>{content.content}</Text>
      </Section>
      <Section style={verificationSection}>
        <Text style={verifyText}>{common.codeLabel}</Text>
        <Text style={codeText}>{otpCode}</Text>
        <Text style={validityText}>{common.validity}</Text>
      </Section>
      <Section style={lowerSection}>
        <Text style={cautionText}>{common.disclaimer}</Text>
        <Hr style={hr} />
      </Section>
    </EmailLayout>
  )
}

// --- Styles ---
const upperSection = { padding: '25px 35px' }
const lowerSection = { padding: '25px 35px' }
const verificationSection = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '25px 35px',
  backgroundColor: '#f2f2f2',
  borderRadius: '8px',
  margin: '0 35px'
}

const h1 = {
  color: '#333',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: '20px',
  fontWeight: 'bold',
  marginBottom: '15px',
  textAlign: 'center' as const
}

const text = {
  color: '#333',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: '14px',
  margin: '24px 0'
}

const mainText = { ...text, marginBottom: '14px', textAlign: 'center' as const }
const verifyText = { ...text, margin: 0, fontWeight: 'bold', textAlign: 'center' as const }
const codeText = { ...text, fontWeight: 'bold', fontSize: '36px', margin: '10px 0', textAlign: 'center' as const }
const validityText = { ...text, margin: '0px', fontSize: '12px', textAlign: 'center' as const }
const cautionText = { ...text, margin: '0px', fontSize: '12px' }
const hr = { borderColor: '#e8eaed', margin: '20px 0' }
