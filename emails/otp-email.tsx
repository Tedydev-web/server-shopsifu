import {
  Body,
  Button,
  Column,
  Container,
  Head,
  Heading,
  Html,
  Img,
  Preview,
  Row,
  Section,
  Text,
  Hr
} from '@react-email/components'
import * as React from 'react'
import { TypeOfVerificationCodeType } from 'src/routes/auth/shared/constants/auth.constants'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

export interface OtpEmailProps {
  userName: string
  code: string
  headline: string
  content: string
  codeLabel: string
  validity: string
  disclaimer: string
  greeting: string
  lang?: 'vi' | 'en'
  details?: { label: string; value: string }[]
}

const baseUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : ''

export const OtpEmail = ({
  userName,
  code,
  headline,
  content,
  codeLabel,
  validity,
  disclaimer,
  greeting,
  details
}: OtpEmailProps) => {
  return (
    <EmailLayout previewText={headline}>
      <Heading as='h2' style={{ fontSize: '24px', fontWeight: '600', textAlign: 'center' }}>
        {headline}
      </Heading>

      <Text style={{ fontSize: '16px', color: '#334155' }}>{greeting}</Text>
      <Text style={{ fontSize: '16px', color: '#334155' }}>{content}</Text>

      <Section style={codeContainer}>
        <Text style={{ marginBottom: '16px', fontSize: '16px', color: '#334155' }}>{codeLabel}:</Text>
        <Text style={codeStyle}>{code}</Text>
        <Text style={{ marginTop: '16px', fontSize: '14px', color: '#64748b' }}>{validity}</Text>
      </Section>

      {details && details.length > 0 && (
        <>
          <Text style={{ fontSize: '16px', color: '#334155', fontWeight: 'bold' }}>Chi tiết yêu cầu:</Text>
          <Section style={detailsTableContainer}>
            {details.map((detail) => (
              <Row key={detail.label} style={tableRow}>
                <Column style={tableCellLabel}>{detail.label}:</Column>
                <Column style={tableCellValue}>{detail.value}</Column>
              </Row>
            ))}
          </Section>
        </>
      )}

      <Hr style={{ borderColor: '#e2e8f0', margin: '26px 0' }} />

      <Text style={{ fontSize: '14px', color: '#64748b' }}>{disclaimer}</Text>
    </EmailLayout>
  )
}

export default OtpEmail

const codeContainer = {
  background: '#f1f5f9',
  borderRadius: '8px',
  border: '1px solid #cbd5e1',
  padding: '24px',
  textAlign: 'center' as const,
  margin: '24px 0'
}

const codeStyle = {
  color: '#0f172a',
  fontSize: '36px',
  fontWeight: 'bold' as const,
  letterSpacing: '0.25em',
  margin: 0
}

const detailsTableContainer = {
  border: '1px solid #e2e8f0',
  borderRadius: '8px',
  padding: '16px',
  margin: '16px 0',
  backgroundColor: '#f8fafc'
}

const tableRow = {
  padding: '8px 0'
}

const tableCellLabel = {
  fontWeight: 'bold' as const,
  color: '#475569',
  width: '120px',
  fontSize: '14px'
}

const tableCellValue = {
  color: '#1e293b',
  fontSize: '14px'
}
