import { Button, Heading, Text, Section, Row, Column, Hr, Link } from '@react-email/components'
import * as React from 'react'
import { EmailLayout } from 'emails/components/email-layout'

export interface SecurityLoginAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage: string
  buttonText: string
  buttonUrl: string
  details: { label: string; value: string }[]
  lang?: 'vi' | 'en'
}

const tableContainer = {
  border: '1px solid #e2e8f0',
  borderRadius: '8px',
  padding: '16px',
  margin: '24px 0',
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

export const SecurityLoginAlert = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details
}: SecurityLoginAlertProps) => {
  return (
    <EmailLayout previewText={title}>
      <Heading as='h2' style={{ fontSize: '24px', fontWeight: '600', textAlign: 'center' }}>
        {title}
      </Heading>

      <Text style={{ fontSize: '16px', color: '#334155' }}>{greeting}</Text>
      <Text style={{ fontSize: '16px', color: '#334155' }}>{mainMessage}</Text>

      <Section style={tableContainer}>
        {details.map((detail) => (
          <Row key={detail.label} style={tableRow}>
            <Column style={tableCellLabel}>{detail.label}:</Column>
            <Column style={tableCellValue}>{detail.value}</Column>
          </Row>
        ))}
      </Section>

      <Text style={{ fontSize: '16px', color: '#334155' }}>{secondaryMessage}</Text>

      <Section style={{ textAlign: 'center', marginTop: '26px' }}>
        <Button
          style={{
            backgroundColor: '#0ea5e9', // sky-500
            borderRadius: '6px',
            color: '#ffffff',
            fontSize: '16px',
            textDecoration: 'none',
            padding: '12px 24px',
            fontWeight: '600'
          }}
          href={buttonUrl}
        >
          {buttonText}
        </Button>
      </Section>

      <Hr style={{ borderColor: '#e2e8f0', margin: '26px 0' }} />

      <Text style={{ fontSize: '14px', color: '#64748b' }}>
        Nếu bạn không thực hiện hành động này, hãy{' '}
        <Link href='#' style={{ color: '#0ea5e9', textDecoration: 'underline' }}>
          bảo vệ tài khoản của bạn ngay lập tức.
        </Link>
      </Text>
    </EmailLayout>
  )
}

export default SecurityLoginAlert
