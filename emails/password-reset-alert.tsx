import { Button, Heading, Section, Text, Row, Column, Hr, Link } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'

export interface PasswordResetAlertProps {
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

export const PasswordResetAlert = ({
  userName,
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details
}: PasswordResetAlertProps) => {
  return (
    <EmailLayout previewText={title}>
      <Heading as='h2' style={{ fontSize: '24px', fontWeight: '600', textAlign: 'center' }}>
        {title}
      </Heading>
      <Text style={text}>{greeting}</Text>
      <Text style={text}>{mainMessage}</Text>

      {details && details.length > 0 && (
        <Section style={detailsTableContainer}>
          {details.map((detail) => (
            <Row key={detail.label} style={tableRow}>
              <Column style={tableCellLabel}>{detail.label}:</Column>
              <Column style={tableCellValue}>{detail.value}</Column>
            </Row>
          ))}
        </Section>
      )}

      <Text style={text}>{secondaryMessage}</Text>
      <Section style={{ textAlign: 'center', marginTop: '26px' }}>
        <Button style={button} href={buttonUrl}>
          {buttonText}
        </Button>
      </Section>
    </EmailLayout>
  )
}

export default PasswordResetAlert

const text: React.CSSProperties = {
  color: '#3a414c',
  fontSize: '16px',
  lineHeight: '26px'
}

const button: React.CSSProperties = {
  backgroundColor: '#dc2626', // red-600
  borderRadius: '6px',
  color: '#ffffff',
  fontSize: '16px',
  textDecoration: 'none',
  padding: '12px 24px',
  fontWeight: '600'
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
