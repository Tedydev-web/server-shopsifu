import { Button, Heading, Section, Text, Row, Column } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'

export interface TwoFactorAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage: string
  buttonText: string
  buttonUrl: string
  details: { label: string; value: string }[]
  action: 'enabled' | 'disabled'
  lang?: 'vi' | 'en'
}

export const TwoFactorAlert = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details,
  action
}: TwoFactorAlertProps) => {
  const titleColor = action === 'enabled' ? '#16a34a' : '#dc2626' // green-600 or red-600
  return (
    <EmailLayout previewText={title}>
      <Heading as='h2' style={{ ...titleStyle, color: titleColor }}>
        {title}
      </Heading>
      <Text style={paragraph}>{greeting}</Text>
      <Text style={paragraph}>{mainMessage}</Text>

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

      <Text style={paragraph}>{secondaryMessage}</Text>
      <Section style={{ textAlign: 'center', marginTop: '26px' }}>
        <Button style={button} href={buttonUrl}>
          {buttonText}
        </Button>
      </Section>
    </EmailLayout>
  )
}

export default TwoFactorAlert

const titleStyle = {
  fontSize: '24px',
  fontWeight: 'bold',
  textAlign: 'center' as const,
  margin: '30px 0'
}

const paragraph = {
  fontSize: '16px',
  lineHeight: '26px',
  color: '#3c4043'
}

const button = {
  backgroundColor: '#2563eb',
  borderRadius: '6px',
  color: '#fff',
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
