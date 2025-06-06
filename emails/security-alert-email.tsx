import { Heading, Hr, Section, Text, Button } from '@react-email/components'
import React from 'react'
import EmailLayout from './email-layout'

// Dựa trên payload từ email.service.ts
export interface SecurityAlertEmailProps {
  userName?: string
  alertSubject: string
  alertTitle: string
  mainMessage: string
  actionDetails?: Array<{ label: string; value: string }>
  actionButtonText?: string
  actionButtonUrl?: string
  secondaryMessage?: string
  lang?: 'vi' | 'en'
}

export default function SecurityAlertEmail({
  alertSubject,
  alertTitle,
  mainMessage,
  actionDetails,
  actionButtonText,
  actionButtonUrl,
  secondaryMessage,
  userName,
  lang = 'vi'
}: SecurityAlertEmailProps) {
  return (
    <EmailLayout title={alertSubject} preview={alertSubject} lang={lang}>
      <Section style={upperSection}>
        <Heading style={h1}>{alertTitle}</Heading>
        {userName && <Text style={mainText}>Xin chào {userName},</Text>}
        <Text style={mainText}>{mainMessage}</Text>
      </Section>

      {actionDetails && actionDetails.length > 0 && (
        <Section style={detailsSection}>
          {actionDetails.map((detail, index) => (
            <Text key={index} style={detailsText}>
              <strong style={{ fontWeight: 'bold' }}>{detail.label}:</strong> {detail.value}
            </Text>
          ))}
        </Section>
      )}

      {actionButtonText && actionButtonUrl && (
        <Section style={buttonSection}>
          <Button style={button} href={actionButtonUrl}>
            {actionButtonText}
          </Button>
        </Section>
      )}

      {secondaryMessage && (
        <Section style={lowerSection}>
          <Text style={cautionText}>{secondaryMessage}</Text>
        </Section>
      )}
      <Hr style={hr} />
    </EmailLayout>
  )
}

// --- Styles ---
const upperSection = { padding: '25px 35px' }
const detailsSection = { padding: '0 35px 25px 35px' }
const lowerSection = { padding: '25px 35px' }
const buttonSection = { textAlign: 'center' as const, padding: '25px 35px' }

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
const detailsText = { ...text, margin: '4px 0', textAlign: 'left' as const }
const cautionText = { ...text, margin: '0px', fontSize: '12px', textAlign: 'center' as const }
const hr = { borderColor: '#e8eaed', margin: '20px 0' }
const button = {
  backgroundColor: '#d0201c',
  borderRadius: '5px',
  color: '#fff',
  fontSize: '16px',
  fontWeight: 'bold',
  textDecoration: 'none',
  textAlign: 'center' as const,
  display: 'inline-block',
  padding: '12px 20px'
}
