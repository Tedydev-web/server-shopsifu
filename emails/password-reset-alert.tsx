import { Button, Heading, Section, Text, Row, Column, Hr, Link } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import {
  detailsTableContainer,
  tableRow,
  tableCellLabel,
  tableCellValue,
  hr,
  heading,
  paragraph
} from './components/style'

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
      <Heading as='h2' style={heading}>
        {title}
      </Heading>
      <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
      <Text style={paragraph}>{mainMessage}</Text>
      <Hr style={hr} />
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
