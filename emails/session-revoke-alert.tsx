import { Button, Heading, Section, Text } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button, heading } from './components/style'

export interface SessionRevokeAlertProps {
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

export const SessionRevokeAlert = ({
  userName,
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details
}: SessionRevokeAlertProps) => {
  return (
    <EmailLayout previewText={title}>
      <Section style={content}>
        <Heading as='h2' style={heading}>
          {title}
        </Heading>
        <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
        <Text style={paragraph}>{mainMessage}</Text>

        {details && details.length > 0 && (
          <Section style={detailsBox}>
            {details.map((detail) => (
              <Text key={detail.label} style={detailItem}>
                <b>{detail.label}:</b> {detail.value}
              </Text>
            ))}
          </Section>
        )}

        <Text style={paragraph}>{secondaryMessage}</Text>
        <Section style={buttonContainer}>
          <Button style={button} href={buttonUrl}>
            {buttonText}
          </Button>
        </Section>
      </Section>
    </EmailLayout>
  )
}

export default SessionRevokeAlert

const content = {
  padding: '0 20px'
}

const paragraph = {
  fontSize: '16px',
  lineHeight: '26px',
  color: '#3c4043'
}

const detailsBox = {
  background: '#f8f9fa',
  border: '1px solid #dee2e6',
  borderRadius: '4px',
  padding: '15px',
  margin: '20px 0'
}

const detailItem = {
  fontSize: '14px',
  lineHeight: '22px',
  margin: '5px 0'
}
