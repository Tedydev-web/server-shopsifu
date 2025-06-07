import { Button, Heading, Section, Text } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button, heading } from './components/style'

export interface DeviceTrustAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage: string
  buttonText: string
  buttonUrl: string
  details: { label: string; value: string }[]
  action: 'trusted' | 'untrusted'
  lang?: 'vi' | 'en'
}

export const DeviceTrustAlert = ({
  userName,
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details,
  action
}: DeviceTrustAlertProps) => {
  const titleColor = action === 'trusted' ? '#28a745' : '#e00707'
  return (
    <EmailLayout previewText={title}>
      <Section style={content}>
        <Heading as='h2' style={{ ...heading, color: titleColor }}>
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

export default DeviceTrustAlert

const content = {
  padding: '0 20px'
}

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
