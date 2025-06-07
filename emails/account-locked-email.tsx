import { Button, Heading, Section, Text } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

export interface AccountLockedEmailProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage: string
  buttonText: string
  buttonUrl: string
  details: { label: string; value: string }[]
  lockoutMinutes: number
  lang?: 'vi' | 'en'
}

export const AccountLockedEmail = ({
  userName,
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details,
  lockoutMinutes
}: AccountLockedEmailProps) => {
  const previewText = title

  return (
    <EmailLayout previewText={previewText}>
      <Heading
        as='h2'
        style={{
          fontSize: '24px',
          fontWeight: 'bold',
          textAlign: 'center',
          margin: '30px 0',
          color: '#e00707'
        }}
      >
        {title}
      </Heading>
      <Text style={{ fontSize: '16px', lineHeight: '26px', color: '#3c4043' }}>{greeting}</Text>
      <Text style={{ fontSize: '16px', lineHeight: '26px', color: '#3c4043' }}>{mainMessage}</Text>
      <Section style={detailsBox}>
        {details.map((item, index) => (
          <Text key={index} style={detailItem}>
            <b>{item.label}:</b> {item.value}
          </Text>
        ))}
      </Section>
      <Text style={{ fontSize: '16px', lineHeight: '26px', color: '#3c4043' }}>{secondaryMessage}</Text>
      <Section style={buttonContainer}>
        <Button
          style={{
            backgroundColor: '#2563eb',
            borderRadius: '6px',
            color: '#fff',
            fontSize: '16px',
            textDecoration: 'none',
            textAlign: 'center',
            display: 'inline-block',
            padding: '12px 20px',
            fontWeight: 'bold'
          }}
          href={buttonUrl}
        >
          {buttonText}
        </Button>
      </Section>
    </EmailLayout>
  )
}

export default AccountLockedEmail

const content = {
  padding: '0 20px'
}

const titleStyle = {
  fontSize: '24px',
  fontWeight: 'bold',
  textAlign: 'center' as const,
  margin: '30px 0',
  color: '#c0392b'
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
