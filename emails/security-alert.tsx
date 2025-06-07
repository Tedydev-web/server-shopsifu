import { Button, Heading, Section, Text } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

interface SecurityAlertEmailProps {
  userName?: string
  alertTitle?: string
  mainMessage?: string
  actionButtonText?: string
  actionButtonUrl?: string
  secondaryMessage?: string
}

export const SecurityAlertEmail = ({
  userName = 'User',
  alertTitle = 'Security Alert',
  mainMessage = 'A security-related event has occurred on your account.',
  actionButtonText,
  actionButtonUrl,
  secondaryMessage
}: SecurityAlertEmailProps) => {
  const previewText = `Security Alert: ${alertTitle}`

  return (
    <EmailLayout previewText={previewText}>
      <Section style={content}>
        <Heading as='h2' style={title}>
          {alertTitle}
        </Heading>
        <Text style={paragraph}>Hello {userName},</Text>
        <Text style={paragraph}>{mainMessage}</Text>
        {secondaryMessage && <Text style={paragraph}>{secondaryMessage}</Text>}

        {actionButtonText && actionButtonUrl && (
          <Section style={buttonContainer}>
            <Button style={button} href={actionButtonUrl}>
              {actionButtonText}
            </Button>
          </Section>
        )}
      </Section>
    </EmailLayout>
  )
}

export default SecurityAlertEmail

const content = {
  padding: '0 20px'
}

const title = {
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
