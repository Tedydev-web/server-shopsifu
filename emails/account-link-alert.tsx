import { Button, Heading, Section, Text } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button, heading } from './components/style'

export interface AccountLinkAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage: string
  buttonText: string
  buttonUrl: string
  action: 'linked' | 'unlinked'
  provider: string
  lang?: 'vi' | 'en'
}

export const AccountLinkAlert = ({
  userName,
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  action,
  provider
}: AccountLinkAlertProps) => {
  const titleColor = action === 'linked' ? '#28a745' : '#d0201c'
  return (
    <EmailLayout previewText={title}>
      <Section style={content}>
        <Heading as='h2' style={{ ...heading, color: titleColor }}>
          {title}
        </Heading>
        <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
        <Text style={paragraph}>{mainMessage}</Text>
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

export default AccountLinkAlert

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
