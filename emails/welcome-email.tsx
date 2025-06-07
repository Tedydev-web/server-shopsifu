import { Button, Heading, Section, Text } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

export interface WelcomeEmailProps {
  userName: string
  headline: string
  content: string
  buttonText: string
  buttonUrl: string
  lang?: 'vi' | 'en'
  greeting: string
}

export const WelcomeEmail = ({ userName, headline, content, buttonText, buttonUrl, greeting }: WelcomeEmailProps) => {
  return (
    <EmailLayout previewText={headline}>
      <Section style={main}>
        <Heading style={heading}>{headline}</Heading>
        <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
        <Text style={paragraph}>{content}</Text>
        <Section style={buttonContainer}>
          <Button style={button} href={buttonUrl}>
            {buttonText}
          </Button>
        </Section>
      </Section>
    </EmailLayout>
  )
}

export default WelcomeEmail

const main = {
  backgroundColor: '#ffffff',
  padding: '20px'
}

const heading = {
  fontSize: '28px',
  fontWeight: 'bold',
  color: '#2c3e50',
  textAlign: 'center' as const
}

const paragraph = {
  fontSize: '16px',
  lineHeight: '1.5',
  color: '#34495e',
  margin: '10px 0'
}
