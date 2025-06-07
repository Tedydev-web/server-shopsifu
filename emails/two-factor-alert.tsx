import { Button, Heading, Section, Text, Row, Column, Hr } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { detailsTableContainer, tableRow, tableCellLabel, tableCellValue, button, hr } from './components/style'

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
