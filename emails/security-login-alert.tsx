import { Button, Heading, Text, Section, Row, Column, Hr, Link } from '@react-email/components'
import * as React from 'react'
import { EmailLayout } from 'emails/components/email-layout'
import { tableRow, tableCellLabel, tableCellValue, hr, heading, paragraph, button } from './components/style'

export interface SecurityLoginAlertProps {
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

const tableContainer = {
  border: '1px solid #e2e8f0',
  borderRadius: '8px',
  padding: '16px',
  margin: '24px 0',
  backgroundColor: '#f8fafc'
}

export const SecurityLoginAlert = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details
}: SecurityLoginAlertProps) => {
  return (
    <EmailLayout previewText={title}>
      <Heading as='h2' style={heading}>
        {title}
      </Heading>

      <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
      <Text style={paragraph}>{mainMessage}</Text>

      <Section style={tableContainer}>
        {details.map((detail) => (
          <Row key={detail.label} style={tableRow}>
            <Column style={tableCellLabel}>{detail.label}:</Column>
            <Column style={tableCellValue}>{detail.value}</Column>
          </Row>
        ))}
      </Section>

      <Text style={paragraph}>{secondaryMessage}</Text>

      <Section style={{ textAlign: 'center', marginTop: '26px' }}>
        <Button style={button} href={buttonUrl}>
          {buttonText}
        </Button>
      </Section>

      <Hr style={hr} />

      <Text style={{ fontSize: '14px', color: '#64748b', textAlign: 'center' as const }}>
        Nếu bạn không thực hiện hành động này, hãy <br />
        <Link href='#' style={{ color: '#d0201c', textDecoration: 'underline' }}>
          bảo vệ tài khoản của bạn ngay lập tức.
        </Link>
      </Text>
    </EmailLayout>
  )
}

export default SecurityLoginAlert
