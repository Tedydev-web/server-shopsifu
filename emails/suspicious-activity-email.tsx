import { Button, Heading, Text, Section, Row, Column, Hr, Link } from '@react-email/components'
import * as React from 'react'
import { EmailLayout } from 'emails/components/email-layout'
import { tableRow, tableCellLabel, tableCellValue, hr, heading, paragraph } from './components/style'

export interface SuspiciousActivityEmailProps {
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
  border: '1px solid #fecaca', // red-200
  borderRadius: '8px',
  padding: '16px',
  margin: '24px 0',
  backgroundColor: '#fff1f2' // red-50
}

export const SuspiciousActivityEmail = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  details
}: SuspiciousActivityEmailProps) => {
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

      <Text style={{ fontSize: '16px', color: '#334155' }}>{secondaryMessage}</Text>

      <Section style={{ textAlign: 'center', marginTop: '26px' }}>
        <Button
          style={{
            backgroundColor: '#dc2626', // red-600
            borderRadius: '6px',
            color: '#ffffff',
            fontSize: '16px',
            textDecoration: 'none',
            padding: '12px 24px',
            fontWeight: '600'
          }}
          href={buttonUrl}
        >
          {buttonText}
        </Button>
      </Section>

      <Hr style={hr} />

      <Text style={{ fontSize: '14px', color: '#64748b', textAlign: 'center' as const }}>
        Nếu bạn có bất kỳ câu hỏi nào, xin vui lòng{' '}
        <Link href='#' style={{ color: '#d0201c', textDecoration: 'underline' }}>
          liên hệ với bộ phận hỗ trợ
        </Link>
        .
      </Text>
    </EmailLayout>
  )
}

export default SuspiciousActivityEmail
