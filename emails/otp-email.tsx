import { Column, Heading, Row, Section, Text, Hr } from '@react-email/components'
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

export interface OtpEmailProps {
  userName: string
  code: string
  headline: string
  content: string
  codeLabel: string
  validity: string
  disclaimer: string
  greeting: string
  lang?: 'vi' | 'en'
  details?: { label: string; value: string }[]
}

export const OtpEmail = ({
  code,
  headline,
  content,
  codeLabel,
  validity,
  disclaimer,
  greeting,
  details
}: OtpEmailProps) => {
  return (
    <EmailLayout previewText={headline}>
      <Heading as='h2' style={heading}>
        {headline}
      </Heading>

      <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
      <Text style={paragraph}>{content}</Text>

      <Section style={codeContainer}>
        <Text style={{ marginBottom: '16px', fontSize: '16px', color: '#334155' }}>{codeLabel}:</Text>
        <Text style={codeStyle}>{code}</Text>
        <Text style={{ marginTop: '16px', fontSize: '14px', color: '#64748b' }}>{validity}</Text>
      </Section>

      {details && details.length > 0 && (
        <>
          <Hr style={hr} />
          <Section style={detailsTableContainer}>
            {details.map((detail) => (
              <Row key={detail.label} style={tableRow}>
                <Column style={tableCellLabel}>{detail.label}:</Column>
                <Column style={tableCellValue}>{detail.value}</Column>
              </Row>
            ))}
          </Section>
        </>
      )}

      <Hr style={hr} />

      <Text style={{ fontSize: '14px', color: '#64748b', textAlign: 'center' as const }}>{disclaimer}</Text>
    </EmailLayout>
  )
}

export default OtpEmail

const codeContainer = {
  background: '#f1f5f9',
  borderRadius: '8px',
  border: '1px solid #cbd5e1',
  textAlign: 'center' as const,
  margin: '16px auto 14px',
  verticalAlign: 'middle',
  width: '280px'
}

const codeStyle = {
  color: '#0f172a',
  fontSize: '36px',
  fontWeight: 'bold' as const,
  letterSpacing: '0.25em',
  margin: 0
}
