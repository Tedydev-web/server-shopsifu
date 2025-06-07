import {
  Body,
  Button,
  Column,
  Container,
  Head,
  Heading,
  Html,
  Img,
  Preview,
  Row,
  Section,
  Text,
  Hr,
  Link
} from '@react-email/components'
import * as React from 'react'
import { EmailLayout } from 'emails/components/email-layout'
import {
  detailsTableContainer,
  tableRow,
  tableCellLabel,
  tableCellValue,
  hr,
  heading,
  paragraph
} from './components/style'

export interface RecoveryCodesEmailProps {
  userName: string
  recoveryCodes: string[]
  headline: string
  greeting: string
  content: string
  codesLabel: string
  warning: string
  buttonText: string
  buttonUrl: string
  lang?: 'vi' | 'en'
  details?: { label: string; value: string }[]
  downloadUrl: string
}

const half = Math.ceil(10 / 2)

export const RecoveryCodesEmail = ({
  greeting,
  headline,
  content,
  codesLabel,
  warning,
  buttonText,
  buttonUrl,
  recoveryCodes,
  details,
  downloadUrl
}: RecoveryCodesEmailProps) => {
  const firstHalf = recoveryCodes.slice(0, half)
  const secondHalf = recoveryCodes.slice(half)

  return (
    <EmailLayout previewText={headline}>
      <Heading as='h2' style={heading}>
        {headline}
      </Heading>
      <Text style={{ ...paragraph, fontWeight: 'bold' }}>{greeting}</Text>
      <Text style={paragraph}>{content}</Text>

      <Section style={codesContainer}>
        <Text style={{ ...text, textAlign: 'center', fontWeight: 'bold', marginBottom: '20px' }}>{codesLabel}</Text>
        <Row>
          <Column align='center' style={codeColumn}>
            {firstHalf.map((code) => (
              <Text key={code} style={codeText}>
                {code}
              </Text>
            ))}
          </Column>
          <Column align='center' style={codeColumn}>
            {secondHalf.map((code) => (
              <Text key={code} style={codeText}>
                {code}
              </Text>
            ))}
          </Column>
        </Row>
      </Section>

      <Section style={{ textAlign: 'center', marginTop: '20px' }}>
        <Button style={downloadButton} href={downloadUrl}>
          Tải xuống (.txt)
        </Button>
      </Section>

      <Text style={{ ...text, fontWeight: 'bold', color: '#c0392b', textAlign: 'center', marginTop: '20px' }}>
        {warning}
      </Text>

      <Hr style={hr} />
      {details && details.length > 0 && (
        <>
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
      <Section style={{ textAlign: 'center' }}>
        <Button style={mainButton} href={buttonUrl}>
          {buttonText}
        </Button>
      </Section>
    </EmailLayout>
  )
}

const text: React.CSSProperties = {
  color: '#3a414c',
  fontSize: '16px',
  lineHeight: '26px'
}

const codesContainer: React.CSSProperties = {
  background: '#f8fafc',
  borderRadius: '8px',
  border: '1px solid #e2e8f0',
  padding: '20px',
  margin: '20px 0',
  fontFamily: `'Courier New', Courier, monospace`
}

const codeColumn: React.CSSProperties = {
  padding: '0 10px'
}

const codeText: React.CSSProperties = {
  ...text,
  textAlign: 'center',
  margin: '10px 0',
  fontSize: '18px',
  letterSpacing: '1px',
  fontWeight: 600
}

const downloadButton: React.CSSProperties = {
  backgroundColor: '#16a34a', // green-600
  borderRadius: '6px',
  color: '#ffffff',
  fontSize: '16px',
  textDecoration: 'none',
  padding: '12px 20px',
  fontWeight: '600',
  display: 'inline-block'
}

const mainButton: React.CSSProperties = {
  backgroundColor: '#2563eb',
  borderRadius: '6px',
  color: '#fff',
  fontSize: '16px',
  textDecoration: 'none',
  textAlign: 'center',
  display: 'block',
  width: '100%',
  padding: '14px 0',
  fontWeight: 'bold'
}

export default RecoveryCodesEmail
