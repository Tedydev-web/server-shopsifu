import {
  Body,
  Container,
  Head,
  Heading,
  Hr,
  Html,
  Img,
  Link,
  Preview,
  Section,
  Text,
  Row,
  Column,
  Tailwind
} from '@react-email/components'
import React from 'react'

interface SecurityAlertEmailProps {
  userName?: string
  alertSubject: string // e.g., "Security Alert" or "New Device Login"
  alertTitle: string // e.g., "Security Alert: Your Password Was Changed"
  mainMessage: string // The main explanation of what happened.
  actionDetails?: Array<{ label: string; value: string }> // e.g., [{label: "Time", value: "..."}]
  actionButtonText?: string // e.g., "Review Your Devices"
  actionButtonUrl?: string // URL for the button
  secondaryMessage?: string // e.g., "If you did not make this change..."
  logoUrl?: string
  appPlayStoreUrl?: string
  contactLinks?: {
    facebook?: string
    telegram?: string
    zalo?: string
  }
  currentYear?: string
}

const defaultProps: Partial<SecurityAlertEmailProps> = {
  logoUrl: 'https://res.cloudinary.com/tedydev/image/upload/v1746547380/shopsifu/white-logo.png',
  appPlayStoreUrl: 'https://res.cloudinary.com/tedydev/image/upload/v1746551514/shopsifu/google-play-footer.png',
  contactLinks: {
    facebook: 'https://notifications.google.com',
    telegram: 'https://notifications.google.com',
    zalo: 'https://notifications.google.com'
  },
  currentYear: new Date().getFullYear().toString()
}

export default function SecurityAlertEmail({
  userName,
  alertSubject,
  alertTitle,
  mainMessage,
  actionDetails,
  actionButtonText,
  actionButtonUrl,
  secondaryMessage,
  logoUrl = defaultProps.logoUrl!,
  appPlayStoreUrl = defaultProps.appPlayStoreUrl!,
  contactLinks = defaultProps.contactLinks!,
  currentYear = defaultProps.currentYear!
}: SecurityAlertEmailProps) {
  const previewText = alertTitle.length > 50 ? alertTitle.substring(0, 47) + '...' : alertTitle

  return (
    <Html>
      <Head>
        <title>{alertSubject}</title>
      </Head>
      <Preview>{previewText}</Preview>
      <Tailwind>
        <Body style={main}>
          <Container style={container}>
            <Section style={coverSection}>
              <Section style={imageSection}>
                <Img src={logoUrl} width='120' height='120' alt='Logo Shopsifu' />
              </Section>
              <Section style={upperSection}>
                <Heading style={h1}>{alertTitle}</Heading>
                {userName && <Text style={mainText}>Xin chào {userName},</Text>}
                <Text style={mainText}>{mainMessage}</Text>
              </Section>

              {actionDetails && actionDetails.length > 0 && (
                <Section style={detailsSection}>
                  <Text style={detailsTitleText}>Thông tin chi tiết:</Text>
                  {actionDetails.map((detail, index) => (
                    <Row key={index} style={detailRow}>
                      <Column style={detailLabelColumn}>
                        <Text style={detailLabelText}>{detail.label}:</Text>
                      </Column>
                      <Column style={detailValueColumn}>
                        <Text style={detailValueText}>{detail.value}</Text>
                      </Column>
                    </Row>
                  ))}
                </Section>
              )}

              {actionButtonText && actionButtonUrl && (
                <Section style={buttonSection}>
                  <Link style={button} href={actionButtonUrl} target='_blank'>
                    {actionButtonText}
                  </Link>
                </Section>
              )}

              {secondaryMessage && (
                <Section style={lowerSection}>
                  <Text style={cautionText}>{secondaryMessage}</Text>
                </Section>
              )}

              <Section style={lowerSection}>
                <Text style={cautionText}>
                  Shopsifu sẽ không bao giờ gửi email yêu cầu bạn tiết lộ hoặc xác minh mật khẩu, số thẻ tín dụng hoặc
                  số tài khoản ngân hàng của bạn.
                </Text>
                <Hr style={hr} />
              </Section>

              <Section style={containerContact}>
                <Row>
                  <Text style={paragraph}>Liên hệ với chúng tôi</Text>
                </Row>
                <Row align='left' style={socialIconsRow}>
                  {contactLinks.facebook && (
                    <Column style={socialIconColumn}>
                      <Link href={contactLinks.facebook}>
                        <Img
                          width='28'
                          height='28'
                          src='https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/facebook.png'
                        />
                      </Link>
                    </Column>
                  )}
                  {contactLinks.telegram && (
                    <Column style={socialIconColumn}>
                      <Link href={contactLinks.telegram}>
                        <Img
                          width='28'
                          height='28'
                          src='https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/telegram.png'
                        />
                      </Link>
                    </Column>
                  )}
                  {contactLinks.zalo && (
                    <Column style={socialIconColumn}>
                      <Link href={contactLinks.zalo}>
                        <Img
                          width='28'
                          height='28'
                          src='https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/zalo.png'
                        />
                      </Link>
                    </Column>
                  )}
                </Row>
                <Row>
                  <Img style={footerImage} width='540' height='48' src={appPlayStoreUrl} />
                </Row>
              </Section>
              <Section style={footerTextSection}>
                <Text style={footerCopyrightText}>© {currentYear} Bản quyền thuộc về Shopsifu</Text>
              </Section>
            </Section>
          </Container>
        </Body>
      </Tailwind>
    </Html>
  )
}

const main = {
  backgroundColor: '#fff',
  color: '#212121',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif"
}

const container = {
  padding: '20px',
  margin: '0 auto',
  maxWidth: '600px'
}

const h1 = {
  color: '#333',
  fontSize: '20px',
  fontWeight: 'bold',
  marginBottom: '15px'
}

const text = {
  color: '#333',
  fontSize: '14px',
  lineHeight: '24px'
}

const imageSection = {
  backgroundColor: '#d0201c',
  display: 'flex',
  padding: '20px 0',
  alignItems: 'center',
  justifyContent: 'center'
}

const coverSection = {
  // Optional: Add background image if needed, similar to otp.tsx
}

const upperSection = { padding: '25px 35px' }
const lowerSection = { padding: '25px 35px' }

const detailsSection = {
  padding: '0px 35px 25px 35px'
}

const detailsTitleText = {
  ...text,
  fontWeight: 'bold',
  marginBottom: '10px'
}

const detailRow = {
  marginBottom: '5px'
}

const detailLabelColumn = {
  width: '120px'
}

const detailValueColumn = {
  // Takes remaining width
}

const detailLabelText = {
  ...text,
  fontWeight: 'bold',
  textAlign: 'left' as const
}

const detailValueText = {
  ...text,
  textAlign: 'left' as const
}

const buttonSection = {
  textAlign: 'center' as const,
  padding: '10px 35px'
}

const button = {
  backgroundColor: '#d0201c',
  borderRadius: '5px',
  color: '#fff',
  fontSize: '16px',
  fontWeight: 'bold',
  textDecoration: 'none',
  textAlign: 'center' as const,
  display: 'inline-block',
  padding: '12px 25px',
  margin: '0 auto'
}

const mainText = { ...text, marginBottom: '14px' }
const cautionText = { ...text, margin: '0px', fontSize: '12px' }

const paragraph = {
  fontSize: '14px',
  lineHeight: '22px',
  color: '#3c4043'
}

const containerContact = {
  backgroundColor: 'rgba(188, 188, 188, 0.17)', // Lighter background
  width: '90%',
  borderRadius: '5px',
  overflow: 'hidden',
  padding: '20px',
  margin: '20px auto'
}

const socialIconsRow = {
  width: '84px',
  float: 'left' as const // Ensure proper alignment
}

const socialIconColumn = {
  paddingRight: '4px'
}

const footerImage = {
  maxWidth: '100%',
  marginTop: '20px'
}

const hr = {
  borderColor: '#e8eaed',
  margin: '20px 0'
}

const footerTextSection = {
  padding: '0 40px 30px 40px'
}

const footerCopyrightText = {
  ...paragraph,
  fontSize: '12px',
  textAlign: 'center' as const,
  margin: 0
}
