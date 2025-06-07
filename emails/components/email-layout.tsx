import { Body, Container, Head, Hr, Html, Img, Preview, Row, Section, Text } from '@react-email/components'
import * as React from 'react'

interface EmailLayoutProps {
  previewText: string
  children: React.ReactNode
}

const baseUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : ''

export const EmailLayout = ({ previewText, children }: EmailLayoutProps) => {
  return (
    <Html>
      <Head />
      <Preview>{previewText}</Preview>
      <Body style={main}>
        <Container style={container}>
          <Section style={logo}>
            <Img
              src={`https://res.cloudinary.com/tedydev/image/upload/v1749290219/shopsifu/zsntmcfhzrl87hn1bete.png`}
              alt='Logo Shopsifu'
              width={150}
            />
          </Section>
          <Section style={content}>
            <Row>
              <Img
                style={image}
                width={620}
                src={`https://react-email-demo-4nuiv9xxi-resend.vercel.app/static/yelp-header.png`}
                alt='OTP verification header'
              />
            </Row>
            {children}
            <Section style={footer}>
              <Img
                style={image}
                width={620}
                src={`https://react-email-demo-4nuiv9xxi-resend.vercel.app/static/yelp-footer.png`}
                alt='Footer decoration'
              />
            </Section>
            <Text
              style={{
                textAlign: 'center',
                fontSize: 12,
                color: 'rgb(0,0,0, 0.7)',
                textDecoration: 'underline'
              }}
            >
              © 2025 | Shopsifu, Việt Nam | www.shopsifu.live
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  )
}

export default EmailLayout

const main = {
  backgroundColor: '#f6f9fc',
  fontFamily:
    '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif'
}

const container = {
  backgroundColor: '#ffffff',
  margin: '0 auto',
  borderRadius: '5px',
  overflow: 'hidden'
}

const logo = {
  margin: '0 auto',
  textAlign: 'center' as const,
  padding: '20px'
}

const hr = {
  borderColor: '#e6ebf1',
  margin: '20px 0'
}

const footer = {
  padding: '20px 0 0 0'
}

const image = {
  maxWidth: '100%'
}

const content = {
  border: '1px solid rgb(0,0,0, 0.1)',
  borderRadius: '3px',
  overflow: 'hidden'
}
