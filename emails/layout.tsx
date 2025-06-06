import { Body, Container, Head, Html, Img, Section, Tailwind, Link, Row, Column, Text } from '@react-email/components'
import React from 'react'

interface EmailLayoutProps {
  title: string
  preview: string
  lang: 'vi' | 'en'
  children: React.ReactNode
}

const APP_URL = process.env.APP_URL || 'https://shopsifu.com'
const CDN_URL = 'https://res.cloudinary.com/tedydev/image/upload/v1746547380/shopsifu'

const I18N = {
  vi: {
    contactUs: 'Liên hệ với chúng tôi',
    copyright: `© ${new Date().getFullYear()} Bản quyền thuộc về Shopsifu`
  },
  en: {
    contactUs: 'Contact Us',
    copyright: `© ${new Date().getFullYear()} Shopsifu. All Rights Reserved.`
  }
}

export default function EmailLayout({ title, preview, lang, children }: EmailLayoutProps) {
  const t = I18N[lang]

  return (
    <Html lang={lang} dir='ltr'>
      <Head>
        <title>{title}</title>
      </Head>
      <Body style={main}>
        <Tailwind>
          <Container style={container}>
            <Section style={headerSection}>
              <Link href={APP_URL}>
                <Img src={`${CDN_URL}/white-logo.png`} width='120' height='120' alt='Shopsifu Logo' />
              </Link>
            </Section>

            {children}

            <Section style={footerSection}>
              <Section style={footerContactSection}>
                <Text style={contactText}>{t.contactUs}</Text>
                <Row
                  align='left'
                  style={{
                    width: '84px'
                  }}
                >
                  <Column style={{ paddingRight: '8px' }}>
                    <Link href='https://facebook.com/shopsifu'>
                      <Img
                        width='28'
                        height='28'
                        src={`https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/facebook.png`}
                      />
                    </Link>
                  </Column>
                  <Column style={{ paddingRight: '8px' }}>
                    <Link href='https://t.me/shopsifu'>
                      <Img
                        width='28'
                        height='28'
                        src={`https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/telegram.png`}
                      />
                    </Link>
                  </Column>
                  <Column>
                    <Link href='https://zalo.me/shopsifu'>
                      <Img
                        width='28'
                        height='28'
                        src={`https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/zalo.png`}
                      />
                    </Link>
                  </Column>
                </Row>
              </Section>
              <Section>
                <Link href={`${APP_URL}/download`}>
                  <Img
                    style={footerDownloadImage}
                    src={`${CDN_URL}/google-play-footer.png`}
                    width='540'
                    height='48'
                    alt='Download on Google Play'
                  />
                </Link>
              </Section>
              <Section style={footerCopyrightSection}>
                <Text style={copyrightText}>{t.copyright}</Text>
              </Section>
            </Section>
          </Container>
        </Tailwind>
      </Body>
    </Html>
  )
}

const main = {
  backgroundColor: '#f0f0f0',
  color: '#212121',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif"
}

const container = {
  padding: '0',
  margin: '20px auto',
  backgroundColor: '#ffffff',
  border: '1px solid #e0e0e0',
  borderRadius: '8px',
  overflow: 'hidden',
  maxWidth: '600px'
}

const headerSection = {
  backgroundColor: '#d0201c',
  padding: '20px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center'
}

const footerSection = {
  backgroundColor: '#f7f7f7',
  padding: '20px 40px'
}

const footerContactSection = {
  paddingBottom: '20px'
}

const contactText = {
  fontSize: '14px',
  lineHeight: '22px',
  color: '#3c4043',
  margin: '0 0 10px 0'
}

const footerDownloadImage = {
  maxWidth: '100%',
  height: 'auto'
}

const footerCopyrightSection = {
  paddingTop: '20px',
  borderTop: '1px solid #e0e0e0'
}

const copyrightText = {
  fontSize: '12px',
  textAlign: 'center' as const,
  margin: '0',
  color: '#666666'
}
