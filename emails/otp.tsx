import {
  Body,
  Container,
  Head,
  Heading,
  Hr,
  Html,
  Img,
  Preview,
  Section,
  Text,
  Tailwind,
  Link,
  Row,
  Column
} from '@react-email/components'

import React from 'react'

interface OTPEmailProps {
  otpCode: string
  title: string
}

export default function OTPEmail({ otpCode, title }: OTPEmailProps) {
  return (
    <Html>
      <Head>
        <title>{title}</title>
      </Head>
      <Body style={main}>
        <Preview>Mã xác minh có hiệu lực trong 5 phút</Preview>
        <Tailwind>
          <Container style={container}>
            <Section style={coverSection}>
              <Section style={imageSection}>
                <Img
                  src={`https://res.cloudinary.com/tedydev/image/upload/v1746547380/shopsifu/white-logo.png`}
                  width='120'
                  height='120'
                  alt='Logo Shopsifu'
                />
              </Section>
              <Section style={upperSection}>
                <Heading style={h1}>Xác minh địa chỉ email của bạn</Heading>
                <Text style={mainText}>
                  Cảm ơn bạn đã bắt đầu quá trình tạo tài khoản mới trên Shopsifu. Chúng tôi muốn đảm bảo rằng đó thực
                  sự là bạn. Vui lòng nhập mã xác minh sau khi được yêu cầu. Nếu bạn không muốn tạo tài khoản, bạn có
                  thể bỏ qua tin nhắn này.
                </Text>
              </Section>
              <Section style={verificationSection}>
                <Text style={verifyText}>Mã xác minh</Text>
                <Text style={codeText}>{otpCode}</Text>
                <Text style={validityText}>(Mã này có hiệu lực trong 5 phút)</Text>
              </Section>
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
                <Row
                  align='left'
                  style={{
                    width: '84px',
                    float: 'left'
                  }}
                >
                  <Column style={{ paddingRight: '4px' }}>
                    <Link href='https://notifications.google.com'>
                      <Img
                        width='28'
                        height='28'
                        src={`https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/facebook.png`}
                      />
                    </Link>
                  </Column>
                  <Column style={{ paddingRight: '4px' }}>
                    <Link href='https://notifications.google.com'>
                      <Img
                        width='28'
                        height='28'
                        src={`https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/telegram.png`}
                      />
                    </Link>
                  </Column>
                  <Column style={{ paddingRight: '4px' }}>
                    <Link href='https://notifications.google.com'>
                      <Img
                        width='28'
                        height='28'
                        src={`https://res.cloudinary.com/tedydev/image/upload/v1728706753/nphdigital/zalo.png`}
                      />
                    </Link>
                  </Column>
                </Row>
                <Row>
                  <Img
                    style={footer}
                    width='540'
                    height='48'
                    src={`https://res.cloudinary.com/tedydev/image/upload/v1746551514/shopsifu/google-play-footer.png`}
                  />
                </Row>
              </Section>
              <Section style={{ ...paragraphContent, paddingBottom: 30 }}>
                <Text
                  style={{
                    ...paragraph,
                    fontSize: '12px',
                    textAlign: 'center',
                    margin: 0
                  }}
                >
                  © 2025 Bản quyền thuộc về Shopsifu
                </Text>
              </Section>
            </Section>
          </Container>
        </Tailwind>
      </Body>
    </Html>
  )
}

// OTPEmail.PreviewProps = {
//   code: '{{code}}'
// } satisfies OTPEmail

const main = {
  backgroundColor: '#fff',
  color: '#212121'
}

const container = {
  padding: '20px',
  margin: '0 auto'
}

const h1 = {
  color: '#333',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: '20px',
  fontWeight: 'bold',
  marginBottom: '15px'
}

const text = {
  color: '#333',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: '14px',
  margin: '24px 0'
}

const imageSection = {
  backgroundColor: '#d0201c',
  display: 'flex',
  // padding: '20px 0',
  alignItems: 'center',
  justifyContent: 'center'
}

const coverSection = {
  // backgroundImage: 'url("https://res.cloudinary.com/tedydev/image/upload/v1746548458/shopsifu/bg.png")',
  // backgroundPosition: 'bottom',
  // backgroundRepeat: 'no-repeat, no-repeat'
}

const upperSection = { padding: '25px 35px' }

const lowerSection = { padding: '25px 35px' }

const verifyText = {
  ...text,
  margin: 0,
  fontWeight: 'bold',
  textAlign: 'center' as const
}

const codeText = {
  ...text,
  fontWeight: 'bold',
  fontSize: '36px',
  margin: '10px 0',
  textAlign: 'center' as const
}

const validityText = {
  ...text,
  margin: '0px',
  textAlign: 'center' as const
}

const verificationSection = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center'
}

const mainText = { ...text, marginBottom: '14px' }

const cautionText = { ...text, margin: '0px' }

const paragraph = {
  fontSize: '14px',
  lineHeight: '22px',
  color: '#3c4043'
}

const paragraphContent = {
  padding: '0 40px'
}

const containerContact = {
  backgroundColor: 'rgba(188, 188, 188, 0.67)',
  width: '90%',
  borderRadius: '5px',
  overflow: 'hidden',
  paddingLeft: '20px'
}

const footer = {
  maxWidth: '100%'
}

const hr = {
  borderColor: '#e8eaed',
  margin: '20px 0'
}
