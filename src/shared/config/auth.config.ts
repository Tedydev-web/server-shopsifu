import { registerAs } from '@nestjs/config'

export default registerAs(
  'auth',
  (): Record<string, any> => ({
    accessToken: {
      secret: process.env.AUTH_ACCESS_TOKEN_SECRET,
      tokenExp: process.env.AUTH_ACCESS_TOKEN_EXP
    },
    refreshToken: {
      secret: process.env.AUTH_REFRESH_TOKEN_SECRET,
      tokenExp: process.env.AUTH_REFRESH_TOKEN_EXP
    },
    otp: {
      expiresIn: process.env.AUTH_OTP_EXP
    },
    google: {
      client: {
        id: process.env.GOOGLE_CLIENT_ID,
        secret: process.env.GOOGLE_CLIENT_SECRET,
        // redirectUri: nơi client frontend sẽ được redirect sau khi đặt cookie thành công
        // Ưu tiên GOOGLE_CLIENT_REDIRECT_URI, fallback GOOGLE_REDIRECT_URI nếu thiếu
        redirectUri: process.env.GOOGLE_CLIENT_REDIRECT_URI || process.env.GOOGLE_REDIRECT_URI,
        // redirectUriGoogleCallback: callback của Google OAuth về API
        // Ưu tiên GOOGLE_REDIRECT_URI_GOOGLE_CALLBACK, fallback GOOGLE_REDIRECT_URI
        redirectUriGoogleCallback: process.env.GOOGLE_REDIRECT_URI_GOOGLE_CALLBACK || process.env.GOOGLE_REDIRECT_URI
      }
    }
  })
)
