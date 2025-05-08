import { useState } from 'react'
import http from './http'

const Login = () => {
  const [error, setError] = useState<string | null>(null)

  const handleGoogleLogin = async () => {
    try {
      const response = await http.get('/auth/google-link')
      // Redirect to Google auth page
      window.location.href = response.data.url
    } catch {
      setError('Failed to initiate Google login')
    }
  }

  return (
    <div className='login-container'>
      <h1>Login</h1>
      {error && <div className='error'>{error}</div>}
      <button className='google-login-button' onClick={handleGoogleLogin}>
        Đăng nhập với Google
      </button>
    </div>
  )
}

export default Login
