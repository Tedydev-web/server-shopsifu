import { Outlet } from 'react-router'
import http from './http'

export default function Layout() {
  const isLogged = localStorage.getItem('accessToken') !== null
  const handleLogout = async () => {
    try {
      await http.post('/auth/logout', {
        refreshToken: localStorage.getItem('refreshToken')
      })
      localStorage.removeItem('accessToken')
      localStorage.removeItem('refreshToken')
      window.location.href = '/login'
    } catch (error) {
      console.error(error)
    }
  }

  return (
    <div>
      <header>
        <nav>
          <ul>
            <li>
              <a href='/'>Trang chủ</a>
            </li>
            <li>
              <a href='/login'>Đăng nhập</a>
            </li>
            <li>
              <a href='/upload'>Upload</a>
            </li>
            {isLogged && (
              <li>
                <button onClick={handleLogout}>Đăng xuất</button>
              </li>
            )}
          </ul>
        </nav>
      </header>

      <main>
        <Outlet />
      </main>
    </div>
  )
}
