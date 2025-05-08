import { createRoot } from 'react-dom/client'
import './index.css'
import { BrowserRouter, Route, Routes } from 'react-router'
import Layout from './Layout.tsx'
import Login from './Login.tsx'
import Home from './Home.tsx'
import Oauth from './Oauth.tsx'
import UploadPage from './UploadPage.tsx'

createRoot(document.getElementById('root')!).render(
  <BrowserRouter>
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path='login' element={<Login />} />
        <Route path='upload' element={<UploadPage />} />
        <Route path='oauth-google-callback' element={<Oauth />} />
      </Route>
    </Routes>
  </BrowserRouter>
)
