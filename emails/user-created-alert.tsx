import { Button, Heading, Section, Text, Hr } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

export interface UserCreatedAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage?: string
  buttonText: string
  buttonUrl: string
  newUserInfo: {
    email: string
    firstName?: string
    lastName?: string
    phoneNumber?: string
    role?: string
  }
  adminInfo: {
    adminName: string
    adminEmail: string
    createdAt: string
    ipAddress?: string
    userAgent?: string
  }
  lang?: 'vi' | 'en'
}

export const UserCreatedAlert = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  newUserInfo,
  adminInfo
}: UserCreatedAlertProps) => {
  const previewText = `User Account Created: ${newUserInfo.email}`

  return (
    <EmailLayout previewText={previewText}>
      <Section style={content}>
        <Heading as='h2' style={titleStyle}>
          {title}
        </Heading>
        <Text style={paragraph}>{greeting}</Text>
        <Text style={paragraph}>{mainMessage}</Text>

        {/* New User Information */}
        <Section style={infoBox}>
          <Heading as='h3' style={sectionTitle}>
            User Details
          </Heading>
          <Text style={infoItem}>
            <strong>Email:</strong> {newUserInfo.email}
          </Text>
          {newUserInfo.firstName && (
            <Text style={infoItem}>
              <strong>Name:</strong> {newUserInfo.firstName} {newUserInfo.lastName || ''}
            </Text>
          )}
          {newUserInfo.phoneNumber && (
            <Text style={infoItem}>
              <strong>Phone:</strong> {newUserInfo.phoneNumber}
            </Text>
          )}
          {newUserInfo.role && (
            <Text style={infoItem}>
              <strong>Role:</strong> {newUserInfo.role}
            </Text>
          )}
        </Section>

        <Hr style={separator} />

        {/* Admin Action Information */}
        <Section style={infoBox}>
          <Heading as='h3' style={sectionTitle}>
            Administrative Action Details
          </Heading>
          <Text style={infoItem}>
            <strong>Created by:</strong> {adminInfo.adminName} ({adminInfo.adminEmail})
          </Text>
          <Text style={infoItem}>
            <strong>Created at:</strong> {adminInfo.createdAt}
          </Text>
          {adminInfo.ipAddress && (
            <Text style={infoItem}>
              <strong>IP Address:</strong> {adminInfo.ipAddress}
            </Text>
          )}
          {adminInfo.userAgent && (
            <Text style={infoItem}>
              <strong>User Agent:</strong> {adminInfo.userAgent}
            </Text>
          )}
        </Section>

        {secondaryMessage && <Text style={warningText}>{secondaryMessage}</Text>}

        <Section style={buttonContainer}>
          <Button style={button} href={buttonUrl}>
            {buttonText}
          </Button>
        </Section>
      </Section>
    </EmailLayout>
  )
}

export default UserCreatedAlert

const content = {
  padding: '0 20px'
}

const titleStyle = {
  fontSize: '24px',
  fontWeight: 'bold',
  textAlign: 'center' as const,
  margin: '30px 0',
  color: '#2c3e50'
}

const paragraph = {
  fontSize: '16px',
  lineHeight: '26px',
  color: '#3c4043'
}

const sectionTitle = {
  fontSize: '18px',
  fontWeight: 'bold',
  color: '#2c3e50',
  margin: '10px 0'
}

const infoBox = {
  backgroundColor: '#f8f9fa',
  padding: '20px',
  borderRadius: '8px',
  margin: '20px 0'
}

const infoItem = {
  fontSize: '14px',
  margin: '8px 0',
  color: '#495057'
}

const separator = {
  margin: '20px 0',
  borderColor: '#e9ecef'
}

const warningText = {
  fontSize: '16px',
  lineHeight: '26px',
  color: '#dc3545',
  fontWeight: 'bold',
  margin: '20px 0'
}
