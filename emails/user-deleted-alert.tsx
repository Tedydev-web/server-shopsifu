import { Button, Heading, Section, Text, Hr } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

export interface UserDeletedAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage?: string
  buttonText: string
  buttonUrl: string
  deletedUserInfo: {
    email: string
    firstName?: string
    lastName?: string
    phoneNumber?: string
    role?: string
    userId: string
    accountCreatedAt?: string
  }
  adminInfo: {
    adminName: string
    adminEmail: string
    deletedAt: string
    ipAddress?: string
    userAgent?: string
  }
  isDangerous?: boolean
  lang?: 'vi' | 'en'
}

export const UserDeletedAlert = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  deletedUserInfo,
  adminInfo,
  isDangerous = true
}: UserDeletedAlertProps) => {
  const previewText = `User Account Deleted: ${deletedUserInfo.email}`

  return (
    <EmailLayout previewText={previewText}>
      <Section style={content}>
        <Heading as='h2' style={isDangerous ? dangerTitleStyle : titleStyle}>
          {title}
        </Heading>
        <Text style={paragraph}>{greeting}</Text>
        <Text style={paragraph}>{mainMessage}</Text>

        {/* Critical Action Warning */}
        {isDangerous && (
          <Section style={warningBox}>
            <Text style={warningIcon}>⚠️</Text>
            <Text style={criticalWarning}>CRITICAL ACTION: This is a permanent deletion and cannot be undone.</Text>
          </Section>
        )}

        {/* Deleted User Information */}
        <Section style={deletedUserBox}>
          <Heading as='h3' style={sectionTitle}>
            Deleted User Details
          </Heading>
          <Text style={infoItem}>
            <strong>User ID:</strong> {deletedUserInfo.userId}
          </Text>
          <Text style={infoItem}>
            <strong>Email:</strong> {deletedUserInfo.email}
          </Text>
          {deletedUserInfo.firstName && (
            <Text style={infoItem}>
              <strong>Name:</strong> {deletedUserInfo.firstName} {deletedUserInfo.lastName || ''}
            </Text>
          )}
          {deletedUserInfo.phoneNumber && (
            <Text style={infoItem}>
              <strong>Phone:</strong> {deletedUserInfo.phoneNumber}
            </Text>
          )}
          {deletedUserInfo.role && (
            <Text style={infoItem}>
              <strong>Role:</strong> {deletedUserInfo.role}
            </Text>
          )}
          {deletedUserInfo.accountCreatedAt && (
            <Text style={infoItem}>
              <strong>Account Created:</strong> {deletedUserInfo.accountCreatedAt}
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
            <strong>Deleted by:</strong> {adminInfo.adminName} ({adminInfo.adminEmail})
          </Text>
          <Text style={infoItem}>
            <strong>Deleted at:</strong> {adminInfo.deletedAt}
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

export default UserDeletedAlert

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

const dangerTitleStyle = {
  fontSize: '24px',
  fontWeight: 'bold',
  textAlign: 'center' as const,
  margin: '30px 0',
  color: '#dc3545'
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

const deletedUserBox = {
  backgroundColor: '#ffebee',
  padding: '20px',
  borderRadius: '8px',
  margin: '20px 0',
  border: '2px solid #f44336'
}

const warningBox = {
  backgroundColor: '#fff3e0',
  padding: '20px',
  borderRadius: '8px',
  margin: '20px 0',
  border: '2px solid #ff9800',
  textAlign: 'center' as const
}

const warningIcon = {
  fontSize: '32px',
  margin: '0 0 10px 0'
}

const criticalWarning = {
  fontSize: '16px',
  fontWeight: 'bold',
  color: '#e65100',
  margin: '0'
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
