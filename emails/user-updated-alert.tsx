import { Button, Heading, Section, Text, Hr } from '@react-email/components'
import * as React from 'react'
import EmailLayout from './components/email-layout'
import { buttonContainer, button } from './components/style'

export interface UserUpdatedAlertProps {
  userName: string
  title: string
  greeting: string
  mainMessage: string
  secondaryMessage?: string
  buttonText: string
  buttonUrl: string
  userInfo: {
    email: string
    firstName?: string
    lastName?: string
    phoneNumber?: string
    role?: string
  }
  changedFields: Array<{
    field: string
    oldValue: string
    newValue: string
  }>
  adminInfo: {
    adminName: string
    adminEmail: string
    updatedAt: string
    ipAddress?: string
    userAgent?: string
  }
  lang?: 'vi' | 'en'
}

export const UserUpdatedAlert = ({
  title,
  greeting,
  mainMessage,
  secondaryMessage,
  buttonText,
  buttonUrl,
  userInfo,
  changedFields,
  adminInfo
}: UserUpdatedAlertProps) => {
  const previewText = `User Account Updated: ${userInfo.email}`

  return (
    <EmailLayout previewText={previewText}>
      <Section style={content}>
        <Heading as='h2' style={titleStyle}>
          {title}
        </Heading>
        <Text style={paragraph}>{greeting}</Text>
        <Text style={paragraph}>{mainMessage}</Text>

        {/* User Information */}
        <Section style={infoBox}>
          <Heading as='h3' style={sectionTitle}>
            User Details
          </Heading>
          <Text style={infoItem}>
            <strong>Email:</strong> {userInfo.email}
          </Text>
          {userInfo.firstName && (
            <Text style={infoItem}>
              <strong>Name:</strong> {userInfo.firstName} {userInfo.lastName || ''}
            </Text>
          )}
          {userInfo.phoneNumber && (
            <Text style={infoItem}>
              <strong>Phone:</strong> {userInfo.phoneNumber}
            </Text>
          )}
          {userInfo.role && (
            <Text style={infoItem}>
              <strong>Role:</strong> {userInfo.role}
            </Text>
          )}
        </Section>

        <Hr style={separator} />

        {/* Changed Fields */}
        <Section style={changesBox}>
          <Heading as='h3' style={sectionTitle}>
            Fields Changed
          </Heading>
          {changedFields.map((change, index) => (
            <Section key={index} style={changeItem}>
              <Text style={fieldName}>
                <strong>{change.field}:</strong>
              </Text>
              <Text style={changeValue}>
                From: <span style={oldValue}>"{change.oldValue}"</span>
              </Text>
              <Text style={changeValue}>
                To: <span style={newValue}>"{change.newValue}"</span>
              </Text>
            </Section>
          ))}
        </Section>

        <Hr style={separator} />

        {/* Admin Action Information */}
        <Section style={infoBox}>
          <Heading as='h3' style={sectionTitle}>
            Administrative Action Details
          </Heading>
          <Text style={infoItem}>
            <strong>Updated by:</strong> {adminInfo.adminName} ({adminInfo.adminEmail})
          </Text>
          <Text style={infoItem}>
            <strong>Updated at:</strong> {adminInfo.updatedAt}
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

export default UserUpdatedAlert

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

const changesBox = {
  backgroundColor: '#fff3cd',
  padding: '20px',
  borderRadius: '8px',
  margin: '20px 0',
  border: '1px solid #ffeaa7'
}

const changeItem = {
  margin: '15px 0',
  padding: '10px',
  backgroundColor: '#ffffff',
  borderRadius: '4px',
  borderLeft: '4px solid #f39c12'
}

const fieldName = {
  fontSize: '15px',
  fontWeight: 'bold',
  color: '#2c3e50',
  margin: '5px 0'
}

const changeValue = {
  fontSize: '14px',
  margin: '3px 0',
  color: '#495057'
}

const oldValue = {
  backgroundColor: '#ffebee',
  color: '#c62828',
  padding: '2px 4px',
  borderRadius: '3px'
}

const newValue = {
  backgroundColor: '#e8f5e8',
  color: '#2e7d32',
  padding: '2px 4px',
  borderRadius: '3px'
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
