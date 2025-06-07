const buttonContainer = {
  textAlign: 'center' as const,
  marginBottom: '20px'
}

const button = {
  backgroundColor: '#e00707',
  borderRadius: 3,
  color: '#FFF',
  fontWeight: 'bold',
  border: '1px solid rgb(0,0,0, 0.1)',
  cursor: 'pointer',
  display: 'inline-block',
  padding: '12px 30px',
  textDecoration: 'none'
}

const tableRow = {
  padding: '8px 0'
}

const tableCellLabel = {
  fontWeight: 'bold' as const,
  color: '#475569',
  width: '120px',
  fontSize: '14px'
}

const tableCellValue = {
  color: '#1e293b',
  fontSize: '14px'
}

const detailsTableContainer = {
  borderRadius: '8px',
  padding: '16px',
  margin: '16px 0',
  backgroundColor: 'transparent'
}

const hr = {
  borderColor: '#e6ebf1',
  margin: '20px 0'
}

const heading = {
  fontSize: '28px',
  fontWeight: '600',
  textAlign: 'center' as const,
  color: '#d0201c',
  margin: '30px 0'
}

const paragraph = {
  fontSize: '16px',
  lineHeight: '26px',
  color: '#3c4043'
}

export {
  buttonContainer,
  button,
  detailsTableContainer,
  tableRow,
  tableCellLabel,
  tableCellValue,
  hr,
  heading,
  paragraph
}
