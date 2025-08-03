import { registerAs } from '@nestjs/config'

export default registerAs('elasticsearch', () => ({
  node: process.env.ELASTICSEARCH_NODE || 'http://localhost:9200',
  apiKey: process.env.ELASTICSEARCH_API_KEY,
  index: {
    products: process.env.ELASTICSEARCH_INDEX_PRODUCTS || 'products_v1'
  },
  connection: {
    timeout: 30000,
    maxRetries: 3,
    requestTimeout: 30000
  }
}))
