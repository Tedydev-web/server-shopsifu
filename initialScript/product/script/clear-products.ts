import { PrismaService } from 'src/shared/services/prisma.service'

const prisma = new PrismaService()

async function clearProducts() {
  try {
    console.log('🗑️  Starting to clear all products...')

    // Xóa ProductTranslations trước
    const deletedTranslations = await prisma.productTranslation.deleteMany({})
    console.log(`🗑️  Deleted ${deletedTranslations.count} product translations`)

    // Xóa SKUs
    const deletedSKUs = await prisma.sKU.deleteMany({})
    console.log(`🗑️  Deleted ${deletedSKUs.count} SKUs`)

    // Xóa Reviews
    const deletedReviews = await prisma.review.deleteMany({})
    console.log(`🗑️  Deleted ${deletedReviews.count} reviews`)

    // Xóa CartItems
    const deletedCartItems = await prisma.cartItem.deleteMany({})
    console.log(`🗑️  Deleted ${deletedCartItems.count} cart items`)

    // Xóa Products
    const deletedProducts = await prisma.product.deleteMany({})
    console.log(`🗑️  Deleted ${deletedProducts.count} products`)

    // Xóa unused Brands
    const unusedBrands = await prisma.brand.deleteMany({
      where: {
        products: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedBrands.count} unused brands`)

    // Xóa unused Categories (chỉ categories không có products)
    const unusedCategories = await prisma.category.deleteMany({
      where: {
        products: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedCategories.count} unused categories`)

    console.log('✅ Successfully cleared all products and related data!')
  } catch (error) {
    console.error('❌ Error clearing products:', error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

// Chạy script
if (require.main === module) {
  clearProducts()
    .then(() => {
      console.log('✅ Product clearing completed successfully!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('❌ Product clearing failed:', error)
      process.exit(1)
    })
}

export { clearProducts }
