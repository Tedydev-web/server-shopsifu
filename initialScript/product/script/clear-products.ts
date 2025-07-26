import { PrismaService } from 'src/shared/services/prisma.service'

const prisma = new PrismaService()

async function clearProducts() {
  try {
    console.log('🗑️  Starting to clear all products and related data...')

    // 1. Xóa ReviewMedia trước (vì nó reference đến Review)
    const deletedReviewMedia = await prisma.reviewMedia.deleteMany({})
    console.log(`🗑️  Deleted ${deletedReviewMedia.count} review media`)

    // 2. Xóa Reviews
    const deletedReviews = await prisma.review.deleteMany({})
    console.log(`🗑️  Deleted ${deletedReviews.count} reviews`)

    // 3. Xóa ProductTranslations
    const deletedTranslations = await prisma.productTranslation.deleteMany({})
    console.log(`🗑️  Deleted ${deletedTranslations.count} product translations`)

    // 4. Xóa ProductSKUSnapshots (nếu có)
    const deletedProductSKUSnapshots = await prisma.productSKUSnapshot.deleteMany({})
    console.log(`🗑️  Deleted ${deletedProductSKUSnapshots.count} product SKU snapshots`)

    // 5. Xóa SKUs
    const deletedSKUs = await prisma.sKU.deleteMany({})
    console.log(`🗑️  Deleted ${deletedSKUs.count} SKUs`)

    // 6. Xóa CartItems
    const deletedCartItems = await prisma.cartItem.deleteMany({})
    console.log(`🗑️  Deleted ${deletedCartItems.count} cart items`)

    // 7. Xóa DiscountSnapshots liên quan đến products
    const deletedDiscountSnapshots = await prisma.discountSnapshot.deleteMany({})
    console.log(`🗑️  Deleted ${deletedDiscountSnapshots.count} discount snapshots`)

    // 8. Xóa Orders liên quan đến products (fake orders cho reviews)
    const deletedOrders = await prisma.order.deleteMany({
      where: {
        items: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedOrders.count} empty orders`)

    // 9. Xóa Payments không có orders
    const deletedPayments = await prisma.payment.deleteMany({
      where: {
        orders: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedPayments.count} orphaned payments`)

    // 10. Xóa Products
    const deletedProducts = await prisma.product.deleteMany({})
    console.log(`🗑️  Deleted ${deletedProducts.count} products`)

    // 11. Xóa BrandTranslations
    const deletedBrandTranslations = await prisma.brandTranslation.deleteMany({})
    console.log(`🗑️  Deleted ${deletedBrandTranslations.count} brand translations`)

    // 12. Xóa unused Brands
    const unusedBrands = await prisma.brand.deleteMany({
      where: {
        products: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedBrands.count} unused brands`)

    // 13. Xóa CategoryTranslations
    const deletedCategoryTranslations = await prisma.categoryTranslation.deleteMany({})
    console.log(`🗑️  Deleted ${deletedCategoryTranslations.count} category translations`)

    // 14. Xóa unused Categories (chỉ categories không có products)
    const unusedCategories = await prisma.category.deleteMany({
      where: {
        products: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedCategories.count} unused categories`)

    // 15. Xóa unused Users (sellers và customers được tạo cho products)
    const unusedUsers = await prisma.user.deleteMany({
      where: {
        AND: [
          {
            OR: [{ role: { name: 'SELLER' } }, { role: { name: 'CLIENT' } }]
          },
          {
            OR: [
              { createdProducts: { none: {} } }, // Sellers không có products
              { reviews: { none: {} } } // Clients không có reviews
            ]
          }
        ]
      }
    })
    console.log(`🗑️  Deleted ${unusedUsers.count} unused users (sellers/clients)`)

    // 16. Xóa unused Addresses
    const unusedAddresses = await prisma.address.deleteMany({
      where: {
        userAddress: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedAddresses.count} unused addresses`)

    console.log('✅ Successfully cleared all products and related data!')

    // Hiển thị thống kê cuối cùng
    const remainingProducts = await prisma.product.count()
    const remainingReviews = await prisma.review.count()
    const remainingSKUs = await prisma.sKU.count()
    const remainingBrands = await prisma.brand.count()
    const remainingCategories = await prisma.category.count()

    console.log('\n📊 Final statistics:')
    console.log(`• Products: ${remainingProducts}`)
    console.log(`• Reviews: ${remainingReviews}`)
    console.log(`• SKUs: ${remainingSKUs}`)
    console.log(`• Brands: ${remainingBrands}`)
    console.log(`• Categories: ${remainingCategories}`)
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
