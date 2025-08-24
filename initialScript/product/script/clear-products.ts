import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function clearProducts() {
  try {
    await prisma.$connect()
    console.log('🗑️  Starting to clear imported products and related data...')

    // Tìm creator user (user được sử dụng để import)
    const creatorUser = await prisma.user.findFirst({
      where: { role: { name: 'ADMIN' } },
      orderBy: { createdAt: 'desc' }
    })

    if (!creatorUser) {
      console.log('⚠️  No admin user found, clearing all data...')
      return clearAllData()
    }

    console.log(`🎯 Clearing data imported by user: ${creatorUser.name} (${creatorUser.id})`)

    // 1. Xóa ReviewMedia của reviews được import
    const deletedReviewMedia = await prisma.reviewMedia.deleteMany({
      where: {
        review: {
          product: {
            createdById: creatorUser.id
          }
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedReviewMedia.count} review media`)

    // 2. Xóa Reviews của products được import
    const deletedReviews = await prisma.review.deleteMany({
      where: {
        product: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedReviews.count} reviews`)

    // 3. Xóa ProductTranslations của products được import
    const deletedTranslations = await prisma.productTranslation.deleteMany({
      where: {
        product: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedTranslations.count} product translations`)

    // 4. Xóa ProductSKUSnapshots của products được import
    const deletedProductSKUSnapshots = await prisma.productSKUSnapshot.deleteMany({
      where: {
        product: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedProductSKUSnapshots.count} product SKU snapshots`)

    // 5. Xóa SKUs của products được import
    const deletedSKUs = await prisma.sKU.deleteMany({
      where: {
        product: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedSKUs.count} SKUs`)

    // 6. Xóa CartItems của products được import
    const deletedCartItems = await prisma.cartItem.deleteMany({
      where: {
        sku: {
          product: {
            createdById: creatorUser.id
          }
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedCartItems.count} cart items`)

    // 7. Xóa DiscountSnapshots của orders được import
    const deletedDiscountSnapshots = await prisma.discountSnapshot.deleteMany({
      where: {
        order: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedDiscountSnapshots.count} discount snapshots`)

    // 8. Xóa Orders được tạo cho reviews (fake orders)
    const deletedOrders = await prisma.order.deleteMany({
      where: {
        createdById: creatorUser.id,
        items: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedOrders.count} fake orders`)

    // 9. Xóa Payments không có orders
    const deletedPayments = await prisma.payment.deleteMany({
      where: {
        orders: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedPayments.count} orphaned payments`)

    // 10. Xóa Products được import
    const deletedProducts = await prisma.product.deleteMany({
      where: {
        createdById: creatorUser.id
      }
    })
    console.log(`🗑️  Deleted ${deletedProducts.count} products`)

    // 11. Xóa BrandTranslations của brands được import
    const deletedBrandTranslations = await prisma.brandTranslation.deleteMany({
      where: {
        brand: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedBrandTranslations.count} brand translations`)

    // 12. Xóa unused Brands (chỉ những brands được tạo bởi import script)
    const unusedBrands = await prisma.brand.deleteMany({
      where: {
        createdById: creatorUser.id,
        products: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedBrands.count} unused brands`)

    // 13. Xóa CategoryTranslations của categories được import
    const deletedCategoryTranslations = await prisma.categoryTranslation.deleteMany({
      where: {
        category: {
          createdById: creatorUser.id
        }
      }
    })
    console.log(`🗑️  Deleted ${deletedCategoryTranslations.count} category translations`)

    // 14. Xóa unused Categories (chỉ những categories được tạo bởi import script)
    const unusedCategories = await prisma.category.deleteMany({
      where: {
        createdById: creatorUser.id,
        products: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedCategories.count} unused categories`)

    // 15. Xóa ALL Orders trước khi xóa Users (để tránh foreign key constraint)
    const remainingOrders = await prisma.order.deleteMany({})
    console.log(`🗑️  Deleted ${remainingOrders.count} remaining orders`)

    // 16. Xóa unused Users (sellers và customers được tạo cho products)
    const unusedUsers = await prisma.user.deleteMany({
      where: {
        createdById: creatorUser.id,
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

    // 17. Xóa unused Addresses được tạo cho users
    const unusedAddresses = await prisma.address.deleteMany({
      where: {
        createdById: creatorUser.id,
        userAddress: {
          none: {}
        }
      }
    })
    console.log(`🗑️  Deleted ${unusedAddresses.count} unused addresses`)

    // 18. Xóa Discounts được import (vouchers)
    const deletedDiscounts = await prisma.discount.deleteMany({
      where: {
        createdById: creatorUser.id
      }
    })
    console.log(`🗑️  Deleted ${deletedDiscounts.count} discounts/vouchers`)

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

    // 19. Clear cache để đảm bảo dữ liệu mới được load
    console.log('\n🧹 Clearing application cache...')
    try {
      const cacheFlushUrl = process.env.APP_URL || 'http://localhost:3000'
      const response = await fetch(`${cacheFlushUrl}/health/cache/flush`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const result = await response.json()
        console.log(`✅ Cache cleared successfully: ${result.message}`)
      } else {
        console.warn(`⚠️  Cache clear failed with status: ${response.status}`)
      }
    } catch (error) {
      console.warn(`⚠️  Could not clear cache: ${error.message}`)
      console.log('💡 Cache will be cleared automatically on next request or restart')
    }
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

// Function để clear tất cả data (fallback)
async function clearAllData() {
  console.log('🗑️  Clearing ALL data (fallback mode)...')

  // Xóa tất cả data theo thứ tự an toàn
  await prisma.reviewMedia.deleteMany({})
  await prisma.review.deleteMany({})
  await prisma.productTranslation.deleteMany({})
  await prisma.productSKUSnapshot.deleteMany({})
  await prisma.sKU.deleteMany({})
  await prisma.cartItem.deleteMany({})
  await prisma.discountSnapshot.deleteMany({})
  await prisma.order.deleteMany({})
  await prisma.payment.deleteMany({})
  await prisma.product.deleteMany({})
  await prisma.brandTranslation.deleteMany({})
  await prisma.brand.deleteMany({})
  await prisma.categoryTranslation.deleteMany({})
  await prisma.category.deleteMany({})
  await prisma.discount.deleteMany({})

  console.log('✅ Cleared ALL data')

  // Clear cache sau khi xóa tất cả data
  console.log('\n🧹 Clearing application cache...')
  try {
    const cacheFlushUrl = process.env.APP_URL || 'http://localhost:3000'
    const response = await fetch(`${cacheFlushUrl}/health/cache/flush`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    if (response.ok) {
      const result = await response.json()
      console.log(`✅ Cache cleared successfully: ${result.message}`)
    } else {
      console.warn(`⚠️  Cache clear failed with status: ${response.status}`)
    }
  } catch (error) {
    console.warn(`⚠️  Could not clear cache: ${error.message}`)
    console.log('💡 Cache will be cleared automatically on next request or restart')
  }
}

export { clearProducts, clearAllData }
