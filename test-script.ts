type Variant = {
  value: string
  options: string[]
}

type SKU = {
  value: string
  price: number
  stock: number
  image: string
}

type Data = {
  product: {
    publishedAt: string | null // ISO date string
    name: string
    basePrice: number
    virtualPrice: number
    brandId: number
    images: string[]
    variants: Variant[]
    categories: number[]
  }
  skus: SKU[]
}

const data: Data = {
  product: {
    publishedAt: new Date().toISOString(),
    name: 'Sản phẩm mẫu',
    basePrice: 100000,
    virtualPrice: 100000,
    brandId: 1,
    images: [
      'https://example.com/image1.jpg',
      'https://example.com/image2.jpg',
      'https://example.com/image3.jpg'
    ],
    categories: [1, 2, 3],
    variants: [
      {
        value: 'Màu sắc',
        options: ['Đen', 'Trắng', 'Xanh', 'Đỏ']
      },
      {
        value: 'Kích thước',
        options: ['S', 'M', 'L', 'XL']
      },
      {
        value: 'Chất liệu',
        options: ['Cotton', 'Polyester', 'Linen']
      }
    ]
  },

  skus: [
    {
      value: 'Đen-S-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-S-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-S-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-M-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-M-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-M-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-L-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-L-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-L-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-XL-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-XL-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đen-XL-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-S-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-S-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-S-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-M-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-M-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-M-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-L-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-L-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-L-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-XL-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-XL-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Trắng-XL-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-S-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-S-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-S-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-M-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-M-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-M-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-L-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-L-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-L-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-XL-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-XL-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Xanh-XL-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-S-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-S-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-S-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-M-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-M-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-M-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-L-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-L-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-L-Linen',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-XL-Cotton',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-XL-Polyester',
      price: 0,
      stock: 100,
      image: ''
    },
    {
      value: 'Đỏ-XL-Linen',
      price: 0,
      stock: 100,
      image: ''
    }
  ]
}

function generateSKUs(variants: Variant[]): SKU[] {
  // Hàm hỗ trợ để tạo tất cả tổ hợp
  function getCombinations(arrays: string[][]): string[] {
    return arrays.reduce(
      (acc, curr) =>
        acc.flatMap((x) => curr.map((y) => `${x}${x ? '-' : ''}${y}`)),
      ['']
    )
  }

  // Lấy mảng các options từ variants
  const options = variants.map((variant) => variant.options)

  // Tạo tất cả tổ hợp
  const combinations = getCombinations(options)

  // Chuyển tổ hợp thành SKU objects
  return combinations.map((value) => ({
    value,
    price: 0,
    stock: 100,
    image: ''
  }))
}

// Ví dụ sử dụng
const variants: Variant[] = [
  {
    value: 'Màu sắc',
    options: ['Đen', 'Trắng', 'Xanh', 'Đỏ']
  },
  {
    value: 'Kích thước',
    options: ['S', 'M', 'L', 'XL']
  }
]

// Test hàm
const skus = generateSKUs(variants)
console.log(JSON.stringify(skus))
