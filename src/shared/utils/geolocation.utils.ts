export interface Coordinates {
  lat: number
  lon: number
}

export function calculateDistance(coord1: Coordinates, coord2: Coordinates): number {
  const R = 6371 // Bán kính Trái Đất (km)
  const dLat = toRad(coord2.lat - coord1.lat)
  const dLon = toRad(coord2.lon - coord1.lon)
  const lat1 = toRad(coord1.lat)
  const lat2 = toRad(coord2.lat)

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(lat1) * Math.cos(lat2)
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
  const distance = R * c
  return distance
}

function toRad(value: number): number {
  return (value * Math.PI) / 180
}
