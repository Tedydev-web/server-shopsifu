import { Subjects } from '../providers/casl/casl-ability.factory'

/**
 * Extracts a string representation of a CASL subject.
 * CASL subjects can be strings, classes (constructors), or instances.
 * This function handles these cases to provide a consistent string name.
 * @param subject The CASL subject.
 * @returns A string name for the subject.
 */
export function getSubjectName(subject: Subjects): string {
  if (typeof subject === 'string') {
    return subject
  }
  if (typeof subject === 'function') {
    return (subject as any).name
  }
  if (typeof subject === 'object' && subject !== null && subject.constructor) {
    return (subject.constructor as any).name
  }
  // This is a fallback that should ideally not be reached with proper subject types.
  return 'UnknownSubject'
}
