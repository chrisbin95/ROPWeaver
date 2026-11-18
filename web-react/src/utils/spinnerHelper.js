/**
 * Loading Spinner Helper Utilities
 *
 * Pure JavaScript helpers for ROPWeaver Cyber Loading Indicators:
 * - Deterministic class name generation
 * - Screen-reader accessible announcement resolution
 * - Size, color, and layout mode resolution
 */

export function getLoadingSpinnerProps({
  size = 'md',
  color = 'green',
  label = null,
  srLabel = 'Loading content...',
  inline = false,
  center = false,
  className = ''
} = {}) {
  const resolvedSize = ['sm', 'md', 'lg'].includes(size) ? size : 'md';
  const resolvedColor = ['green', 'cyan', 'orange', 'muted'].includes(color) ? color : 'green';

  const containerClasses = [
    'cyber-spinner-wrap',
    `size-${resolvedSize}`,
    `color-${resolvedColor}`,
    inline ? 'is-inline' : null,
    center ? 'is-centered' : null,
    className || null
  ].filter(Boolean).join(' ');

  const spinnerClasses = [
    'cyber-spinner',
    `size-${resolvedSize}`,
    `color-${resolvedColor}`
  ].join(' ');

  const accessibleText = typeof label === 'string' && label.trim() ? label.trim() : srLabel;

  return {
    role: 'status',
    ariaLive: 'polite',
    containerClasses,
    spinnerClasses,
    accessibleText,
    hasLabel: Boolean(label)
  };
}
