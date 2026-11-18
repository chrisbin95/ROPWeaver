import React from 'react';
import { getLoadingSpinnerProps } from '../utils/spinnerHelper';

/**
 * Shared Cyber-Themed Loading Spinner Component
 *
 * Provides a consistent, accessible loading indicator across ROPWeaver:
 * - Cyber visual aesthetic with glowing accent ring and orbiting pulse core.
 * - Accessible `role="status"` and hidden screen-reader announcement (`.sr-only`).
 * - Multiple sizes: 'sm' (15px), 'md' (28px), 'lg' (44px).
 * - Theme-matched accent colors: 'green' (default), 'cyan', 'orange', 'muted'.
 * - Preserves contextual status messages and avoids layout shifts.
 * - Respects prefers-reduced-motion preferences via CSS.
 */
export default function LoadingSpinner(props) {
  const { asCard, label } = props;
  const config = getLoadingSpinnerProps(props);

  const content = (
    <div
      role={config.role}
      aria-live={config.ariaLive}
      className={config.containerClasses}
    >
      <div className={config.spinnerClasses} aria-hidden="true">
        <div className="spinner-core" />
      </div>
      {label && <span className="cyber-spinner-label mono">{label}</span>}
      <span className="sr-only">{config.accessibleText}</span>
    </div>
  );

  if (asCard) {
    return (
      <div className="loading-state-card" role="status" aria-live="polite">
        {content}
      </div>
    );
  }

  return content;
}
