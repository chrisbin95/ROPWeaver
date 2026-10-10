import React, { useState, useEffect } from 'react';
import { ChevronDown, Layers, Sparkles } from 'lucide-react';

export default function LazyList({
  items,
  renderItem,
  initialCount = 3,
  step = 3,
  emptyMessage = "No items to display.",
  containerClassName = "lazy-list-container"
}) {
  const [visibleCount, setVisibleCount] = useState(initialCount);

  // Reset pagination when the underlying dataset or filter changes
  useEffect(() => {
    setVisibleCount(initialCount);
  }, [items, initialCount]);

  if (!items || items.length === 0) {
    return (
      <div className="empty-state-box">
        <Layers size={28} className="text-dim" />
        <p className="mono text-muted">{emptyMessage}</p>
      </div>
    );
  }

  const visibleItems = items.slice(0, visibleCount);
  const hasMore = visibleCount < items.length;
  const remaining = items.length - visibleItems.length;
  const nextBatch = Math.min(step, remaining);

  return (
    <div className={containerClassName}>
      <div className="lazy-items-wrapper">
        {visibleItems.map((item, index) => renderItem(item, index))}
      </div>

      {hasMore && (
        <div className="load-more-bar">
          <span className="mono text-muted text-xs">
            Showing <strong className="text-accent-cyan">{visibleItems.length}</strong> of <strong className="text-muted">{items.length}</strong> records
          </span>
          <button
            type="button"
            onClick={() => setVisibleCount((prev) => prev + step)}
            className="load-more-btn"
          >
            <ChevronDown size={16} className="text-accent-green" />
            <span>Show More ({nextBatch} more &bull; {remaining} remaining)</span>
          </button>
        </div>
      )}
    </div>
  );
}
